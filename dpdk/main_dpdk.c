/*
 * DPDK-based QUIC Packet Decryption
 * High-performance packet processing using DPDK
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "quic_d.h"

#define RTE_LOGTYPE_QUIC_DECRYPT RTE_LOGTYPE_USER1

/* DPDK Configuration */
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_PKT_BURST 32

/* QUIC Detection */
#define MIN_HOST_LEN 6
#define MAX_HOST_LEN 253
#define QUIC_PORT 443
#define QUIC_LONG_HEADER_BIT 0x80
#define QUIC_HEADER_FORM_MASK 0xC0

/* Statistics */
static rte_atomic64_t total_packets;
static rte_atomic64_t quic_packets;
static rte_atomic64_t decoded_packets;
static volatile bool force_quit = false;

/* Per-lcore statistics */
struct lcore_stats {
    uint64_t rx_packets;
    uint64_t quic_packets;
    uint64_t decoded_packets;
    uint64_t dropped_packets;
} __rte_cache_aligned;

static struct lcore_stats lcore_stats[RTE_MAX_LCORE];

/* Port configuration */
static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

typedef struct packet_data_info {
    uint16_t packet_header_length;
    uint16_t packet_payload_length;
    uint16_t packet_length;
    unsigned char sni[256];
    uint16_t dst_port;
} packet_info_t;

/* Function prototypes */
static inline int is_host_char(unsigned char c);
static int is_valid_hostname(const unsigned char *s, int len);
int extract_hostnames(const unsigned char *buf, size_t len, unsigned char *out, size_t out_size);
Session_info *find_or_create_session(quic_cid_t quic_dcic, uint32_t quic_version);

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* Character validation - inline for performance */
static inline int is_host_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '-';
}

static int is_valid_hostname(const unsigned char *s, int len)
{
    int label_len = 0;
    int has_alpha = 0;
    int has_dot = 0;

    if (len < MIN_HOST_LEN || len > MAX_HOST_LEN)
        return 0;

    if (s[0] == '.' || s[0] == '-' || s[len - 1] == '.' || s[len - 1] == '-')
        return 0;

    for (int i = 0; i < len; i++) {
        unsigned char c = s[i];

        if (!is_host_char(c))
            return 0;

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
            has_alpha = 1;

        if (c == '.') {
            has_dot = 1;
            if (label_len == 0 || label_len > 63)
                return 0;
            label_len = 0;
        } else {
            label_len++;
        }
    }

    if (!has_alpha || !has_dot)
        return 0;

    if (label_len == 0 || label_len > 63)
        return 0;

    return 1;
}

int extract_hostnames(const unsigned char *buf, size_t len, unsigned char *out, size_t out_size)
{
    if (!buf || !out || out_size < 2)
        return 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            size_t j = i;
            while (j < len && is_host_char(buf[j]))
                j++;

            int slen = j - i;

            if (is_valid_hostname(&buf[i], slen)) {
                if (j < len && isalnum(buf[j])) {
                    continue;
                }

                if ((size_t)slen >= out_size)
                    slen = out_size - 1;

                rte_memcpy(out, &buf[i], slen);
                out[slen] = '\0';
                return slen;
            }

            i = j;
        }
    }

    return 0;
}

Session_info *find_or_create_session(quic_cid_t quic_dcic, uint32_t quic_version)
{
    Session_info *new_session = (Session_info *)rte_malloc(NULL, sizeof(Session_info), 0);
    if (!new_session) {
        return NULL;
    }

    memset(new_session, 0, sizeof(Session_info));
    new_session->quic_version = quic_version;
    new_session->quic_dcic.len = quic_dcic.len;
    rte_memcpy(new_session->quic_dcic.cid, quic_dcic.cid, quic_dcic.len);

    return new_session;
}

static inline void detect_quic(const uint8_t *packet, uint32_t pkt_len, packet_info_t *packet_info,
                               unsigned lcore_id)
{
    if (packet_info->dst_port != QUIC_PORT)
        return;

    uint16_t offset = packet_info->packet_header_length;
    if (offset + 8 > pkt_len)
        return;

    const uint8_t *quic_packet = packet + offset;
    uint16_t quic_packet_len = packet_info->packet_payload_length;

    uint8_t quic_byte0 = quic_packet[0];

    if ((quic_byte0 & QUIC_HEADER_FORM_MASK) != 0xC0)
        return;

    lcore_stats[lcore_id].quic_packets++;
    rte_atomic64_inc(&quic_packets);

    uint8_t cid_len = quic_packet[5];
    if (cid_len == 0 || cid_len > QUIC_MAX_CID_LENGTH)
        return;

    quic_cid_t cid_t;
    cid_t.len = cid_len;
    rte_memcpy(cid_t.cid, &quic_packet[6], cid_len);

    uint32_t quic_version = rte_be_to_cpu_32(*(uint32_t *)&quic_packet[1]);

    Session_info *Session_t = find_or_create_session(cid_t, quic_version);
    if (!Session_t)
        return;

    if (!decode_quic(Session_t)) {
        rte_free(Session_t);
        return;
    }

    quic_ciphers_t this_quic_ciphers_t = Session_t->quic_cipher_keys;

    int quic_cidc_len = quic_packet[1 + 4 + 1 + cid_len];
    int quic_cidc_offset = 1 + 4 + 1 + cid_len + 1;
    int token_len_offset = quic_cidc_offset + quic_cidc_len;

    uint64_t token_val;
    uint16_t token_bytes = GetVarInt(quic_packet, token_len_offset, &token_val);
    uint16_t token_len = (uint16_t)token_val;

    int token_offset = token_len_offset + token_bytes;
    uint64_t qpkn_val;
    uint16_t qpkn_len_bytes = GetVarInt(quic_packet, token_offset + token_len, &qpkn_val);
    int quic_offset = token_offset + token_len + qpkn_len_bytes;

    quic_frame_essentials_t quic_frame_essens;

    if (!process_quic_header(quic_packet, quic_offset, this_quic_ciphers_t, &quic_frame_essens)) {
        rte_free(Session_t);
        return;
    }

    quic_offset += quic_frame_essens.qpkn_len;

    int cipher_payload_len = quic_packet_len - quic_offset - 16;

    if (cipher_payload_len <= 0) {
        rte_free(Session_t);
        return;
    }

    size_t total_size = quic_offset + 16 + cipher_payload_len * 2;
    uint8_t *buffer = (uint8_t *)rte_malloc(NULL, total_size, 0);
    if (!buffer) {
        rte_free(Session_t);
        return;
    }

    uint8_t *associateddata = buffer;
    uint8_t *authtag = buffer + quic_offset;
    uint8_t *cipher_payload = buffer + quic_offset + 16;
    uint8_t *decrypted_payload = buffer + quic_offset + 16 + cipher_payload_len;

    rte_memcpy(associateddata, quic_packet, quic_offset);
    rte_memcpy(authtag, quic_packet + quic_packet_len - 16, 16);
    rte_memcpy(cipher_payload, quic_packet + quic_offset, cipher_payload_len);

    int ret = process_quic_payload(associateddata, quic_offset, authtag, cipher_payload,
                                   cipher_payload_len, quic_frame_essens, this_quic_ciphers_t,
                                   decrypted_payload);
    if (ret) {
        int hlen = extract_hostnames(decrypted_payload, cipher_payload_len, packet_info->sni, 256);
        if (hlen) {
            lcore_stats[lcore_id].decoded_packets++;
            rte_atomic64_inc(&decoded_packets);
            printf("[Core %u] SNI: %s\n", lcore_id, packet_info->sni);
        }
    }

    rte_free(buffer);
    rte_free(Session_t);
}

/*
 * Process a single packet
 */
static inline void process_packet(struct rte_mbuf *m, unsigned lcore_id)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    uint16_t eth_type;
    uint32_t pkt_len;
    uint8_t *pkt_data;

    lcore_stats[lcore_id].rx_packets++;
    rte_atomic64_inc(&total_packets);

    pkt_len = rte_pktmbuf_pkt_len(m);
    pkt_data = rte_pktmbuf_mtod(m, uint8_t *);

    /* Parse Ethernet header */
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    /* Check if IPv4 */
    if (unlikely(eth_type != RTE_ETHER_TYPE_IPV4))
        return;

    /* Parse IPv4 header */
    ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    /* Check if UDP */
    if (unlikely(ipv4_hdr->next_proto_id != IPPROTO_UDP))
        return;

    /* Parse UDP header */
    uint16_t ip_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
    udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + ip_hdr_len);

    /* Setup packet info */
    packet_info_t packet_info;
    packet_info.dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    packet_info.packet_header_length =
            sizeof(struct rte_ether_hdr) + ip_hdr_len + sizeof(struct rte_udp_hdr);
    packet_info.packet_length = pkt_len;
    packet_info.packet_payload_length = pkt_len - packet_info.packet_header_length;

    /* Detect and process QUIC */
    detect_quic(pkt_data, pkt_len, &packet_info, lcore_id);
}

/*
 * Main packet processing loop per lcore
 */
static int lcore_main(void *arg)
{
    unsigned lcore_id;
    uint16_t port;
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx;
    unsigned i;

    lcore_id = rte_lcore_id();
    port = *(uint16_t *)arg;

    RTE_LOG(INFO, QUIC_DECRYPT, "Core %u: processing packets from port %u\n", lcore_id, port);

    while (!force_quit) {
        /* Receive burst of packets */
        nb_rx = rte_eth_rx_burst(port, lcore_id, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        /* Prefetch first packets */
        for (i = 0; i < RTE_MIN(4, nb_rx); i++)
            rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

        /* Process packets */
        for (i = 0; i < nb_rx; i++) {
            /* Prefetch next packet */
            if (i + 4 < nb_rx)
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i + 4], void *));

            process_packet(bufs[i], lcore_id);

            /* Free the mbuf */
            rte_pktmbuf_free(bufs[i]);
        }
    }

    RTE_LOG(INFO, QUIC_DECRYPT, "Core %u: exiting\n", lcore_id);
    return 0;
}

/*
 * Print statistics
 */
static void print_stats(void)
{
    uint64_t total_rx = 0;
    uint64_t total_quic = 0;
    uint64_t total_decoded = 0;
    unsigned lcore_id;

    printf("\n========== Statistics ==========\n");

    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        printf("Core %2u: RX=%10" PRIu64 " QUIC=%10" PRIu64 " Decoded=%10" PRIu64 "\n", lcore_id,
               lcore_stats[lcore_id].rx_packets, lcore_stats[lcore_id].quic_packets,
               lcore_stats[lcore_id].decoded_packets);

        total_rx += lcore_stats[lcore_id].rx_packets;
        total_quic += lcore_stats[lcore_id].quic_packets;
        total_decoded += lcore_stats[lcore_id].decoded_packets;
    }

    printf("--------------------------------\n");
    printf("Total  : RX=%10" PRIu64 " QUIC=%10" PRIu64 " Decoded=%10" PRIu64 "\n", total_rx,
           total_quic, total_decoded);
    printf("================================\n\n");
}

/*
 * Initialize port
 */
static int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf local_port_conf = port_conf;
    const uint16_t rx_rings = rte_lcore_count() - 1; // Exclude main lcore
    const uint16_t tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error getting device info for port %u: %s\n", port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &local_port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up RX queues (one per worker lcore) */
    unsigned lcore_id;
    q = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL,
                                        mbuf_pool);
        if (retval < 0)
            return retval;
        q++;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = local_port_conf.txmode.offloads;

    /* Allocate and set up TX queue */
    retval = rte_eth_tx_queue_setup(port, 0, nb_txd, rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
        return retval;

    /* Start the Ethernet port */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
           "\n",
           port, RTE_ETHER_ADDR_BYTES(&addr));

    /* Enable promiscuous mode */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/*
 * Main function
 */
int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid = 0;
    unsigned lcore_id;
    int ret;

    /* Initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Register signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize atomic counters */
    rte_atomic64_init(&total_packets);
    rte_atomic64_init(&quic_packets);
    rte_atomic64_init(&decoded_packets);

    /* Check that there is at least one port */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "Error: no Ethernet ports available\n");

    printf("DPDK QUIC Decryption initialized with %u port(s)\n", nb_ports);
    printf("Using %u worker lcore(s)\n", rte_lcore_count() - 1);

    /* Create mbuf pool */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize port 0 */
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    /* Launch worker threads on all worker lcores */
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        rte_eal_remote_launch(lcore_main, &portid, lcore_id);
    }

    /* Main lcore prints statistics */
    printf("\nStarting packet processing. Press Ctrl+C to stop.\n\n");

    while (!force_quit) {
        sleep(5);
        print_stats();
    }

    /* Wait for worker lcores to finish */
    RTE_LCORE_FOREACH_WORKER(lcore_id)
    {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    /* Print final statistics */
    print_stats();

    /* Stop and close port */
    printf("Closing port %d...", portid);
    ret = rte_eth_dev_stop(portid);
    if (ret != 0)
        printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);

    rte_eth_dev_close(portid);
    printf(" Done\n");

    /* Clean up the EAL */
    rte_eal_cleanup();

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <ctype.h>
#include "quic_d.h"

#define MIN_HOST_LEN 6
#define MAX_HOST_LEN 253
#define QUIC_PORT 443
#define QUIC_LONG_HEADER_BIT 0x80
#define QUIC_HEADER_FORM_MASK 0xC0
#define ETHERNET_HEADER_SIZE 14
#define UDP_HEADER_SIZE 8

// Thread-local or atomic counter if multi-threading
uint32_t packet_counter = 0;

typedef struct packet_data_info {
    uint16_t packet_header_length;
    uint16_t packet_payload_length;
    uint16_t packet_length;
    unsigned char sni[256];
    uint16_t dst_port;
} packet_info_t;

// Optimized: inline for better performance
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

    // Early bounds check
    if (len < MIN_HOST_LEN || len > MAX_HOST_LEN)
        return 0;

    // Check first and last characters
    if (s[0] == '.' || s[0] == '-' || s[len - 1] == '.' || s[len - 1] == '-')
        return 0;

    for (int i = 0; i < len; i++) {
        unsigned char c = s[i];

        if (!is_host_char(c))
            return 0;

        // Optimized: avoid redundant isalpha call
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

/*
 * Extract first valid hostname from raw buffer
 * Returns length written into out[]
 */
int extract_hostnames(const unsigned char *buf, size_t len, unsigned char *out, size_t out_size)
{
    if (!buf || !out || out_size < 2)
        return 0;

    for (size_t i = 0; i < len; i++) {
        // Optimized: check for alpha character more efficiently
        unsigned char c = buf[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            size_t j = i;
            while (j < len && is_host_char(buf[j]))
                j++;

            int slen = j - i;

            if (is_valid_hostname(&buf[i], slen)) {
                // Boundary check
                if (j < len && isalnum(buf[j])) {
                    continue;
                }

                if ((size_t)slen >= out_size)
                    slen = out_size - 1;

                memcpy(out, &buf[i], slen);
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
    Session_info *new_session = (Session_info *)malloc(sizeof(Session_info));
    if (!new_session) {
        perror("malloc");
        return NULL;
    }

    memset(new_session, 0, sizeof(Session_info));
    new_session->quic_version = quic_version;
    new_session->quic_dcic.len = quic_dcic.len;
    memcpy(new_session->quic_dcic.cid, quic_dcic.cid, quic_dcic.len);

    return new_session;
}

void detect_quic(const u_char *packet, packet_info_t *packet_info)
{
    // Early exit optimization
    if (packet_info->dst_port != QUIC_PORT)
        return;

    uint16_t offset = packet_info->packet_header_length;

    // Bounds check optimization
    if (offset + 8 > packet_info->packet_length)
        return;

    const u_char *quic_packet = packet + offset;
    uint16_t quic_packet_len = packet_info->packet_payload_length;

    uint8_t quic_byte0 = quic_packet[0];

    // Optimized: check long header format directly
    if ((quic_byte0 & QUIC_HEADER_FORM_MASK) != 0xC0)
        return;

    // Extract CID length
    uint8_t cid_len = quic_packet[5];
    if (cid_len == 0 || cid_len > QUIC_MAX_CID_LENGTH)
        return;

    // Stack allocation for small CID - avoid malloc
    quic_cid_t cid_t;
    cid_t.len = cid_len;
    memcpy(cid_t.cid, &quic_packet[6], cid_len);

    // Direct read and byte swap
    uint32_t quic_version = ntohl(*(uint32_t *)&quic_packet[1]);

    // Allocate session - consider using object pool for optimization
    Session_info *Session_t = find_or_create_session(cid_t, quic_version);
    if (!Session_t)
        return;

    if (!decode_quic(Session_t)) {
        free(Session_t);
        return;
    }

    quic_ciphers_t this_quic_ciphers_t = Session_t->quic_cipher_keys;

    // Calculate offsets
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
        free(Session_t);
        return;
    }

    quic_offset += quic_frame_essens.qpkn_len;

    // Calculate sizes
    int cipher_payload_len = quic_packet_len - quic_offset - 16;

    // Bounds check
    if (cipher_payload_len <= 0) {
        free(Session_t);
        return;
    }

    // Allocate all buffers at once to reduce allocator overhead
    size_t total_size = quic_offset + 16 + cipher_payload_len * 2;
    uint8_t *buffer = (uint8_t *)malloc(total_size);
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        free(Session_t);
        return;
    }

    // Partition the buffer
    uint8_t *associateddata = buffer;
    uint8_t *authtag = buffer + quic_offset;
    uint8_t *cipher_payload = buffer + quic_offset + 16;
    uint8_t *decrypted_payload = buffer + quic_offset + 16 + cipher_payload_len;

    // Copy data
    memcpy(associateddata, quic_packet, quic_offset);
    memcpy(authtag, quic_packet + quic_packet_len - 16, 16);
    memcpy(cipher_payload, quic_packet + quic_offset, cipher_payload_len);

    int ret = process_quic_payload(associateddata, quic_offset, authtag, cipher_payload,
                                   cipher_payload_len, quic_frame_essens, this_quic_ciphers_t,
                                   decrypted_payload);
    if (ret) {
        int hlen = extract_hostnames(decrypted_payload, cipher_payload_len, packet_info->sni, 256);
        if (hlen) {
            printf("packet_counter   = %u\t Readable output:\t%s\n", packet_counter,
                   packet_info->sni);
        }
    }

    // Single free instead of multiple
    free(buffer);
    free(Session_t);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;

    packet_counter++;

    const struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t eth_type = ntohs(eth_header->ether_type);

    // Early exit if not IPv4
    if (eth_type != ETHERTYPE_IP)
        return;

    const struct ip *ip_header = (struct ip *)(packet + ETHERNET_HEADER_SIZE);

    // Early exit if not UDP
    if (ip_header->ip_p != IPPROTO_UDP)
        return;

    int ip_header_len = ip_header->ip_hl * 4;
    int offset = ETHERNET_HEADER_SIZE + ip_header_len + UDP_HEADER_SIZE;

    const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_len);

    packet_info_t packet_info;
    packet_info.dst_port = ntohs(udp_header->dest);
    packet_info.packet_header_length = offset;
    packet_info.packet_length = header->caplen;
    packet_info.packet_payload_length = header->caplen - offset;

    detect_quic(packet, &packet_info);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(dev, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open file %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_close(handle);

    return EXIT_SUCCESS;
}

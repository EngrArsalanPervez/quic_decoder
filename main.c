#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <gcrypt.h>
#include <glib.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h> // Added for sleep function
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <ctype.h>
#include "quic_d.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

uint32_t packet_counter = 0;
Session_info *find_or_create_session(quic_cid_t quic_dcic, uint32_t quic_version)
{
    Session_info *new_session = (Session_info *)malloc(sizeof(Session_info));
    if (!new_session) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(new_session, 0, sizeof(Session_info));
    new_session->quic_version = quic_version;
    new_session->quic_dcic.len = quic_dcic.len;
    memcpy(new_session->quic_dcic.cid, quic_dcic.cid, quic_dcic.len);
    return new_session;
}

#define MIN_PRINTABLE_SEQ \
    5 // Minimum length of consecutive printable characters to consider as a string
#define MAX_STR_SIZE 256 // Maximum string length to extract

#define MIN_HOST_LEN 6
#define MAX_HOST_LEN 253

static inline int is_host_char(unsigned char c)
{
    return isalnum(c) || c == '.' || c == '-';
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

        if (isalpha(c))
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
        /* possible hostname start */
        if (isalpha(buf[i])) {
            size_t j = i;
            while (j < len && is_host_char(buf[j]))
                j++;

            int slen = j - i;

            if (is_valid_hostname(&buf[i], slen)) {
                /* boundary check */
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

void detect_quic(const u_char *packet, packet_info_t *packet_info)
{
    uint16_t offset = packet_info->packet_header_length;
    if (offset + 8 > packet_info->packet_length)
        return;
    if (!(packet_info->dst_port == 443))
        return;

    const u_char *quic_packet = packet + offset;
    uint16_t quic_packet_len = packet_info->packet_payload_length;
    uint8_t quic_byte0 = quic_packet[0];
    uint32_t *quic_version = (uint32_t *)&quic_packet[1];
    uint32_t qv = htonl(*quic_version);
    if (!((quic_byte0 & 0xF0) == 0xC0))
        return;
    //if (((quic_byte0&0xF0) == 0xc0 ||(quic_byte0&0xF0) == 0xd0||(quic_byte0&0xF0) == 0xe0||(quic_byte0&0xF0) == 0xf0 ) && (quic_version ==0x01)){}

    //printf(" ======================== QUIC DETECTED ===================== %u\n",packet_counter );
    //quic_info_data_t quic_info;
    quic_cid_t cid_t;
    cid_t.len = (uint8_t)quic_packet[5];
    if (cid_t.len == 0)
        return;
    memcpy(cid_t.cid, &quic_packet[6], cid_t.len);
    Session_info *Session_t = find_or_create_session(cid_t, qv);
    //if (Session_t->packet_count==0)
    //{
    if (!decode_quic(Session_t))
        return;
    //}
    //Session_t->packet_count++;
    //print_secrete("DCIC",cid_t.cid,cid_t.len);
    quic_ciphers_t this_quic_ciphers_t = Session_t->quic_cipher_keys;
    int quic_cidc_len = quic_packet[1 + 4 + 1 + cid_t.len];
    int quic_cidc_offset = 1 + 4 + 1 + cid_t.len + 1;
    int token_len_offset = quic_cidc_offset + quic_cidc_len;
    uint64_t token_val;
    uint16_t token_bytes = GetVarInt(quic_packet, token_len_offset, &token_val);
    uint16_t token_len = (uint16_t)token_val;
    //printf("token_bytes: %u   token_len = %u\n", token_bytes,token_len);
    //int token_len = quic_packet[quic_cidc_offset +quic_cidc_len];

    int token_offset = token_len_offset + token_bytes; //1+4+1+cid_t.len+1+cidc_len+1;
    //int packet_len = quic_packet[token_offset +token_len];
    uint64_t qpkn_val;
    uint16_t qpkn_len_bytes = GetVarInt(quic_packet, token_offset + token_len, &qpkn_val);
    int quic_offset = token_offset + token_len + qpkn_len_bytes;
    //printf("pkt_len_bytes: %u   packet_val = %lu\n", pkt_len_bytes,packet_val);

    // printf("quic_offset = %d\n",quic_offset);
    quic_frame_essentials_t quic_frame_essens;
    //uint16_t len_pkn,pkt_pkn;
    //uint8_t qbyte0;
    if (!process_quic_header(quic_packet, quic_offset, this_quic_ciphers_t, &quic_frame_essens))
        return;
    //printf("Packet Number: %lu  pkn_len = %u quic_byte0 %02x\n", quic_frame_essens.qpkn,quic_frame_essens.qpkn_len,quic_frame_essens.first_byte);
    quic_offset += quic_frame_essens.qpkn_len;
    uint8_t *associateddata = (uint8_t *)malloc(quic_offset);
    memcpy(associateddata, quic_packet, quic_offset);
    uint8_t *authtag = (uint8_t *)malloc(16);
    memcpy(authtag, quic_packet + quic_packet_len - 16, 16);
    // printf("authtag: ");
    //for (int i = 0; i < 16; i++) {
    //    printf("%02x", authtag[i]);
    // }
    // printf("\n");

    // Extract and save bytes except header and last 16
    int cipher_payload_len = quic_packet_len - quic_offset - 16;
    uint8_t *cipher_payload = (uint8_t *)malloc(cipher_payload_len);
    memcpy(cipher_payload, quic_packet + quic_offset, cipher_payload_len);
    uint8_t *decrypted_payload;

    decrypted_payload = (uint8_t *)malloc(cipher_payload_len);
    if (!decrypted_payload) {
        fprintf(stderr, "Memory allocation failed for decrypted_payload\n");
        return;
    }
    //printf("\n");
    int ret = process_quic_payload(associateddata, quic_offset, authtag, cipher_payload,
                                   cipher_payload_len, quic_frame_essens, this_quic_ciphers_t,
                                   decrypted_payload);
    if (ret) {
        int p = 0;

        int hlen = extract_hostnames(decrypted_payload, cipher_payload_len, packet_info->sni, 256);
        if (hlen) {
            printf("packet_counter   = %u\t ", packet_counter);
            printf("Readable output:\t%s\n", packet_info->sni);
        }
        //free(readable);
        /*if (packet_counter==54004 || packet_counter==54003 ){
         for (p =0; p< cipher_payload_len ;p++)
         {
            // printf()
             char c = (char)decrypted_payload[p];
            if (isprint(c))
             printf("%c",c);


        }
	}*/
        // memcpy(Session_t->quic_decrypted_frames[Session_t->quic_decrypted_frames_count], decrypted_payload, cipher_payload_len);
        //Session_t->quic_decrypted_frame_len[Session_t->quic_decrypted_frames_count] = cipher_payload_len;
        //printf("cipher_payload_len = %u  %u\n",cipher_payload_len, Session_t->quic_decrypted_frame_len[Session_t->quic_decrypted_frames_count]);
        //Session_t->session_decrypted_payload_length +=cipher_payload_len;
        //Session_t->quic_decrypted_frames_count++;
    }
    free(Session_t);
    free(decrypted_payload);
    free(cipher_payload);
    free(associateddata);
    free(authtag);
    //if (packet_counter==24)
    //	printf("session->session_is_quic  Hameed\n");
    //session = find_or_create_session(src_ip, dst_ip, src_port, dst_port,0);
    //if (session->session_is_quic == 4)
    //session->session_is_quic++;
    //if (packet_counter==24)
    //printf("session->session_is_quic  %u\n",session->session_is_quic);

    /*if (src_port != 0 && dst_port != 0) {
        Session *session = find_or_create_session(src_ip, dst_ip, src_port, dst_port, protocol);
        session->packet_count++;
        session->byte_count += header->len;
        session->last_packet_time = time(NULL);
    }*/
}

// Function to process each packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t eth_type = ntohs(eth_header->ether_type);
    //uint16_t packet_caplen = header->caplen;
    char src_ip[INET6_ADDRSTRLEN] = { 0 };
    char dst_ip[INET6_ADDRSTRLEN] = { 0 };
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    const u_char *payload;
    packet_info_t packet_info;
    packet_info.packet_length = header->caplen;
    int offset = 14;
    packet_counter++;
    //packet_info.packet_counter = packet_counter;
    //if (packet_counter > 500)
    //return;
    if (eth_type == ETHERTYPE_IP) {
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        protocol = ip_header->ip_p;
        //inet_ntop(AF_INET, &(ip_header->ip_src), packet_info.src_ip, INET_ADDRSTRLEN);
        //inet_ntop(AF_INET, &(ip_header->ip_dst), packet_info.dst_ip, INET_ADDRSTRLEN);
        //packet_info.ip_packet_type = 4;
        offset += ip_header->ip_hl * 4;
        if (protocol == IPPROTO_TCP) {
            const struct tcphdr *tcp_header =
                    (struct tcphdr *)((u_char *)ip_header + (ip_header->ip_hl * 4));
            //packet_info.src_port = ntohs(tcp_header->source);
            packet_info.dst_port = ntohs(tcp_header->dest);
            //packet_info.l4_proto = IPPROTO_TCP;
            return;

        } else if (protocol == IPPROTO_UDP) {
            const struct udphdr *udp_header =
                    (struct udphdr *)((u_char *)ip_header + (ip_header->ip_hl * 4));
            //packet_info.src_port = ntohs(udp_header->source);
            packet_info.dst_port = ntohs(udp_header->dest);
            //packet_info.l4_proto = IPPROTO_UDP;
            offset += 8;
            packet_info.packet_header_length = offset;
            packet_info.packet_payload_length = header->caplen - offset;
            detect_quic(packet, &packet_info);
        }

    } else if (eth_type == ETHERTYPE_IPV6) {
        const struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        protocol = ip6_header->ip6_nxt;
        //inet_ntop(AF_INET6, &(ip6_header->ip6_src), packet_info.src_ip, INET6_ADDRSTRLEN);
        //inet_ntop(AF_INET6, &(ip6_header->ip6_dst), packet_info.dst_ip, INET6_ADDRSTRLEN);
        //packet_info.ip_packet_type = 6;
        offset += sizeof(struct ip6_hdr);
        if (protocol == IPPROTO_TCP) {
            const struct tcphdr *tcp_header =
                    (struct tcphdr *)((u_char *)ip6_header + sizeof(struct ip6_hdr));
            // packet_info.src_port = ntohs(tcp_header->source);
            packet_info.dst_port = ntohs(tcp_header->dest);
            return;
        } else if (protocol == IPPROTO_UDP) {
            const struct udphdr *udp_header =
                    (struct udphdr *)((u_char *)ip6_header + sizeof(struct ip6_hdr));
            //packet_info.src_port = ntohs(udp_header->source);
            packet_info.dst_port = ntohs(udp_header->dest);
            // packet_info.l4_proto = IPPROTO_UDP;
            offset += 8;
            packet_info.packet_header_length = offset;
            packet_info.packet_payload_length = header->caplen - offset;
            detect_quic(packet, &packet_info);
        }
    }
}
int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    pcap_t *handle = pcap_open_offline(dev, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    //pthread_t cleanup_thread;
    //if (pthread_create(&cleanup_thread, NULL, session_cleanup_thread, NULL) != 0) {
    //   perror("pthread_create");
    //  return EXIT_FAILURE;
    //}

    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    pcap_close(handle);
    //printf("PROCESSING SESSIONS\n");
    //process_sessions();
    //printf("quic_packet_count = %u\n",quic_packet_count);
    //pthread_cancel(cleanup_thread);
    //pthread_join(cleanup_thread, NULL);
    return EXIT_SUCCESS;

    return 0;
}

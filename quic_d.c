#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <gcrypt.h>
#include <glib.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h> // Added for sleep function
#include <ctype.h>
#include "quic_d.h"

#ifndef WS_DLL_PUBLIC
#define WS_DLL_PUBLIC
#endif

WS_DLL_PUBLIC gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length,
                                          const void *key, size_t keylen);

gcry_error_t ws_hmac_buffer(int algo, void *digest, const void *buffer, size_t length,
                            const void *key, size_t keylen)
{
    gcry_md_hd_t hd;
    gcry_error_t err;

    err = gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC);
    if (err)
        return err;

    err = gcry_md_setkey(hd, key, keylen);
    if (err) {
        gcry_md_close(hd);
        return err;
    }

    gcry_md_write(hd, buffer, length);

    memcpy(digest, gcry_md_read(hd, algo), gcry_md_get_algo_dlen(algo));

    gcry_md_close(hd);
    return 0;
}

static inline gcry_error_t hkdf_extract(int hashalgo, const uint8_t *salt, size_t salt_len,
                                        const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    /* PRK = HMAC-Hash(salt, IKM) where salt is key, and IKM is input. */
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}

gcry_error_t hkdf_expand(int hashalgo, const uint8_t *prk, unsigned prk_len, const uint8_t *info,
                         unsigned info_len, uint8_t *out, unsigned out_len)
{
    // Current maximum hash output size: 48 bytes for SHA-384.
    unsigned char lastoutput[48];
    gcry_md_hd_t h;
    gcry_error_t err;
    const unsigned hash_len = gcry_md_get_algo_dlen(hashalgo);

    /* Some sanity checks */
    if (!(out_len > 0 && out_len <= 255 * hash_len) ||
        !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
        return GPG_ERR_INV_ARG;
    }

    err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
    if (err) {
        return err;
    }

    for (unsigned offset = 0; offset < out_len; offset += hash_len) {
        gcry_md_reset(h);
        gcry_md_setkey(h, prk, prk_len); /* Set PRK */
        if (offset > 0) {
            gcry_md_write(h, lastoutput, hash_len); /* T(1..N) */
        }
        gcry_md_write(h, info, info_len); /* info */
        gcry_md_putc(h, (uint8_t)(offset / hash_len + 1)); /* constant 0x01..N */

        memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
        memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
    }

    gcry_md_close(h);
    return 0;
}

// HKDF-Expand-Label as per RFC 8446

//uint16_t packet_counter =0;

static inline gcry_error_t hkdf_extract_func(int hashalgo, const uint8_t *salt, size_t salt_len,
                                             const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    return hkdf_extract(hashalgo, salt, salt_len, ikm, ikm_len, prk);
}

bool tls13_hkdf_expand_label_context(int md, const StringInfo *secret, const char *label_prefix,
                                     const char *label, const uint8_t *context_hash,
                                     uint8_t context_length, uint16_t out_len, unsigned char **out)
{
    /* RFC 8446 Section 7.1:
     * HKDF-Expand-Label(Secret, Label, Context, Length) =
     *      HKDF-Expand(Secret, HkdfLabel, Length)
     * struct {
     *     uint16 length = Length;
     *     opaque label<7..255> = "tls13 " + Label; // "tls13 " is label prefix.
     *     opaque context<0..255> = Context;
     * } HkdfLabel;
     *
     * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
     * HKDF-Expand(PRK, info, L) -> OKM
     */
    gcry_error_t err;
    const unsigned label_prefix_length = (unsigned)strlen(label_prefix);
    const unsigned label_length = (unsigned)strlen(label);

    /* Some sanity checks */
    if (!(label_length > 0 && label_prefix_length + label_length <= 255)) {
        return false;
    }

    /* info = HkdfLabel { length, label, context } */
    GByteArray *info = g_byte_array_new();
    const uint16_t length = g_htons(out_len);
    g_byte_array_append(info, (const uint8_t *)&length, sizeof(length));

    const uint8_t label_vector_length = label_prefix_length + label_length;
    g_byte_array_append(info, &label_vector_length, 1);
    g_byte_array_append(info, (const uint8_t *)label_prefix, label_prefix_length);
    g_byte_array_append(info, (const uint8_t *)label, label_length);

    g_byte_array_append(info, &context_length, 1);
    if (context_length) {
        g_byte_array_append(info, context_hash, context_length);
    }

    *out = (unsigned char *)g_malloc(out_len);
    err = hkdf_expand(md, secret->data, secret->data_len, info->data, info->len, *out, out_len);
    g_byte_array_free(info, true);

    if (err) {
        printf("%s failed  : %d\n", G_STRFUNC, md);
        //ssl_debug_printf("%s failed  %d: %s\n", G_STRFUNC, md, gcry_strerror(err));
        g_free(*out);
        *out = NULL;
        return false;
    }

    return true;
}

bool tls13_hkdf_expand_label(int md, const StringInfo *secret, const char *label_prefix,
                             const char *label, uint16_t out_len, unsigned char **out)
{
    return tls13_hkdf_expand_label_context(md, secret, label_prefix, label, NULL, 0, out_len, out);
}
static bool quic_hkdf_expand_label(int hash_algo, uint8_t *secret, unsigned secret_len,
                                   const char *label, uint8_t *out, unsigned out_len)
{
    const StringInfo secret_si = { secret, secret_len };
    unsigned char *out_mem = NULL;
    if (tls13_hkdf_expand_label(hash_algo, &secret_si, "tls13 ", label, out_len, &out_mem)) {
        //print_secrete("secret_si",out_mem,out_len);
        memcpy(out, out_mem, out_len);
        g_free(out_mem);
        return true;
    }
    return false;
}

/* Returns the QUIC draft version or 0 if not applicable. */
static inline uint8_t quic_draft_version(uint32_t version)
{
    /* IETF Draft versions */
    if ((version >> 8) == 0xff0000) {
        return (uint8_t)version;
    }
    /* Facebook mvfst, based on draft -22. */
    if (version == 0xfaceb001) {
        return 22;
    }
    /* Facebook mvfst, based on draft -27. */
    if (version == 0xfaceb002 || version == 0xfaceb00e) {
        return 27;
    }
    /* GQUIC Q050, T050 and T051: they are not really based on any drafts,
     * but we must return a sensible value */
    if (version == 0x51303530 || version == 0x54303530 || version == 0x54303531) {
        return 27;
    }
    /* https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-15
       "Versions that follow the pattern 0x?a?a?a?a are reserved for use in
       forcing version negotiation to be exercised"
       We can't return a correct draft version because we don't have a real
       version here! That means that we can't decode any data and we can dissect
       only the cleartext header.
       Let's return v1 (any other numbers should be fine, anyway) to only allow
       the dissection of the (expected) long header */
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a) {
        return 34;
    }
    /* QUIC (final?) constants for v1 are defined in draft-33, but draft-34 is the
       final draft version */
    if (version == 0x00000001) {
        return 34;
    }
    /* QUIC Version 2 */
    if (version == 0x6b3343cf) {
        return 100;
    }
    return 0;
}

static inline bool is_quic_v2(uint32_t version)
{
    return version == 0x6b3343cf;
}

static inline bool is_quic_draft_max(uint32_t version, uint8_t max_version)
{
    uint8_t draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

static const uint8_t handshake_salt_v11[20] = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                                0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };
static bool quic_derive_initial_secrets(const quic_cid_t *cid,
                                        uint8_t client_initial_secret[HASH_SHA2_256_LENGTH],
                                        uint8_t server_initial_secret[HASH_SHA2_256_LENGTH],
                                        uint32_t version, const char **error)
{
    /*
     * https://tools.ietf.org/html/draft-ietf-quic-tls-29#section-5.2
     *
     * initial_salt = 0xafbfec289993d24c9e9786f19c6111e04390a899
     * initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *
     * client_initial_secret = HKDF-Expand-Label(initial_secret,
     *                                           "client in", "", Hash.length)
     * server_initial_secret = HKDF-Expand-Label(initial_secret,
     *                                           "server in", "", Hash.length)
     *
     * Hash for handshake packets is SHA-256 (output size 32).
     */
    static const uint8_t handshake_salt_draft_22[20] = { 0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb,
                                                         0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51,
                                                         0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a };
    static const uint8_t handshake_salt_draft_23[20] = {
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
        0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
    };
    static const uint8_t handshake_salt_draft_29[20] = { 0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2,
                                                         0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61,
                                                         0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99 };
    static const uint8_t handshake_salt_v1[20] = { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                                   0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                                   0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a };
    static const uint8_t hanshake_salt_draft_q50[20] = { 0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE,
                                                         0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3,
                                                         0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45 };
    static const uint8_t hanshake_salt_draft_t50[20] = { 0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72,
                                                         0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2,
                                                         0x36, 0x7c, 0x60, 0x48, 0x83, 0x10 };
    static const int8_t hanshake_salt_draft_t51[20] = { 0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee,
                                                        0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f,
                                                        0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d };
    static const uint8_t handshake_salt_v2[20] = { 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6,
                                                   0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                                                   0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 };

    gcry_error_t err;
    uint8_t secret[HASH_SHA2_256_LENGTH];

    if (version == 0x51303530) {
        err = hkdf_extract_func(GCRY_MD_SHA256, hanshake_salt_draft_q50,
                                sizeof(hanshake_salt_draft_q50), cid->cid, cid->len, secret);
    } else if (version == 0x54303530) {
        err = hkdf_extract_func(GCRY_MD_SHA256, hanshake_salt_draft_t50,
                                sizeof(hanshake_salt_draft_t50), cid->cid, cid->len, secret);
    } else if (version == 0x54303531) {
        err = hkdf_extract_func(GCRY_MD_SHA256, hanshake_salt_draft_t51,
                                sizeof(hanshake_salt_draft_t51), cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 22)) {
        err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_draft_22,
                                sizeof(handshake_salt_draft_22), cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 28)) {
        err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_draft_23,
                                sizeof(handshake_salt_draft_23), cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 32)) {
        err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_draft_29,
                                sizeof(handshake_salt_draft_29), cid->cid, cid->len, secret);
    } else if (is_quic_draft_max(version, 34)) {
        err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_v1, sizeof(handshake_salt_v1),
                                cid->cid, cid->len, secret);
    } else {
        err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_v2, sizeof(handshake_salt_v2),
                                cid->cid, cid->len, secret);
    }
    if (err) {
        printf("Failed to extract secrets: %s\n", gcry_strerror(err));
        //*error = wmem_strdup_printf(wmem_packet_scope(), "Failed to extract secrets: %s", gcry_strerror(err));
        return false;
    }

    //printf("HERE5\n");
    //gcry_error_t    err;
    //uint8_t         secret[HASH_SHA2_256_LENGTH];
    //err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_v1, sizeof(handshake_salt_v1), cid->cid, cid->len, secret);
    //print_secrete("Initial Key", secret,HASH_SHA2_256_LENGTH);

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, HASH_SHA2_256_LENGTH, "client in",
                                client_initial_secret, HASH_SHA2_256_LENGTH)) {
        printf("Key extension failed (Client)\n");
        return false;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, HASH_SHA2_256_LENGTH, "server in",
                                server_initial_secret, HASH_SHA2_256_LENGTH)) {
        printf("Key extension failed (Server)\n");
        return false;
    }
    return true;
}

static bool quic_derive_initial_secrets1(const quic_cid_t *cid,
                                         uint8_t client_initial_secret[HASH_SHA2_256_LENGTH],
                                         uint8_t server_initial_secret[HASH_SHA2_256_LENGTH],
                                         uint32_t version, const char **error)
{
    //printf("HERE5\n");
    gcry_error_t err;
    uint8_t secret[HASH_SHA2_256_LENGTH];
    err = hkdf_extract_func(GCRY_MD_SHA256, handshake_salt_v11, sizeof(handshake_salt_v11),
                            cid->cid, cid->len, secret);
    //print_secrete("Initial Key", secret,HASH_SHA2_256_LENGTH);

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, HASH_SHA2_256_LENGTH, "client in",
                                client_initial_secret, HASH_SHA2_256_LENGTH)) {
        printf("Key extension failed (Client)\n");
        return false;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, HASH_SHA2_256_LENGTH, "server in",
                                server_initial_secret, HASH_SHA2_256_LENGTH)) {
        printf("Key extension failed (Server)\n");
        return false;
    }
    return true;
}

static bool quic_create_initial_decoders(Session_info *Session_t, const char **error)
{
    if (!quic_derive_initial_secrets(&Session_t->quic_dcic,
                                     Session_t->quic_cipher_keys.client_initial_secret,
                                     Session_t->quic_cipher_keys.server_initial_secret,
                                     Session_t->quic_version, error)) {
        return false;
    }

    quic_hkdf_expand_label(GCRY_MD_SHA256, Session_t->quic_cipher_keys.client_initial_secret,
                           HASH_SHA2_256_LENGTH, "quic hp",
                           Session_t->quic_cipher_keys.client_hp_key, KEY_LEN);
    quic_hkdf_expand_label(GCRY_MD_SHA256, Session_t->quic_cipher_keys.client_initial_secret,
                           HASH_SHA2_256_LENGTH, "quic iv",
                           Session_t->quic_cipher_keys.client_iv_key, IV_LEN);
    quic_hkdf_expand_label(GCRY_MD_SHA256, Session_t->quic_cipher_keys.client_initial_secret,
                           HASH_SHA2_256_LENGTH, "quic key",
                           Session_t->quic_cipher_keys.client_pp_key, KEY_LEN);

    return true;
}
bool decode_quic(Session_info *Session_t)
{
    //quic_info_data_t quic_info;
    //quic_info.version = 1;
    //uint8_t cid[] = {0xde, 0x77, 0xfc, 0x37,0x4b, 0xd3, 0xad, 0xc4};
    //quic_cid_t cid_t;

    //printf("HERE\n");
    const char **error;
    //uint32_t version = 1;
    return quic_create_initial_decoders(Session_t, error);
}

int process_quic_header(const u_char *quic_packet, int quic_offset,
                        quic_ciphers_t this_quic_ciphers_t,
                        quic_frame_essentials_t *quic_frame_essens)
{
    uint8_t sample[16];
    //memcpy(quic_packet, sample, quic_offset + 4, 16);
    memcpy(sample, quic_packet + quic_offset + 4, 16);
    uint8_t mask[5] = { 0 };
    gcry_cipher_hd_t h;
    gcry_error_t err;

    // Open cipher handle
    err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0);
    if (err) {
        fprintf(stderr, "Failed to open cipher: %s\n", gcry_strerror(err));
        return 0;
    }

    // Set the key
    err = gcry_cipher_setkey(h, this_quic_ciphers_t.client_hp_key, KEY_LEN);
    if (err) {
        fprintf(stderr, "Failed to set key: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        return 0;
    }

    // Encrypt in-place with AES-ECB and extract the mask
    err = gcry_cipher_encrypt(h, sample, sizeof(sample), NULL, 0);
    if (err) {
        fprintf(stderr, "Failed to encrypt: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        return 0;
    }

    // Close cipher handle
    gcry_cipher_close(h);
    /* Encrypt in-place with AES-ECB and extract the mask. */
    //if (gcry_cipher_encrypt(this_quic_ciphers_t.client_hp_key, sample, sizeof(sample), NULL, 0)) {
    //   return;
    //}
    memcpy(mask, sample, sizeof(mask));

    uint8_t quic_byte0 = quic_packet[0];

    quic_byte0 ^= mask[0] & 0x0F;
    uint16_t pkn_len = (quic_byte0 & 0x03) + 1;
    uint8_t pkn_bytes[4];
    memcpy(pkn_bytes, quic_packet + quic_offset, pkn_len);
    uint32_t pkt_pkn = 0;
    for (unsigned i = 0; i < pkn_len; i++) {
        pkt_pkn |= (pkn_bytes[i] ^ mask[1 + i]) << (8 * (pkn_len - 1 - i));
    }
    //printf("Packet Number: %u  pkn_len = %u quic_byte0 %02x\n", pkt_pkn,pkn_len,quic_byte0);
    quic_frame_essens->first_byte = quic_byte0;
    quic_frame_essens->qpkn = pkt_pkn;
    quic_frame_essens->qpkn_len = pkn_len;
    //*pkn_lenx =pkn_len ;
    //*pkt_num = pkt_pkn;
    //*firstbyte = quic_byte0;
    return 1;
}

// Function to read a 4-byte integer in network byte order (big-endian)
uint32_t GetNtohl(const uint8_t *buffer, int offset)
{
    return (uint32_t)buffer[offset] << 24 | (uint32_t)buffer[offset + 1] << 16 |
           (uint32_t)buffer[offset + 2] << 8 | (uint32_t)buffer[offset + 3];
}

// Function to read an 8-byte integer in network byte order (big-endian)
uint64_t GetNtoh64(const uint8_t *buffer, int offset)
{
    return (uint64_t)buffer[offset] << 56 | (uint64_t)buffer[offset + 1] << 48 |
           (uint64_t)buffer[offset + 2] << 40 | (uint64_t)buffer[offset + 3] << 32 |
           (uint64_t)buffer[offset + 4] << 24 | (uint64_t)buffer[offset + 5] << 16 |
           (uint64_t)buffer[offset + 6] << 8 | (uint64_t)buffer[offset + 7];
}

// QUIC varint decoding function
int GetVarInt(const uint8_t *buffer, int offset, uint64_t *value)
{
    if (!buffer)
        return -1; // Null check

    uint8_t firstByte = buffer[offset];

    // Determine the length from the first 2 bits
    int length;
    switch (firstByte >> 6) {
    case 0:
        length = 1;
        break;
    case 1:
        length = 2;
        break;
    case 2:
        length = 4;
        break;
    case 3:
        length = 8;
        break;
    default:
        return -1; // Invalid case
    }

    // Decode the value based on length
    switch (length) {
    case 1:
        *value = (uint64_t)(firstByte & 0x3F);
        break;
    case 2:
        *value = (uint64_t)((firstByte & 0x3F) << 8 | buffer[offset + 1]);
        break;
    case 4:
        *value = (uint64_t)((firstByte & 0x3F) << 24 | GetNtohl(buffer, offset + 1));
        break;
    case 8:
        *value = ((uint64_t)(firstByte & 0x3F) << 56 | GetNtoh64(buffer, offset + 1));
        break;
    default:
        return -1; // Invalid length
    }

    return length; // Return the number of bytes read
}

#define MIN_PRINTABLE_SEQ \
    5 // Minimum length of consecutive printable characters to consider as a string
#define MAX_STR_SIZE 256 // Maximum string length to extract

int process_quic_payload(const uint8_t *associated_data, uint16_t associated_data_len,
                         uint8_t *auth_tag, const uint8_t *cipher_payload,
                         uint16_t cipher_payload_len, quic_frame_essentials_t quic_frames_essens,
                         quic_ciphers_t this_quic_ciphers_t, uint8_t *decrypted_payload)
{
    gcry_error_t err;
    uint8_t nonce[IV_LEN];

    //size_t payload_len = strlen((const char *)cipher_payload);
    uint8_t *modified_header = (uint8_t *)malloc(associated_data_len);
    if (!modified_header) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    // Copy associateddata bytes to modified_header
    memcpy(modified_header, associated_data, associated_data_len);
    modified_header[0] = quic_frames_essens.first_byte;

    // Replace the Packet Number (PKN) with its plaintext version
    for (int i = 0; i < quic_frames_essens.qpkn_len; i++) {
        modified_header[associated_data_len - 1 - i] =
                (uint8_t)((quic_frames_essens.qpkn >> (8 * i)) & 0xFF);
    }

    memcpy(nonce, this_quic_ciphers_t.client_iv_key, IV_LEN);
    for (int i = 0; i < 4; i++) {
        nonce[IV_LEN - 1 - i] ^= (quic_frames_essens.qpkn >> (8 * i)) & 0xFF;
    }
    //print nonce
    //printf("Nonce: ");
    //for (size_t i = 0; i < IV_LEN; i++) {
    //    printf("%02x", nonce[i]);
    //}
    //print modified header
    //printf("\nModified Header: ");
    //for (size_t i = 0; i < associated_data_len; i++) {
    //   printf("%02x", modified_header[i]);
    //}
    //printf("\n");
    //

    gcry_cipher_hd_t h;
    // Open cipher handle
    err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
    if (err) {
        //fprintf(stderr, "Failed to open cipher: %s\n", gcry_strerror(err));
        free(modified_header);
        return 0;
    }

    // Set the key
    err = gcry_cipher_setkey(h, this_quic_ciphers_t.client_pp_key, KEY_LEN);
    if (err) {
        //fprintf(stderr, "Failed to set key: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Set the IV (nonce)
    err = gcry_cipher_setiv(h, nonce, IV_LEN);
    if (err) {
        //fprintf(stderr, "Failed to set IV: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Set the AAD (Associated Data)
    err = gcry_cipher_authenticate(h, modified_header, associated_data_len);
    if (err) {
        //fprintf(stderr, "Failed to set AAD: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Decrypt the payload
    err = gcry_cipher_decrypt(h, decrypted_payload, cipher_payload_len, cipher_payload,
                              cipher_payload_len);
    if (err) {
        //fprintf(stderr, "Failed to decrypt payload: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }
    err = gcry_cipher_checktag(h, auth_tag, 16);
    if (err) {
        //fprintf(stderr, "Failed to verify authentication tag: %s\n", gcry_strerror(err));
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Print decrypted payload
    //printf("Decrypted Payload: %u\n %s",cipher_payload_len, extract_printable_string(decrypted_payload, cipher_payload_len));
    //print_secrete("Decrypted Payload", decrypted_payload, cipher_payload_len);
    //extract_string_from_uint8(decrypted_payload, cipher_payload_len) ;
    // for (size_t i = 0; i < cipher_payload_len; i++) {
    //     if (isprint(decrypted_payload[i])) {
    //         putchar(decrypted_payload[i]);  // Print as character
    //     } else {
    //         putchar('.');      // Print a dot for non-printable characters
    //     }
    //     //printf("%c", (char)decrypted_payload[i]);
    // }
    // printf("\n");

    // Clean up
    gcry_cipher_close(h);
    free(modified_header);

    return 1;
}

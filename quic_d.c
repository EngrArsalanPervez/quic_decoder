#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <gcrypt.h>
#include <glib.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "quic_d.h"

#ifndef WS_DLL_PUBLIC
#define WS_DLL_PUBLIC
#endif

#define TLS13_AEAD_NONCE_LENGTH 12

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
    return ws_hmac_buffer(hashalgo, prk, ikm, ikm_len, salt, salt_len);
}

gcry_error_t hkdf_expand(int hashalgo, const uint8_t *prk, unsigned prk_len, const uint8_t *info,
                         unsigned info_len, uint8_t *out, unsigned out_len)
{
    unsigned char lastoutput[48];
    gcry_md_hd_t h;
    gcry_error_t err;
    const unsigned hash_len = gcry_md_get_algo_dlen(hashalgo);

    if (!(out_len > 0 && out_len <= 255 * hash_len) ||
        !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
        return GPG_ERR_INV_ARG;
    }

    err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
    if (err)
        return err;

    for (unsigned offset = 0; offset < out_len; offset += hash_len) {
        gcry_md_reset(h);
        gcry_md_setkey(h, prk, prk_len);

        if (offset > 0) {
            gcry_md_write(h, lastoutput, hash_len);
        }

        gcry_md_write(h, info, info_len);
        gcry_md_putc(h, (uint8_t)(offset / hash_len + 1));

        memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);

        // Optimized: use MIN macro inline
        unsigned copy_len = (hash_len < out_len - offset) ? hash_len : (out_len - offset);
        memcpy(out + offset, lastoutput, copy_len);
    }

    gcry_md_close(h);
    return 0;
}

static inline gcry_error_t hkdf_extract_func(int hashalgo, const uint8_t *salt, size_t salt_len,
                                             const uint8_t *ikm, size_t ikm_len, uint8_t *prk)
{
    return hkdf_extract(hashalgo, salt, salt_len, ikm, ikm_len, prk);
}

bool tls13_hkdf_expand_label_context(int md, const StringInfo *secret, const char *label_prefix,
                                     const char *label, const uint8_t *context_hash,
                                     uint8_t context_length, uint16_t out_len, unsigned char **out)
{
    gcry_error_t err;
    const unsigned label_prefix_length = (unsigned)strlen(label_prefix);
    const unsigned label_length = (unsigned)strlen(label);

    if (!(label_length > 0 && label_prefix_length + label_length <= 255)) {
        return false;
    }

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
        memcpy(out, out_mem, out_len);
        g_free(out_mem);
        return true;
    }

    return false;
}

static inline uint8_t quic_draft_version(uint32_t version)
{
    // IETF Draft versions
    if ((version >> 8) == 0xff0000) {
        return (uint8_t)version;
    }

    // Facebook mvfst variants
    if (version == 0xfaceb001)
        return 22;
    if (version == 0xfaceb002 || version == 0xfaceb00e)
        return 27;

    // GQUIC variants
    if (version == 0x51303530 || version == 0x54303530 || version == 0x54303531)
        return 27;

    // Version negotiation pattern
    if ((version & 0x0F0F0F0F) == 0x0a0a0a0a)
        return 34;

    // QUIC v1
    if (version == 0x00000001)
        return 34;

    // QUIC v2
    if (version == 0x6b3343cf)
        return 100;

    return 0;
}

static inline bool is_quic_draft_max(uint32_t version, uint8_t max_version)
{
    uint8_t draft_version = quic_draft_version(version);
    return draft_version && draft_version <= max_version;
}

static bool quic_derive_initial_secrets(const quic_cid_t *cid,
                                        uint8_t client_initial_secret[HASH_SHA2_256_LENGTH],
                                        uint8_t server_initial_secret[HASH_SHA2_256_LENGTH],
                                        uint32_t version)
{
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

    static const uint8_t handshake_salt_v2[20] = { 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6,
                                                   0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                                                   0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 };

    const uint8_t *salt;
    size_t salt_len;

    // Optimized: direct version comparison
    if (version == 0x00000001 || version == 0x6b3343cf) {
        salt = (version == 0x00000001) ? handshake_salt_v1 : handshake_salt_v2;
        salt_len = 20;
    } else if (is_quic_draft_max(version, 22)) {
        salt = handshake_salt_draft_22;
        salt_len = 20;
    } else if (is_quic_draft_max(version, 28)) {
        salt = handshake_salt_draft_23;
        salt_len = 20;
    } else if (is_quic_draft_max(version, 255)) {
        salt = handshake_salt_draft_29;
        salt_len = 20;
    } else {
        return false;
    }

    uint8_t secret[HASH_SHA2_256_LENGTH];
    if (hkdf_extract_func(GCRY_MD_SHA256, salt, salt_len, cid->cid, cid->len, secret)) {
        return false;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, HASH_SHA2_256_LENGTH, "client in",
                                client_initial_secret, HASH_SHA2_256_LENGTH)) {
        return false;
    }

    if (!quic_hkdf_expand_label(GCRY_MD_SHA256, secret, HASH_SHA2_256_LENGTH, "server in",
                                server_initial_secret, HASH_SHA2_256_LENGTH)) {
        return false;
    }

    return true;
}

static bool quic_create_initial_decoders(Session_info *Session_t)
{
    if (!quic_derive_initial_secrets(
                &Session_t->quic_dcic, Session_t->quic_cipher_keys.client_initial_secret,
                Session_t->quic_cipher_keys.server_initial_secret, Session_t->quic_version)) {
        return false;
    }

    // Expand all three keys - consider batching if possible
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
    return quic_create_initial_decoders(Session_t);
}

int process_quic_header(const u_char *quic_packet, int quic_offset,
                        quic_ciphers_t this_quic_ciphers_t,
                        quic_frame_essentials_t *quic_frame_essens)
{
    uint8_t sample[16];
    memcpy(sample, quic_packet + quic_offset + 4, 16);

    gcry_cipher_hd_t h;
    gcry_error_t err;

    // Open cipher handle
    err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0);
    if (err) {
        return 0;
    }

    // Set the key
    err = gcry_cipher_setkey(h, this_quic_ciphers_t.client_hp_key, KEY_LEN);
    if (err) {
        gcry_cipher_close(h);
        return 0;
    }

    // Encrypt in-place with AES-ECB to get mask
    err = gcry_cipher_encrypt(h, sample, sizeof(sample), NULL, 0);
    gcry_cipher_close(h);

    if (err) {
        return 0;
    }

    // Extract mask (first 5 bytes)
    uint8_t mask[5];
    memcpy(mask, sample, sizeof(mask));

    // Unmask first byte
    uint8_t quic_byte0 = quic_packet[0] ^ (mask[0] & 0x0F);
    uint16_t pkn_len = (quic_byte0 & 0x03) + 1;

    // Unmask packet number
    uint32_t pkt_pkn = 0;
    for (unsigned i = 0; i < pkn_len; i++) {
        uint8_t masked_byte = quic_packet[quic_offset + i];
        uint8_t unmasked_byte = masked_byte ^ mask[1 + i];
        pkt_pkn |= (uint32_t)unmasked_byte << (8 * (pkn_len - 1 - i));
    }

    quic_frame_essens->first_byte = quic_byte0;
    quic_frame_essens->qpkn = pkt_pkn;
    quic_frame_essens->qpkn_len = pkn_len;

    return 1;
}

// Optimized: inline functions for byte order conversion
static inline uint32_t read_be32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) |
           (uint32_t)buf[3];
}

static inline uint64_t read_be64(const uint8_t *buf)
{
    return ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) | ((uint64_t)buf[2] << 40) |
           ((uint64_t)buf[3] << 32) | ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
           ((uint64_t)buf[6] << 8) | (uint64_t)buf[7];
}

// QUIC varint decoding function - optimized
int GetVarInt(const uint8_t *buffer, int offset, uint64_t *value)
{
    if (!buffer)
        return -1;

    uint8_t firstByte = buffer[offset];
    uint8_t length_code = firstByte >> 6;

    // Optimized: compute directly based on length code
    switch (length_code) {
    case 0:
        *value = firstByte & 0x3F;
        return 1;
    case 1:
        *value = ((uint64_t)(firstByte & 0x3F) << 8) | buffer[offset + 1];
        return 2;
    case 2:
        *value = ((uint64_t)(firstByte & 0x3F) << 24) | read_be32(buffer + offset + 1);
        return 4;
    case 3:
        *value = ((uint64_t)(firstByte & 0x3F) << 56) | read_be64(buffer + offset + 1);
        return 8;
    }

    return -1;
}

int process_quic_payload(const uint8_t *associated_data, uint16_t associated_data_len,
                         uint8_t *auth_tag, const uint8_t *cipher_payload,
                         uint16_t cipher_payload_len, quic_frame_essentials_t quic_frames_essens,
                         quic_ciphers_t this_quic_ciphers_t, uint8_t *decrypted_payload)
{
    gcry_error_t err;
    uint8_t nonce[IV_LEN];

    // Allocate modified header
    uint8_t *modified_header = (uint8_t *)malloc(associated_data_len);
    if (!modified_header) {
        return 0;
    }

    memcpy(modified_header, associated_data, associated_data_len);
    modified_header[0] = quic_frames_essens.first_byte;

    // Replace the Packet Number (PKN) with plaintext version
    for (int i = 0; i < quic_frames_essens.qpkn_len; i++) {
        modified_header[associated_data_len - 1 - i] =
                (uint8_t)((quic_frames_essens.qpkn >> (8 * i)) & 0xFF);
    }

    // Construct nonce
    memcpy(nonce, this_quic_ciphers_t.client_iv_key, IV_LEN);
    for (int i = 0; i < 4; i++) {
        nonce[IV_LEN - 1 - i] ^= (uint8_t)((quic_frames_essens.qpkn >> (8 * i)) & 0xFF);
    }

    gcry_cipher_hd_t h;

    // Open cipher handle
    err = gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 0);
    if (err) {
        free(modified_header);
        return 0;
    }

    // Set key
    err = gcry_cipher_setkey(h, this_quic_ciphers_t.client_pp_key, KEY_LEN);
    if (err) {
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Set IV (nonce)
    err = gcry_cipher_setiv(h, nonce, IV_LEN);
    if (err) {
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Set AAD
    err = gcry_cipher_authenticate(h, modified_header, associated_data_len);
    if (err) {
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Decrypt payload
    err = gcry_cipher_decrypt(h, decrypted_payload, cipher_payload_len, cipher_payload,
                              cipher_payload_len);
    if (err) {
        gcry_cipher_close(h);
        free(modified_header);
        return 0;
    }

    // Verify auth tag
    err = gcry_cipher_checktag(h, auth_tag, 16);

    gcry_cipher_close(h);
    free(modified_header);

    return (err == 0) ? 1 : 0;
}

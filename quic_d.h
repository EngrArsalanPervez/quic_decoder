#include <stdbool.h>
#include <stdint.h>

typedef struct _StringInfo {
    unsigned char *data; /* Backing storage which may be larger than data_len */
    unsigned data_len; /* Length of the meaningful part of data */
} StringInfo;

#define QUIC_MAX_CID_LENGTH 20
typedef struct quic_cid {
    uint8_t len;
    uint8_t cid[QUIC_MAX_CID_LENGTH];
} quic_cid_t;

typedef struct quic_frame_essentials {
    uint16_t qpkn_len;
    uint64_t qpkn;
    uint8_t first_byte;
} quic_frame_essentials_t;

#define HASH_SHA2_256_LENGTH 32
#define KEY_LEN 16 // 16 bytes for AES-128
#define IV_LEN 12 // 12 bytes for IV
typedef struct quic_ciphers_h {
    uint8_t client_initial_secret[HASH_SHA2_256_LENGTH];
    uint8_t client_initial_secret_len;
    uint8_t server_initial_secret[HASH_SHA2_256_LENGTH];
    uint8_t server_initial_secret_len;
    unsigned char client_hp_key[KEY_LEN];
    unsigned char client_iv_key[IV_LEN];
    unsigned char client_pp_key[KEY_LEN];
} quic_ciphers_t;

typedef struct Session {
    uint32_t quic_version;
    quic_cid_t quic_dcic;
    quic_ciphers_t quic_cipher_keys;
} Session_info;

int GetVarInt(const uint8_t *buffer, int offset, uint64_t *value);
bool decode_quic(Session_info *Session_t);
int process_quic_header(const unsigned char *quic_packet, int quic_offset,
                        quic_ciphers_t this_quic_ciphers_t,
                        quic_frame_essentials_t *quic_frame_essens);
int process_quic_payload(const uint8_t *associated_data, uint16_t associated_data_len,
                         uint8_t *auth_tag, const uint8_t *cipher_payload,
                         uint16_t cipher_payload_len, quic_frame_essentials_t quic_frames_essens,
                         quic_ciphers_t this_quic_ciphers_t, uint8_t *decrypted_payload);

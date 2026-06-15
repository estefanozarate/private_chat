#include "hsm.h"
#include "frame.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "bootloader_random.h"

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

#include "monocypher.h"
#include "monocypher-ed25519.h"

static const char *TAG = "hsm";
#define NVS_NS "hsm"

/* ---- identity (persisted, flash-encrypted NVS) ---- */
static uint8_t id_ed_sk[64];   /* Ed25519 secret (RFC 8032) */
static uint8_t id_ed_pk[32];   /* Ed25519 public */
static uint8_t id_x_sk[32];    /* X25519 secret */
static uint8_t id_x_pk[32];    /* X25519 public */

/* ---- session/ratchet (single slot for Fase 1; persisted) ---- */
static bool     have_session = false;
static uint8_t  sess_send[32]; /* AEAD key for our outbound messages */
static uint8_t  sess_recv[32]; /* AEAD key for inbound messages */
static uint32_t ratchet_gen = 0;
static uint64_t send_ctr = 0;  /* RAM-only; nonce = gen||send_ctr, reset on key change */

/* ================= NVS helpers ================= */
static esp_err_t nvs_get_fixed(nvs_handle_t h, const char *k, void *buf, size_t want)
{
    size_t sz = want;
    esp_err_t e = nvs_get_blob(h, k, buf, &sz);
    if (e == ESP_OK && sz != want) return ESP_ERR_INVALID_SIZE;
    return e;
}

/* ================= KDF / crypto helpers ================= */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -1;
    /* salt empty: HKDF-Extract uses a zero salt internally */
    return mbedtls_hkdf(md, NULL, 0, ikm, ikm_len, info, info_len, okm, okm_len);
}

/* Derive directional keys from the raw DH secret, binding to both pubkeys.
 * Both peers compute identical k_l2h / k_h2l; role (who is lexicographically
 * "low") decides which is send vs recv -> A.send == B.recv. This prevents
 * AES-GCM nonce reuse that a single shared key would cause. */
static void derive_session_keys(const uint8_t shared[32],
                                const uint8_t peer_pk[32])
{
    int we_are_low = (memcmp(id_x_pk, peer_pk, 32) < 0);
    const uint8_t *low  = we_are_low ? id_x_pk : peer_pk;
    const uint8_t *high = we_are_low ? peer_pk : id_x_pk;

    uint8_t info_l2h[15 + 64];
    uint8_t info_h2l[15 + 64];
    memcpy(info_l2h, "chat-e2e/v1/l2h", 15);
    memcpy(info_h2l, "chat-e2e/v1/h2l", 15);
    memcpy(info_l2h + 15, low, 32);  memcpy(info_l2h + 47, high, 32);
    memcpy(info_h2l + 15, low, 32);  memcpy(info_h2l + 47, high, 32);

    uint8_t k_l2h[32], k_h2l[32];
    hkdf_sha256(shared, 32, info_l2h, sizeof(info_l2h), k_l2h, 32);
    hkdf_sha256(shared, 32, info_h2l, sizeof(info_h2l), k_h2l, 32);

    if (we_are_low) { memcpy(sess_send, k_l2h, 32); memcpy(sess_recv, k_h2l, 32); }
    else            { memcpy(sess_send, k_h2l, 32); memcpy(sess_recv, k_l2h, 32); }

    crypto_wipe(k_l2h, 32);
    crypto_wipe(k_h2l, 32);
}

static int persist_session(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    nvs_set_blob(h, "s_send", sess_send, 32);
    nvs_set_blob(h, "s_recv", sess_recv, 32);
    nvs_set_u32 (h, "s_gen",  ratchet_gen);
    nvs_set_u8  (h, "s_have", 1);
    esp_err_t e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}

/* nonce = ratchet_gen (4 LE) || send_ctr (8 LE) = 12 bytes (AES-GCM IV) */
static void make_send_nonce(uint8_t nonce[12])
{
    nonce[0] = (uint8_t)(ratchet_gen);       nonce[1] = (uint8_t)(ratchet_gen >> 8);
    nonce[2] = (uint8_t)(ratchet_gen >> 16); nonce[3] = (uint8_t)(ratchet_gen >> 24);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(send_ctr >> (8 * i));
}

static int aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *pt, size_t n,
                           uint8_t *ct, uint8_t tag[16])
{
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (r == 0)
        r = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, n,
                                      nonce, 12, NULL, 0, pt, ct, 16, tag);
    mbedtls_gcm_free(&g);
    return r;
}

static int aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t *ct, size_t n, const uint8_t tag[16],
                           uint8_t *pt)
{
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (r == 0)
        r = mbedtls_gcm_auth_decrypt(&g, n, nonce, 12, NULL, 0,
                                     tag, 16, ct, pt);
    mbedtls_gcm_free(&g);
    return r; /* nonzero => auth failure */
}

/* ================= provisioning ================= */
static int provision_identity(void)
{
    ESP_LOGW(TAG, "first boot: generating identity keypairs");
    /* This HSM has no RF subsystem, so seed the RNG from hardware entropy
     * sources before key generation, then disable it again. */
    bootloader_random_enable();

    uint8_t seed[32];
    esp_fill_random(seed, sizeof(seed));
    crypto_ed25519_key_pair(id_ed_sk, id_ed_pk, seed); /* wipes seed */

    esp_fill_random(id_x_sk, sizeof(id_x_sk));
    crypto_x25519_public_key(id_x_pk, id_x_sk);        /* clamps internally */

    bootloader_random_disable();

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    nvs_set_blob(h, "id_ed_sk", id_ed_sk, 64);
    nvs_set_blob(h, "id_ed_pk", id_ed_pk, 32);
    nvs_set_blob(h, "id_x_sk",  id_x_sk, 32);
    nvs_set_blob(h, "id_x_pk",  id_x_pk, 32);
    nvs_set_u8  (h, "prov", 1);
    esp_err_t e = nvs_commit(h);
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}

int hsm_init(void)
{
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        e = nvs_flash_init();
    }
    ESP_ERROR_CHECK(e);

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;

    uint8_t prov = 0;
    nvs_get_u8(h, "prov", &prov);
    if (!prov) {
        nvs_close(h);
        if (provision_identity() != 0) return -1;
        if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return -1;
    } else {
        if (nvs_get_fixed(h, "id_ed_sk", id_ed_sk, 64) != ESP_OK ||
            nvs_get_fixed(h, "id_ed_pk", id_ed_pk, 32) != ESP_OK ||
            nvs_get_fixed(h, "id_x_sk",  id_x_sk, 32) != ESP_OK ||
            nvs_get_fixed(h, "id_x_pk",  id_x_pk, 32) != ESP_OK) {
            nvs_close(h);
            return -1;
        }
    }

    /* restore session if persisted (survives browser disconnect) */
    uint8_t have = 0;
    nvs_get_u8(h, "s_have", &have);
    if (have &&
        nvs_get_fixed(h, "s_send", sess_send, 32) == ESP_OK &&
        nvs_get_fixed(h, "s_recv", sess_recv, 32) == ESP_OK &&
        nvs_get_u32(h, "s_gen", &ratchet_gen) == ESP_OK) {
        have_session = true;
        send_ctr = 0; /* counter is RAM-only; restart safe because... see note */
        ESP_LOGI(TAG, "restored session, ratchet gen=%u", (unsigned)ratchet_gen);
    }
    nvs_close(h);
    ESP_LOGI(TAG, "hsm ready");
    return 0;
}

/* ================= command handlers ================= */
static size_t err_resp(uint8_t *out_cmd, uint8_t *out_flags, uint8_t st)
{
    *out_cmd = CMD_ERROR; *out_flags = st;
    return 0;
}

size_t hsm_handle_command(uint8_t cmd, uint8_t flags,
                          const uint8_t *payload, uint16_t len,
                          uint8_t *out_cmd, uint8_t *out_flags,
                          uint8_t *out_payload, size_t out_cap)
{
    (void)flags;
    *out_cmd = cmd; *out_flags = ST_OK;

    switch (cmd) {
    case CMD_GET_PUBKEY: {
        if (len != 0) return err_resp(out_cmd, out_flags, ST_BAD_LENGTH);
        if (out_cap < 64) return err_resp(out_cmd, out_flags, ST_INTERNAL);
        memcpy(out_payload,      id_x_pk,  32);  /* X25519 identity pub */
        memcpy(out_payload + 32, id_ed_pk, 32);  /* Ed25519 identity pub */
        return 64;
    }

    case CMD_DERIVE_SESSION: {
        if (len != 32) return err_resp(out_cmd, out_flags, ST_BAD_LENGTH);
        if (out_cap < 64) return err_resp(out_cmd, out_flags, ST_INTERNAL);
        uint8_t shared[32];
        crypto_x25519(shared, id_x_sk, payload);
        /* reject low-order / all-zero shared secret */
        uint8_t acc = 0; for (int i = 0; i < 32; i++) acc |= shared[i];
        if (acc == 0) { crypto_wipe(shared, 32); return err_resp(out_cmd, out_flags, ST_CRYPTO_FAIL); }

        derive_session_keys(shared, payload);
        crypto_wipe(shared, 32);
        ratchet_gen = 0; send_ctr = 0; have_session = true;
        if (persist_session() != 0) return err_resp(out_cmd, out_flags, ST_INTERNAL);

        /* Diseño B export: send_key || recv_key (see docs for the trade-off) */
        memcpy(out_payload,      sess_send, 32);
        memcpy(out_payload + 32, sess_recv, 32);
        return 64;
    }

    case CMD_ENCRYPT: {
        if (!have_session) return err_resp(out_cmd, out_flags, ST_NO_SESSION);
        size_t need = 12 + (size_t)len + 16;
        if (need > out_cap || need > FRAME_MAX_PAYLOAD)
            return err_resp(out_cmd, out_flags, ST_BAD_LENGTH);
        uint8_t nonce[12]; make_send_nonce(nonce);
        uint8_t *ct  = out_payload + 12;
        uint8_t *tag = out_payload + 12 + len;
        if (aes_gcm_encrypt(sess_send, nonce, payload, len, ct, tag) != 0)
            return err_resp(out_cmd, out_flags, ST_CRYPTO_FAIL);
        memcpy(out_payload, nonce, 12);
        send_ctr++;  /* never reuse (nonce, key) */
        return need;
    }

    case CMD_DECRYPT: {
        if (!have_session) return err_resp(out_cmd, out_flags, ST_NO_SESSION);
        if (len < 12 + 16) return err_resp(out_cmd, out_flags, ST_BAD_LENGTH);
        uint16_t ct_len = len - 12 - 16;
        if (ct_len > out_cap) return err_resp(out_cmd, out_flags, ST_BAD_LENGTH);
        const uint8_t *nonce = payload;
        const uint8_t *ct    = payload + 12;
        const uint8_t *tag   = payload + 12 + ct_len;
        if (aes_gcm_decrypt(sess_recv, nonce, ct, ct_len, tag, out_payload) != 0)
            return err_resp(out_cmd, out_flags, ST_DECRYPT_FAIL);
        return ct_len;
    }

    case CMD_RATCHET_ADVANCE: {
        if (!have_session) return err_resp(out_cmd, out_flags, ST_NO_SESSION);
        uint8_t ns[32], nr[32];
        const uint8_t info[] = "chat-e2e/v1/ratchet";
        hkdf_sha256(sess_send, 32, info, sizeof(info) - 1, ns, 32);
        hkdf_sha256(sess_recv, 32, info, sizeof(info) - 1, nr, 32);
        memcpy(sess_send, ns, 32); memcpy(sess_recv, nr, 32);
        crypto_wipe(ns, 32); crypto_wipe(nr, 32);
        ratchet_gen++; send_ctr = 0;
        if (persist_session() != 0) return err_resp(out_cmd, out_flags, ST_INTERNAL);
        out_payload[0] = (uint8_t)(ratchet_gen);
        out_payload[1] = (uint8_t)(ratchet_gen >> 8);
        out_payload[2] = (uint8_t)(ratchet_gen >> 16);
        out_payload[3] = (uint8_t)(ratchet_gen >> 24);
        return 4;
    }

    case CMD_SIGN_CHALLENGE: {
        if (len == 0 || len > FRAME_MAX_PAYLOAD)
            return err_resp(out_cmd, out_flags, ST_BAD_LENGTH);
        if (out_cap < 64) return err_resp(out_cmd, out_flags, ST_INTERNAL);
        crypto_ed25519_sign(out_payload, id_ed_sk, payload, len);
        return 64;
    }

    default:
        return err_resp(out_cmd, out_flags, ST_BAD_CMD);
    }
}

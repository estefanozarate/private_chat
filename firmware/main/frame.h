#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ===== Wire frame ====================================================
 *  [0xA5][0x5A]  SOF magic (resync marker, NOT covered by CRC)
 *  [CMD]         1 byte
 *  [FLAGS]       1 byte   (request: reserved=0; response: status code)
 *  [LEN]         2 bytes  uint16 little-endian, length of PAYLOAD only
 *  [PAYLOAD]     LEN bytes
 *  [CRC]         2 bytes  uint16 little-endian, CRC-16/CCITT over CMD..PAYLOAD
 * ==================================================================== */

#define FRAME_SOF0 0xA5
#define FRAME_SOF1 0x5A
#define FRAME_HEADER_LEN 4          /* CMD+FLAGS+LEN, after SOF */
#define FRAME_MAX_PAYLOAD 2048      /* bounds RAM; reject larger */

/* Commands (request CMD echoed back on success). */
typedef enum {
    CMD_GET_PUBKEY      = 0x01,
    CMD_DERIVE_SESSION  = 0x02,
    CMD_ENCRYPT         = 0x03,
    CMD_DECRYPT         = 0x04,
    CMD_RATCHET_ADVANCE = 0x05,
    CMD_SIGN_CHALLENGE  = 0x06,
    CMD_ERROR           = 0xFF,
} hsm_cmd_t;

/* Status codes carried in FLAGS byte of a response (0 == OK). */
typedef enum {
    ST_OK            = 0x00,
    ST_BAD_LENGTH    = 0x01,
    ST_BAD_CMD       = 0x02,
    ST_NO_SESSION    = 0x03,
    ST_DECRYPT_FAIL  = 0x04,
    ST_NOT_PROVISIONED = 0x05,
    ST_INTERNAL      = 0x06,
    ST_CRYPTO_FAIL   = 0x07,
} hsm_status_t;

/* Callback invoked for every complete, CRC-valid frame. */
typedef void (*frame_handler_t)(uint8_t cmd, uint8_t flags,
                                const uint8_t *payload, uint16_t len);

/* Streaming parser state. Feed arbitrary byte chunks; resyncs on SOF
 * after any corruption or CRC mismatch. */
typedef enum {
    PS_SOF0, PS_SOF1, PS_HEADER, PS_PAYLOAD, PS_CRC
} frame_parse_state_t;

typedef struct {
    frame_parse_state_t state;
    uint8_t  hdr[FRAME_HEADER_LEN];
    uint8_t  hdr_got;
    uint8_t  cmd, flags;
    uint16_t len;
    uint16_t payload_got;
    uint8_t  crc_buf[2];
    uint8_t  crc_got;
    uint8_t  payload[FRAME_MAX_PAYLOAD];
    frame_handler_t on_frame;
} frame_parser_t;

void frame_parser_init(frame_parser_t *p, frame_handler_t handler);
void frame_parser_feed(frame_parser_t *p, const uint8_t *data, size_t len);

/* Build a frame into `out` (caller-provided, must hold 6 + len bytes).
 * Returns total bytes written, or 0 if payload too large. */
size_t frame_encode(uint8_t cmd, uint8_t flags,
                    const uint8_t *payload, uint16_t len,
                    uint8_t *out, size_t out_cap);

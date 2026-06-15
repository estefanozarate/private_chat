#include "frame.h"
#include "crc16.h"
#include <string.h>

/* CRC over two concatenated regions in a single pass (one init). */
static uint16_t crc16_two(const uint8_t *a, size_t na,
                          const uint8_t *b, size_t nb)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < na + nb; i++) {
        uint8_t byte = (i < na) ? a[i] : b[i - na];
        crc ^= (uint16_t)byte << 8;
        for (int k = 0; k < 8; k++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }
    return crc;
}

void frame_parser_init(frame_parser_t *p, frame_handler_t handler)
{
    memset(p, 0, sizeof(*p));
    p->state = PS_SOF0;
    p->on_frame = handler;
}

static void reset(frame_parser_t *p)
{
    p->state = PS_SOF0;
    p->hdr_got = 0;
    p->payload_got = 0;
    p->crc_got = 0;
}

void frame_parser_feed(frame_parser_t *p, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        switch (p->state) {
        case PS_SOF0:
            if (c == FRAME_SOF0) p->state = PS_SOF1;
            break;
        case PS_SOF1:
            if (c == FRAME_SOF1) { p->state = PS_HEADER; p->hdr_got = 0; }
            else if (c == FRAME_SOF0) p->state = PS_SOF1;  /* A5 A5 .. */
            else p->state = PS_SOF0;
            break;
        case PS_HEADER:
            p->hdr[p->hdr_got++] = c;
            if (p->hdr_got == FRAME_HEADER_LEN) {
                p->cmd   = p->hdr[0];
                p->flags = p->hdr[1];
                p->len   = (uint16_t)p->hdr[2] | ((uint16_t)p->hdr[3] << 8);
                if (p->len > FRAME_MAX_PAYLOAD) { reset(p); break; } /* drop, resync */
                p->payload_got = 0;
                p->state = (p->len == 0) ? PS_CRC : PS_PAYLOAD;
            }
            break;
        case PS_PAYLOAD:
            p->payload[p->payload_got++] = c;
            if (p->payload_got == p->len) { p->crc_got = 0; p->state = PS_CRC; }
            break;
        case PS_CRC:
            p->crc_buf[p->crc_got++] = c;
            if (p->crc_got == 2) {
                uint16_t rx = (uint16_t)p->crc_buf[0] | ((uint16_t)p->crc_buf[1] << 8);
                uint16_t calc = crc16_two(p->hdr, FRAME_HEADER_LEN,
                                          p->payload, p->len);
                if (rx == calc && p->on_frame)
                    p->on_frame(p->cmd, p->flags, p->payload, p->len);
                reset(p);  /* good or bad, hunt next SOF */
            }
            break;
        }
    }
}

size_t frame_encode(uint8_t cmd, uint8_t flags,
                    const uint8_t *payload, uint16_t len,
                    uint8_t *out, size_t out_cap)
{
    if (len > FRAME_MAX_PAYLOAD) return 0;
    size_t total = 2 + FRAME_HEADER_LEN + len + 2;
    if (out_cap < total) return 0;

    uint8_t hdr[FRAME_HEADER_LEN] = {
        cmd, flags, (uint8_t)(len & 0xFF), (uint8_t)(len >> 8)
    };
    uint16_t crc = crc16_two(hdr, FRAME_HEADER_LEN, payload ? payload : (const uint8_t*)"", len);

    size_t i = 0;
    out[i++] = FRAME_SOF0; out[i++] = FRAME_SOF1;
    memcpy(out + i, hdr, FRAME_HEADER_LEN); i += FRAME_HEADER_LEN;
    if (len) { memcpy(out + i, payload, len); i += len; }
    out[i++] = (uint8_t)(crc & 0xFF);
    out[i++] = (uint8_t)(crc >> 8);
    return i;
}

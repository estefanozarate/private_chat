#pragma once
#include <stdint.h>
#include <stddef.h>

/* CRC-16/CCITT-FALSE: poly=0x1021, init=0xFFFF, refin/out=false, xorout=0.
 * Check value for ASCII "123456789" == 0x29B1. */
uint16_t crc16_ccitt(const uint8_t *data, size_t len);

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Initialize crypto state: load identity keys from NVS, provisioning on
 * first boot, restore persisted session/ratchet state if present.
 * Returns 0 on success. */
int hsm_init(void);

/* Process one decoded request frame and produce a response frame body.
 * Writes the response CMD/FLAGS and payload into the provided buffers.
 * Returns response payload length (>=0). On error, sets *out_cmd=CMD_ERROR
 * and *out_flags to a status code with a short payload. */
size_t hsm_handle_command(uint8_t cmd, uint8_t flags,
                          const uint8_t *payload, uint16_t len,
                          uint8_t *out_cmd, uint8_t *out_flags,
                          uint8_t *out_payload, size_t out_cap);

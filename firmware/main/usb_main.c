#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "driver/usb_serial_jtag.h"

#include "frame.h"
#include "hsm.h"

static const char *TAG = "usb_main";

static frame_parser_t g_parser;
static uint8_t g_resp_payload[FRAME_MAX_PAYLOAD];
static uint8_t g_tx[2 + FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + 2];
static uint8_t g_rx[256];

/* Transport: ESP32-S3 built-in USB-Serial-JTAG (the peripheral macOS shows as
 * "USB JTAG/serial debug unit"). Chosen over TinyUSB-OTG because it owns the
 * native USB pins by default and needs no PHY switching. The browser side
 * (Web Serial CDC) is unchanged. */
static void usb_write_all(const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int w = usb_serial_jtag_write_bytes(data + off, len - off, pdMS_TO_TICKS(100));
        if (w > 0) off += (size_t)w;
    }
}

/* Called for each complete, CRC-valid request frame. */
static void on_frame(uint8_t cmd, uint8_t flags, const uint8_t *payload, uint16_t len)
{
    uint8_t out_cmd, out_flags;
    size_t out_len = hsm_handle_command(cmd, flags, payload, len,
                                        &out_cmd, &out_flags,
                                        g_resp_payload, sizeof(g_resp_payload));
    size_t n = frame_encode(out_cmd, out_flags, g_resp_payload, (uint16_t)out_len,
                            g_tx, sizeof(g_tx));
    if (n) usb_write_all(g_tx, n);
}

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32-S3 HSM starting");
    ESP_ERROR_CHECK(hsm_init() == 0 ? ESP_OK : ESP_FAIL);

    frame_parser_init(&g_parser, on_frame);

    usb_serial_jtag_driver_config_t cfg = {
        .rx_buffer_size = 1024,
        .tx_buffer_size = 1024,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));

    ESP_LOGI(TAG, "USB-Serial-JTAG ready, waiting for host");

    for (;;) {
        int n = usb_serial_jtag_read_bytes(g_rx, sizeof(g_rx), pdMS_TO_TICKS(20));
        if (n > 0) {
            frame_parser_feed(&g_parser, g_rx, (size_t)n);
        }
    }
}

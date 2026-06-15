#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "tinyusb.h"
#include "tusb_cdc_acm.h"

#include "frame.h"
#include "hsm.h"

static const char *TAG = "usb_main";
static const int CDC_ITF = TINYUSB_CDC_ACM_0;

static frame_parser_t g_parser;
static uint8_t g_resp_payload[FRAME_MAX_PAYLOAD];
static uint8_t g_tx[2 + FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + 2];

static void cdc_write_all(const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        size_t queued = tinyusb_cdcacm_write_queue(CDC_ITF, data + off, len - off);
        if (queued == 0) {
            tinyusb_cdcacm_write_flush(CDC_ITF, pdMS_TO_TICKS(100));
            continue;
        }
        off += queued;
    }
    tinyusb_cdcacm_write_flush(CDC_ITF, pdMS_TO_TICKS(100));
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
    if (n) cdc_write_all(g_tx, n);
}

static uint8_t g_rx[CONFIG_TINYUSB_CDC_RX_BUFSIZE];
static void cdc_rx_cb(int itf, cdcacm_event_t *event)
{
    (void)event;
    size_t rxsize = 0;
    while (tinyusb_cdcacm_read(itf, g_rx, sizeof(g_rx), &rxsize) == ESP_OK && rxsize) {
        frame_parser_feed(&g_parser, g_rx, rxsize);
        rxsize = 0;
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32-S3 HSM starting");
    ESP_ERROR_CHECK(hsm_init() == 0 ? ESP_OK : ESP_FAIL);

    frame_parser_init(&g_parser, on_frame);

    tinyusb_config_t tusb_cfg = {
        .device_descriptor = NULL,    /* use default VID/PID + descriptors */
        .string_descriptor = NULL,
        .external_phy = false,
    };
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_config_cdcacm_t acm_cfg = {
        .usb_dev = TINYUSB_USBDEV_0,
        .cdc_port = TINYUSB_CDC_ACM_0,
        .rx_unread_buf_sz = 1024,
        .callback_rx = &cdc_rx_cb,
        .callback_rx_wanted_char = NULL,
        .callback_line_state_changed = NULL,
        .callback_line_coding_changed = NULL,
    };
    ESP_ERROR_CHECK(tusb_cdc_acm_init(&acm_cfg));

    ESP_LOGI(TAG, "USB CDC ready, waiting for host");
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

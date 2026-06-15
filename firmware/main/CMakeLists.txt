idf_component_register(
    SRCS
        "usb_main.c"
        "hsm.c"
        "frame.c"
        "crc16.c"
    INCLUDE_DIRS "."
    REQUIRES
        nvs_flash
        esp_tinyusb
        mbedtls
        bootloader_support
        monocypher
)

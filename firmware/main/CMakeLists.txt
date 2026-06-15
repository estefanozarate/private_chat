idf_component_register(
    SRCS
        "usb_main.c"
        "hsm.c"
        "frame.c"
        "crc16.c"
    INCLUDE_DIRS "."
    REQUIRES
        nvs_flash
        esp_driver_usb_serial_jtag
        mbedtls
        bootloader_support
        monocypher
)

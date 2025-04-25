idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES 
        honeypot
        nvs_flash
        esp_http_server
        esp_wifi
        esp_http_client
        spiffs
        json
) 
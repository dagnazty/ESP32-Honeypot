#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_http_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the web server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t web_server_init(void);

/**
 * @brief Start the web server in normal configuration mode
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t web_server_start(void);

/**
 * @brief Start the web server in AP configuration mode
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t web_server_start_ap_mode(void);

/**
 * @brief Stop the web server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t web_server_stop(void);

#ifdef __cplusplus
}
#endif 
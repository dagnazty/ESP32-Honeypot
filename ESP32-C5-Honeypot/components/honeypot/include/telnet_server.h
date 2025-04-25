#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the telnet server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t telnet_server_init(void);

/**
 * @brief Start the telnet server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t telnet_server_start(void);

/**
 * @brief Stop the telnet server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t telnet_server_stop(void);

/**
 * @brief Function to handle telnet client connections
 * 
 * This is run in a separate task to handle client connections
 */
void telnet_server_task(void *pvParameters);

#ifdef __cplusplus
}
#endif 
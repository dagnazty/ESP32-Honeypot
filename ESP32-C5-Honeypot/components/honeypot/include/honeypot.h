#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize and start the honeypot
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t honeypot_init(void);

/**
 * @brief Start the honeypot telnet server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t honeypot_start(void);

/**
 * @brief Stop the honeypot telnet server
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t honeypot_stop(void);

/**
 * @brief Check if honeypot is running
 * 
 * @return true if honeypot is running, false otherwise
 */
bool honeypot_is_running(void);

#ifdef __cplusplus
}
#endif 
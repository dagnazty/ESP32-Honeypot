#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_SSID "HoneypotConfig"
#define DEFAULT_PASSWORD "HoneyPotConfig123"
#define DEFAULT_AP_IP "192.168.4.1"

#define MAX_SSID_LEN 32
#define MAX_PASSWORD_LEN 64
#define MAX_WEBHOOK_LEN 256

/**
 * @brief Configuration structure
 */
typedef struct {
    char wifi_ssid[MAX_SSID_LEN];
    char wifi_password[MAX_PASSWORD_LEN];
    char webhook_url[MAX_WEBHOOK_LEN];
    bool is_configured;
} honeypot_config_t;

/**
 * @brief Initialize the configuration system
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t config_init(void);

/**
 * @brief Load configuration from file
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t config_load(void);

/**
 * @brief Save configuration to file
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t config_save(void);

/**
 * @brief Get the current configuration
 * 
 * @return Pointer to the current configuration structure
 */
honeypot_config_t *config_get(void);

/**
 * @brief Set the configuration
 * 
 * @param config New configuration
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t config_set(honeypot_config_t *config);

/**
 * @brief Check if WiFi is configured
 * 
 * @return true if configured, false otherwise
 */
bool config_is_wifi_configured(void);

#ifdef __cplusplus
}
#endif 
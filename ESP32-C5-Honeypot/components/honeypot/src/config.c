#include "config.h"
#include "file_system.h"
#include "esp_log.h"
#include "cJSON.h"
#include <string.h>

static const char *TAG = "CONFIG";
static honeypot_config_t honeypot_config;

esp_err_t config_init(void)
{
    ESP_LOGI(TAG, "Initializing configuration");
    
    // Set default values
    memset(&honeypot_config, 0, sizeof(honeypot_config_t));
    honeypot_config.is_configured = false;
    
    // Try to load configuration from file
    return config_load();
}

esp_err_t config_load(void)
{
    char buffer[512];
    int bytes_read = fs_read_file(CONFIG_FILE_PATH, buffer, sizeof(buffer));
    
    if (bytes_read <= 0) {
        ESP_LOGE(TAG, "Failed to read configuration file");
        return ESP_FAIL;
    }
    
    cJSON *root = cJSON_Parse(buffer);
    if (root == NULL) {
        ESP_LOGE(TAG, "Failed to parse configuration JSON");
        return ESP_FAIL;
    }
    
    // Extract values
    cJSON *ssid = cJSON_GetObjectItem(root, "wifi_ssid");
    cJSON *password = cJSON_GetObjectItem(root, "wifi_password");
    cJSON *webhook = cJSON_GetObjectItem(root, "webhook_url");
    cJSON *configured = cJSON_GetObjectItem(root, "is_configured");
    
    if (ssid && ssid->valuestring) {
        strncpy(honeypot_config.wifi_ssid, ssid->valuestring, MAX_SSID_LEN - 1);
    }
    
    if (password && password->valuestring) {
        strncpy(honeypot_config.wifi_password, password->valuestring, MAX_PASSWORD_LEN - 1);
    }
    
    if (webhook && webhook->valuestring) {
        strncpy(honeypot_config.webhook_url, webhook->valuestring, MAX_WEBHOOK_LEN - 1);
    }
    
    if (configured && cJSON_IsBool(configured)) {
        honeypot_config.is_configured = cJSON_IsTrue(configured);
    }
    
    cJSON_Delete(root);
    
    ESP_LOGI(TAG, "Configuration loaded: SSID=%s, Webhook=%s, Configured=%d",
             honeypot_config.wifi_ssid, 
             honeypot_config.webhook_url,
             honeypot_config.is_configured);
    
    return ESP_OK;
}

esp_err_t config_save(void)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        ESP_LOGE(TAG, "Failed to create JSON object");
        return ESP_FAIL;
    }
    
    cJSON_AddStringToObject(root, "wifi_ssid", honeypot_config.wifi_ssid);
    cJSON_AddStringToObject(root, "wifi_password", honeypot_config.wifi_password);
    cJSON_AddStringToObject(root, "webhook_url", honeypot_config.webhook_url);
    cJSON_AddBoolToObject(root, "is_configured", honeypot_config.is_configured);
    
    char *json_str = cJSON_Print(root);
    if (json_str == NULL) {
        ESP_LOGE(TAG, "Failed to print JSON to string");
        cJSON_Delete(root);
        return ESP_FAIL;
    }
    
    esp_err_t ret = fs_write_file(CONFIG_FILE_PATH, json_str, strlen(json_str));
    
    cJSON_Delete(root);
    free(json_str);
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to write configuration to file");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Configuration saved successfully");
    return ESP_OK;
}

honeypot_config_t *config_get(void)
{
    return &honeypot_config;
}

esp_err_t config_set(honeypot_config_t *config)
{
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    
    memcpy(&honeypot_config, config, sizeof(honeypot_config_t));
    
    return config_save();
}

bool config_is_wifi_configured(void)
{
    return honeypot_config.is_configured && 
           strlen(honeypot_config.wifi_ssid) > 0 && 
           strlen(honeypot_config.wifi_password) > 0;
} 
#include "file_system.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "FS";

// Default config content
static const char *DEFAULT_CONFIG_CONTENT = "{\"wifi_ssid\":\"\",\"wifi_password\":\"\",\"webhook_url\":\"\",\"is_configured\":false}";
// Default log content
static const char *DEFAULT_LOG_CONTENT = "--- ESP32-C5 Honeypot Log ---\n";

esp_err_t fs_init(void)
{
    ESP_LOGI(TAG, "Initializing SPIFFS");
    
    // Configure SPIFFS
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "storage",
        .max_files = 5,
        .format_if_mount_failed = true
    };
    
    // Mount SPIFFS
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return ret;
    }
    
    // Get partition info
    size_t total = 0, used = 0;
    ret = esp_spiffs_info(conf.partition_label, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
        return ret;
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }
    
    // Create required files if they don't exist
    ret = fs_create_file_if_missing(CONFIG_FILE_PATH, DEFAULT_CONFIG_CONTENT);
    if (ret != ESP_OK) return ret;
    
    ret = fs_create_file_if_missing(LOG_FILE_PATH, DEFAULT_LOG_CONTENT);
    if (ret != ESP_OK) return ret;
    
    ret = fs_create_file_if_missing(INDEX_HTML_PATH, DEFAULT_HTML_CONTENT);
    if (ret != ESP_OK) return ret;
    
    return ESP_OK;
}

esp_err_t fs_append_log(const char *text)
{
    FILE *f = fopen(LOG_FILE_PATH, "a");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open log file for appending");
        return ESP_FAIL;
    }
    
    fprintf(f, "%s", text);
    fclose(f);
    
    return ESP_OK;
}

int fs_read_file(const char *path, char *buffer, size_t max_len)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file %s for reading", path);
        return -1;
    }
    
    size_t bytes_read = fread(buffer, 1, max_len - 1, f);
    fclose(f);
    
    buffer[bytes_read] = '\0';
    return bytes_read;
}

esp_err_t fs_write_file(const char *path, const char *buffer, size_t len)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file %s for writing", path);
        return ESP_FAIL;
    }
    
    size_t bytes_written = fwrite(buffer, 1, len, f);
    fclose(f);
    
    if (bytes_written != len) {
        ESP_LOGE(TAG, "Failed to write to file %s", path);
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

esp_err_t fs_create_file_if_missing(const char *path, const char *default_content)
{
    // Check if file exists
    FILE *f = fopen(path, "r");
    if (f != NULL) {
        // File exists, close and return
        fclose(f);
        return ESP_OK;
    }
    
    // File doesn't exist, create it with default content
    ESP_LOGI(TAG, "Creating file %s with default content", path);
    f = fopen(path, "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to create file %s", path);
        return ESP_FAIL;
    }
    
    fprintf(f, "%s", default_content);
    fclose(f);
    
    return ESP_OK;
} 
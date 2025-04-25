#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default HTML content for the configuration interface */
extern const char *DEFAULT_HTML_CONTENT;

/** Path to the config file */
#define CONFIG_FILE_PATH "/spiffs/config.json"
/** Path to the log file */
#define LOG_FILE_PATH "/spiffs/honeypot_logs.txt"
/** Path to the index HTML file */
#define INDEX_HTML_PATH "/spiffs/index.html"

/**
 * @brief Initialize the file system (SPIFFS)
 * 
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t fs_init(void);

/**
 * @brief Append text to the log file
 * 
 * @param text Text to append
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t fs_append_log(const char *text);

/**
 * @brief Read file into buffer
 * 
 * @param path File path
 * @param buffer Buffer to store file content
 * @param max_len Maximum length of buffer
 * @return Number of bytes read, -1 on failure
 */
int fs_read_file(const char *path, char *buffer, size_t max_len);

/**
 * @brief Write buffer to file
 * 
 * @param path File path
 * @param buffer Buffer containing data to write
 * @param len Length of buffer
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t fs_write_file(const char *path, const char *buffer, size_t len);

/**
 * @brief Create a file if it doesn't exist
 * 
 * @param path File path
 * @param default_content Default content if file needs to be created
 * @return ESP_OK on success, ESP_FAIL otherwise
 */
esp_err_t fs_create_file_if_missing(const char *path, const char *default_content);

#ifdef __cplusplus
}
#endif 
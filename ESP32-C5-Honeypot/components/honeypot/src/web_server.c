#include "web_server.h"
#include "file_system.h"
#include "config.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "cJSON.h"
#include <string.h>

static const char *TAG = "WEB";
static httpd_handle_t server = NULL;

// Handler for root path (/) - serves the HTML configuration page
static esp_err_t root_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, DEFAULT_HTML_CONTENT, strlen(DEFAULT_HTML_CONTENT));
}

// Handler for getting current configuration
static esp_err_t config_get_handler(httpd_req_t *req)
{
    honeypot_config_t *config = config_get();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "ssid", config->wifi_ssid);
    cJSON_AddStringToObject(root, "webhook", config->webhook_url);
    cJSON_AddBoolToObject(root, "configured", config->is_configured);
    
    char *json_str = cJSON_Print(root);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_str, strlen(json_str));
    
    cJSON_Delete(root);
    free(json_str);
    
    return ESP_OK;
}

// Handler for saving configuration
static esp_err_t config_post_handler(httpd_req_t *req)
{
    char buf[1024];
    int ret, remaining = req->content_len;
    
    if (remaining > sizeof(buf) - 1) {
        ESP_LOGE(TAG, "Content too large");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Content too large");
        return ESP_FAIL;
    }
    
    // Read the data
    if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf) - 1))) <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    
    buf[ret] = '\0';
    
    // Parse the JSON
    cJSON *root = cJSON_Parse(buf);
    if (root == NULL) {
        ESP_LOGE(TAG, "Failed to parse JSON");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to parse JSON");
        return ESP_FAIL;
    }
    
    // Extract values
    cJSON *ssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *password = cJSON_GetObjectItem(root, "password");
    cJSON *webhook = cJSON_GetObjectItem(root, "webhook");
    
    if (!ssid || !password) {
        ESP_LOGE(TAG, "Missing required fields");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing required fields");
        cJSON_Delete(root);
        return ESP_FAIL;
    }
    
    // Update configuration
    honeypot_config_t *config = config_get();
    
    if (ssid && ssid->valuestring) {
        strncpy(config->wifi_ssid, ssid->valuestring, MAX_SSID_LEN - 1);
    }
    
    if (password && password->valuestring) {
        strncpy(config->wifi_password, password->valuestring, MAX_PASSWORD_LEN - 1);
    }
    
    if (webhook && webhook->valuestring) {
        // Convert HTTPS to HTTP for better compatibility
        if (strncmp(webhook->valuestring, "https://", 8) == 0) {
            char http_url[MAX_WEBHOOK_LEN];
            snprintf(http_url, sizeof(http_url), "http://%s", webhook->valuestring + 8);
            ESP_LOGI(TAG, "Converting webhook URL from HTTPS to HTTP: %s -> %s", 
                     webhook->valuestring, http_url);
            strncpy(config->webhook_url, http_url, MAX_WEBHOOK_LEN - 1);
        } else {
            strncpy(config->webhook_url, webhook->valuestring, MAX_WEBHOOK_LEN - 1);
        }
    }
    
    config->is_configured = true;
    
    // Save configuration
    esp_err_t err = config_save();
    cJSON_Delete(root);
    
    // Send response
    cJSON *resp = cJSON_CreateObject();
    if (err == ESP_OK) {
        cJSON_AddBoolToObject(resp, "success", true);
        cJSON_AddStringToObject(resp, "message", "Configuration saved successfully");
    } else {
        cJSON_AddBoolToObject(resp, "success", false);
        cJSON_AddStringToObject(resp, "message", "Failed to save configuration");
    }
    
    char *json_resp = cJSON_Print(resp);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_resp, strlen(json_resp));
    
    cJSON_Delete(resp);
    free(json_resp);
    
    // Schedule a restart after a short delay if config was saved successfully
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "Configuration updated, scheduling restart...");
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    }
    
    return ESP_OK;
}

// Handler for serving log file
static esp_err_t logs_handler(httpd_req_t *req)
{
    char buffer[4096];
    int bytes_read = fs_read_file(LOG_FILE_PATH, buffer, sizeof(buffer));
    
    if (bytes_read < 0) {
        ESP_LOGE(TAG, "Failed to read log file");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read log file");
        return ESP_FAIL;
    }
    
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, buffer, bytes_read);
    
    return ESP_OK;
}

// Register URI handlers
static httpd_uri_t root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_handler,
    .user_ctx = NULL
};

static httpd_uri_t config_get_uri = {
    .uri = "/api/config",
    .method = HTTP_GET,
    .handler = config_get_handler,
    .user_ctx = NULL
};

static httpd_uri_t config_post = {
    .uri = "/api/config",
    .method = HTTP_POST,
    .handler = config_post_handler,
    .user_ctx = NULL
};

static httpd_uri_t logs = {
    .uri = "/api/logs",
    .method = HTTP_GET,
    .handler = logs_handler,
    .user_ctx = NULL
};

esp_err_t web_server_init(void)
{
    ESP_LOGI(TAG, "Initializing web server");
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;
    config.max_uri_handlers = 8;
    config.max_resp_headers = 8;
    config.lru_purge_enable = true;
    
    esp_err_t ret = httpd_start(&server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Register URI handlers
    httpd_register_uri_handler(server, &root);
    httpd_register_uri_handler(server, &config_get_uri);
    httpd_register_uri_handler(server, &config_post);
    httpd_register_uri_handler(server, &logs);
    
    ESP_LOGI(TAG, "Web server initialized successfully");
    return ESP_OK;
}

esp_err_t web_server_start(void)
{
    if (server != NULL) {
        ESP_LOGW(TAG, "Web server already running");
        return ESP_OK;
    }
    
    return web_server_init();
}

esp_err_t web_server_start_ap_mode(void)
{
    // Same as normal mode for now, but could be customized for AP mode
    return web_server_start();
}

esp_err_t web_server_stop(void)
{
    if (server == NULL) {
        ESP_LOGW(TAG, "Web server not running");
        return ESP_OK;
    }
    
    esp_err_t err = httpd_stop(server);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to stop web server: %s", esp_err_to_name(err));
        return err;
    }
    
    server = NULL;
    ESP_LOGI(TAG, "Web server stopped");
    return ESP_OK;
} 
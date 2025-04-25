#include "honeypot.h"
#include "telnet_server.h"
#include "web_server.h"
#include "file_system.h"
#include "config.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include <string.h>

static const char *TAG = "HONEYPOT";
static bool honeypot_running = false;

// WiFi event handler
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            ESP_LOGI(TAG, "WiFi STA starting, connecting to AP...");
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            ESP_LOGI(TAG, "WiFi disconnected, attempting to reconnect...");
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_AP_STACONNECTED) {
            wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
            char mac_str[18];
            sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", 
                   event->mac[0], event->mac[1], event->mac[2], 
                   event->mac[3], event->mac[4], event->mac[5]);
            ESP_LOGI(TAG, "Client joined, MAC: %s", mac_str);
        } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
            wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
            char mac_str[18];
            sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", 
                   event->mac[0], event->mac[1], event->mac[2], 
                   event->mac[3], event->mac[4], event->mac[5]);
            ESP_LOGI(TAG, "Client left, MAC: %s", mac_str);
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
            ESP_LOGI(TAG, "Got IP address: " IPSTR, IP2STR(&event->ip_info.ip));
            
            // Start the honeypot services once we have an IP
            telnet_server_start();
            web_server_start();
        }
    }
}

// Initialize WiFi in STA mode to connect to configured AP
static esp_err_t wifi_init_sta(void)
{
    esp_err_t ret = ESP_OK;
    honeypot_config_t *config = config_get();
    
    wifi_config_t wifi_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false
            },
        },
    };
    
    strncpy((char *)wifi_config.sta.ssid, config->wifi_ssid, sizeof(wifi_config.sta.ssid));
    strncpy((char *)wifi_config.sta.password, config->wifi_password, sizeof(wifi_config.sta.password));
    
    ESP_LOGI(TAG, "Connecting to SSID: %s", config->wifi_ssid);
    
    ret = esp_wifi_set_mode(WIFI_MODE_STA);
    if (ret != ESP_OK) return ret;
    
    ret = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    if (ret != ESP_OK) return ret;
    
    ret = esp_wifi_start();
    if (ret != ESP_OK) return ret;
    
    ESP_LOGI(TAG, "WiFi STA mode initialized");
    return ESP_OK;
}

// Initialize WiFi in AP mode for configuration
static esp_err_t wifi_init_ap(void)
{
    esp_err_t ret = ESP_OK;
    
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = DEFAULT_SSID,
            .ssid_len = strlen(DEFAULT_SSID),
            .password = DEFAULT_PASSWORD,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    
    ESP_LOGI(TAG, "Setting up AP mode with SSID: %s", DEFAULT_SSID);
    
    ret = esp_wifi_set_mode(WIFI_MODE_AP);
    if (ret != ESP_OK) return ret;
    
    ret = esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    if (ret != ESP_OK) return ret;
    
    ret = esp_wifi_start();
    if (ret != ESP_OK) return ret;
    
    ESP_LOGI(TAG, "WiFi AP mode initialized");
    
    // Start web server in AP configuration mode
    web_server_start_ap_mode();
    
    return ESP_OK;
}

esp_err_t honeypot_init(void)
{
    esp_err_t ret;
    
    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // Initialize filesystem
    ret = fs_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize filesystem");
        return ret;
    }
    
    // Initialize configuration
    ret = config_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize configuration");
        return ret;
    }
    
    // Initialize networking components
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // Create default netif instances
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();
    
    // Initialize WiFi with default config
    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    
    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                       ESP_EVENT_ANY_ID,
                                                       &wifi_event_handler,
                                                       NULL,
                                                       NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                       IP_EVENT_STA_GOT_IP,
                                                       &wifi_event_handler,
                                                       NULL,
                                                       NULL));
    
    // Initialize server components
    telnet_server_init();
    web_server_init();
    
    // Setup WiFi based on configuration state
    if (config_is_wifi_configured()) {
        ret = wifi_init_sta();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to initialize WiFi in STA mode");
            // Fall back to AP mode if STA fails
            ret = wifi_init_ap();
        }
    } else {
        // No config found, start in AP mode
        ESP_LOGI(TAG, "No configuration found, starting in AP mode");
        ret = wifi_init_ap();
    }
    
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WiFi");
        return ret;
    }
    
    ESP_LOGI(TAG, "Honeypot initialized successfully");
    honeypot_running = true;
    return ESP_OK;
}

esp_err_t honeypot_start(void)
{
    if (honeypot_running) {
        ESP_LOGW(TAG, "Honeypot already running");
        return ESP_OK;
    }
    
    esp_err_t ret = telnet_server_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start telnet server");
        return ret;
    }
    
    honeypot_running = true;
    ESP_LOGI(TAG, "Honeypot started successfully");
    return ESP_OK;
}

esp_err_t honeypot_stop(void)
{
    if (!honeypot_running) {
        ESP_LOGW(TAG, "Honeypot not running");
        return ESP_OK;
    }
    
    esp_err_t ret = telnet_server_stop();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to stop telnet server");
        return ret;
    }
    
    honeypot_running = false;
    ESP_LOGI(TAG, "Honeypot stopped successfully");
    return ESP_OK;
}

bool honeypot_is_running(void)
{
    return honeypot_running;
} 
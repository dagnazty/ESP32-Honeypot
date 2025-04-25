#include <stdio.h>
#include "esp_system.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "honeypot.h"

static const char *TAG = "MAIN";

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32-C5 Honeypot starting up...");
    ESP_LOGI(TAG, "Initializing honeypot...");
    
    esp_err_t ret = honeypot_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize honeypot: %s", esp_err_to_name(ret));
        ESP_LOGE(TAG, "System halted due to initialization failure.");
        while (1) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
    
    ESP_LOGI(TAG, "Honeypot initialized successfully");
    ESP_LOGI(TAG, "System running normally");
    
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(60000)); // 1 minute heartbeat
        ESP_LOGI(TAG, "Honeypot heartbeat - running normally");
    }
} 
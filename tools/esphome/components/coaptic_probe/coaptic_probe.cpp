#include "coaptic_probe.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"

extern "C" uint32_t coaptic_probe_version();
extern "C" uint32_t coaptic_probe_oscore();
extern "C" int32_t coaptic_probe_run();

#if CONFIG_IDF_TARGET_ESP32C3
static constexpr const char *CHIP = "esp32c3";
#elif CONFIG_IDF_TARGET_ESP32C6
static constexpr const char *CHIP = "esp32c6";
#elif CONFIG_IDF_TARGET_ESP32S3
static constexpr const char *CHIP = "esp32s3";
#else
#error "Coaptic qualification requires ESP32-C3, ESP32-C6 or ESP32-S3"
#endif

namespace esphome::coaptic_probe {

static constexpr const char *TAG = "coaptic_probe";

void CoapticProbe::setup() {
  if (coaptic_probe_version() != 1) {
    ESP_LOGE(TAG, "COAPTIC_DEVICE_FAIL incompatible Rust ABI");
    mark_failed();
    return;
  }
  started_ = millis();
  if (xTaskCreate(run_probe_, "coaptic_probe", STACK_BYTES, this, 1, &task_) != pdPASS) {
    ESP_LOGE(TAG, "COAPTIC_DEVICE_FAIL task stack allocation refused");
    task_ = nullptr;
    mark_failed();
  }
}

void CoapticProbe::run_probe_(void *argument) {
  auto *self = static_cast<CoapticProbe *>(argument);
  const int32_t result = coaptic_probe_run();
  const uint32_t free_bytes = uxTaskGetStackHighWaterMark(nullptr);
  self->high_water_ = free_bytes < STACK_BYTES ? STACK_BYTES - free_bytes : 0;
  self->completed_ = millis();
  self->result_.store(result == 0 ? 1 : 2, std::memory_order_release);
  for (;;) {
    vTaskDelay(portMAX_DELAY);
  }
}

void CoapticProbe::loop() {
  if (task_ == nullptr)
    return;
  const uint32_t result = result_.load(std::memory_order_acquire);
  if (result == 0) {
    if (millis() - started_ >= DEADLINE_MS) {
      on_shutdown();
      ESP_LOGE(TAG, "COAPTIC_DEVICE_FAIL probe deadline exceeded");
      mark_failed();
    }
    return;
  }
  on_shutdown();
  const bool passed = result == 1 && completed_ - started_ < DEADLINE_MS &&
                      high_water_ > 0 && high_water_ < STACK_BYTES;
  ESP_LOGI(TAG,
           "COAPTIC_DEVICE {\"schema\":\"coaptic-device/1\",\"chip\":\"%s\",\"run_id\":\"%s\","
           "\"passed\":%s,\"oscore\":%s,\"stack_high_water_bytes\":%lu,\"stack_capacity_bytes\":%lu,"
           "\"runtime\":\"esphome\",\"stack_scope\":\"freertos_probe_task\"}",
           CHIP, run_id_.c_str(), passed ? "true" : "false", coaptic_probe_oscore() ? "true" : "false",
           static_cast<unsigned long>(high_water_), static_cast<unsigned long>(STACK_BYTES));
  if (!passed)
    mark_failed();
}

void CoapticProbe::on_shutdown() {
  if (task_ != nullptr) {
    vTaskDelete(task_);
    task_ = nullptr;
  }
}

}

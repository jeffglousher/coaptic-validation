#pragma once

#include "esphome/core/component.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <atomic>
#include <cstdint>
#include <string>

namespace esphome::coaptic_probe {

class CoapticProbe : public Component {
 public:
  void set_run_id(const std::string &value) { run_id_ = value; }
  void setup() override;
  void loop() override;
  void on_shutdown() override;
  float get_setup_priority() const override { return setup_priority::LATE; }

 protected:
  static void run_probe_(void *argument);
  static constexpr uint32_t STACK_BYTES = 98304;
  static constexpr uint32_t DEADLINE_MS = 30000;
  TaskHandle_t task_{nullptr};
  std::atomic<uint32_t> result_{0};
  uint32_t high_water_{0};
  uint32_t started_{0};
  uint32_t completed_{0};
  std::string run_id_;
};

}

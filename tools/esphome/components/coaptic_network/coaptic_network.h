#pragma once

#include "esphome/core/component.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <atomic>
#include <cstdint>
#include <string>
#include "nvs.h"

namespace esphome::coaptic_network {

class CoapticNetwork : public Component {
 public:
  void set_run_id(const std::string &value) { run_id_ = value; }
  void set_port(uint16_t value) { port_ = value; }
  void set_oscore(const std::string &secret, const std::string &salt, const std::string &context,
                  uint8_t sender, uint8_t recipient, bool provision) {
    secret_ = secret; salt_ = salt; context_ = context;
    sender_ = sender; recipient_ = recipient; security_mode_ = provision ? 2 : 1;
  }
  uint32_t security_mode() const { return security_mode_; }
  bool security_config(uint8_t *bytes, uint32_t length);
  int32_t read_security(uint8_t *bytes, uint32_t length);
  bool commit_security(const uint8_t *bytes, uint32_t length);
  void loop() override;
  void on_shutdown() override;
  float get_setup_priority() const override { return setup_priority::LATE; }
  int32_t receive(uint8_t *bytes, uint32_t capacity, uint64_t *peer);
  int32_t send(const uint8_t *bytes, uint32_t length, uint64_t peer);
  uint64_t clock();

 protected:
  static void run_(void *argument);
  static constexpr uint32_t STACK_BYTES = 98304;
  TaskHandle_t task_{nullptr};
  int socket_{-1};
  uint16_t port_{5683};
  std::atomic<bool> stop_{false};
  std::atomic<uint32_t> result_{0};
  std::atomic<uint32_t> rx_{0}, tx_{0}, dropped_{0}, high_water_{0};
  std::atomic<uint32_t> polls_{0}, idle_waits_{0}, scheduler_yields_{0}, wait_errors_{0};
  uint64_t stack_checked_us_{0};
  uint32_t ready_burst_{0};
  uint32_t logged_{0};
  bool started_{false};
  std::string run_id_;
  std::string secret_, salt_, context_;
  uint8_t sender_{1}, recipient_{2};
  uint32_t security_mode_{0};
  nvs_handle_t security_handle_{0};
};

}

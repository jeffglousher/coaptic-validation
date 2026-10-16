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
  void set_pairing() { security_mode_ = 5; }
  int32_t read_pairing(uint8_t *bytes, uint32_t capacity);
  bool commit_pairing(const uint8_t *bytes, uint32_t length);
  bool security_config(uint8_t *bytes, uint32_t length);
  int32_t read_security(uint8_t *bytes, uint32_t length);
  bool commit_security(const uint8_t *bytes, uint32_t length);
  void set_telemetry(const std::string &principal, uint8_t kid, const std::string &resource,
                     uint32_t address, uint16_t port, uint32_t timeout,
                     const std::string &operation, int32_t format, const std::string &payload) {
    principal_ = principal; principal_kid_ = kid; resource_ = resource;
    peer_address_ = address; peer_port_ = port; telemetry_timeout_ = timeout;
    operation_ = operation; format_ = format; payload_ = payload;
    security_mode_ = operation.empty() ? 3 : 4;
  }
  int32_t telemetry_config(uint8_t *bytes, uint32_t capacity);
  int32_t read_pending(uint8_t *bytes, uint32_t length);
  bool commit_pending(const uint8_t *bytes, uint32_t length);
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
  nvs_handle_t pairing_handle_{0};
  std::string principal_, resource_, operation_, payload_;
  uint8_t principal_kid_{0};
  uint32_t peer_address_{0}, telemetry_timeout_{0};
  uint16_t peer_port_{0};
  int32_t format_{-1};
#ifdef COAPTIC_TIMING_TRACE
  // Diagnostic only: one bounded capture after boot. No packet contents or keys.
  static constexpr uint32_t TRACE_EVENTS = 512;
  struct TraceEvent {
    uint64_t at_us, duration_us;
    uint32_t bytes, mid;
    uint8_t kind;
    int8_t result;
  };
  TraceEvent trace_[TRACE_EVENTS]{};
  std::atomic<uint32_t> trace_count_{0};
  std::atomic<bool> trace_frozen_{false}, trace_overflow_{false};
  std::atomic<uint32_t> trace_last_ms_{0};
  uint64_t trace_poll_start_us_{0};
  void trace_event_(uint8_t kind, uint64_t start, uint64_t duration, uint32_t bytes, uint32_t mid, int8_t result);
  void trace_dump_();
#endif
};

}

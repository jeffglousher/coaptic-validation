#pragma once

#include "esphome/core/component.h"
#include <cstdint>
#include <cstring>

namespace esphome::libcoap_benchmark {

// One finite client task. ESPHome continues to own WiFi/API/OTA and NVS.
class LibcoapBenchmark : public Component {
public:
  void set_run_id(const char *value) { std::memcpy(run_id_, value, 32); }
  void set_server_run_id(const char *value) {
    std::memcpy(server_run_id_, value, 32);
  }
  void set_peer_address(uint32_t value) { peer_address_ = value; }
  void set_peer_port(uint16_t value) { peer_port_ = value; }
  void set_start_delay_ms(uint32_t value) { start_delay_ms_ = value; }
  void setup() override;
  void loop() override;

protected:
  static void task_(void *argument);
  void run_();
  char run_id_[33]{};
  char server_run_id_[33]{};
  uint32_t peer_address_{};
  uint16_t peer_port_{5683};
  uint32_t start_delay_ms_{30000};
  int64_t setup_us_{};
  bool launched_{};
};

} // namespace esphome::libcoap_benchmark

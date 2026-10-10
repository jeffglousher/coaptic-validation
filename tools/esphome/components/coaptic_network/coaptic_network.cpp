#include "coaptic_network.h"
#include "esphome/components/network/util.h"
#include "esphome/components/wifi/wifi_component.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

extern "C" int32_t coaptic_network_run(void *context, const uint8_t *id);

namespace esphome::coaptic_network {

static constexpr const char *TAG = "coaptic_network";

void CoapticNetwork::loop() {
  if (!started_) {
    if (!network::is_connected() && !wifi::global_wifi_component->is_ap_active())
      return;
    started_ = true;
    if (security_mode_ != 2) {
    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port_);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (socket_ < 0 || fcntl(socket_, F_SETFL, O_NONBLOCK) < 0 ||
        bind(socket_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
      if (socket_ >= 0)
        close(socket_);
      socket_ = -1;
      ESP_LOGE(TAG, "COAPTIC_NETWORK_FAIL socket setup errno=%d", errno);
      mark_failed();
      return;
    }
    }
    if (xTaskCreate(run_, "coaptic_udp", STACK_BYTES, this, 1, &task_) != pdPASS) {
      close(socket_);
      socket_ = -1;
      task_ = nullptr;
      ESP_LOGE(TAG, "COAPTIC_NETWORK_FAIL task allocation");
      mark_failed();
      return;
    }
    if (security_mode_ == 2)
      ESP_LOGI(TAG, "COAPTIC_SECURITY_PROVISION_START run_id=%s", run_id_.c_str());
    else
      ESP_LOGI(TAG, "COAPTIC_NETWORK_READY run_id=%s port=%u mode=%lu", run_id_.c_str(), port_, static_cast<unsigned long>(security_mode_));
  }
  if (task_ == nullptr)
    return;
  if (result_.load(std::memory_order_acquire) != 0) {
    vTaskDelete(task_);
    task_ = nullptr;
    if (security_mode_ == 2 && result_.load() == 1) {
      ESP_LOGI(TAG, "COAPTIC_SECURITY_PROVISIONED run_id=%s; no network service", run_id_.c_str());
    } else {
      ESP_LOGE(TAG, "COAPTIC_NETWORK_STOPPED result=%lu", static_cast<unsigned long>(result_.load()));
      mark_failed();
    }
    return;
  }
  if (millis() - logged_ >= 5000) {
    logged_ = millis();
    ESP_LOGI(TAG,
             "COAPTIC_NETWORK {\"run_id\":\"%s\",\"rx\":%lu,\"tx\":%lu,\"dropped\":%lu,"
             "\"stack_high_water_bytes\":%lu,\"stack_capacity_bytes\":%lu,"
             "\"polls\":%lu,\"idle_waits\":%lu,\"scheduler_yields\":%lu,\"wait_errors\":%lu}",
             run_id_.c_str(), static_cast<unsigned long>(rx_.load()), static_cast<unsigned long>(tx_.load()),
             static_cast<unsigned long>(dropped_.load()), static_cast<unsigned long>(high_water_.load()),
             static_cast<unsigned long>(STACK_BYTES), static_cast<unsigned long>(polls_.load()),
             static_cast<unsigned long>(idle_waits_.load()), static_cast<unsigned long>(scheduler_yields_.load()),
             static_cast<unsigned long>(wait_errors_.load()));
  }
}

void CoapticNetwork::run_(void *argument) {
  auto *self = static_cast<CoapticNetwork *>(argument);
  int32_t result = coaptic_network_run(self, reinterpret_cast<const uint8_t *>(self->run_id_.data()));
  if (self->socket_ >= 0) close(self->socket_);
  self->socket_ = -1;
  if (self->security_handle_ != 0) {
    nvs_close(self->security_handle_);
    self->security_handle_ = 0;
  }
  self->result_.store(result == 0 ? 1 : static_cast<uint32_t>(-result) + 1, std::memory_order_release);
  for (;;) {
    vTaskDelay(portMAX_DELAY);
  }
}

int32_t CoapticNetwork::receive(uint8_t *bytes, uint32_t capacity, uint64_t *peer) {
  uint8_t packet[2048];
  sockaddr_in address{};
  socklen_t size = sizeof(address);
  int length = recvfrom(socket_, packet, sizeof(packet), 0, reinterpret_cast<sockaddr *>(&address), &size);
  if (length < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? -1 : -2;
  rx_.store(rx_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
  if (length >= sizeof(packet) || static_cast<uint32_t>(length) > capacity ||
      size != sizeof(address) || address.sin_family != AF_INET) {
    dropped_.store(dropped_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
    return -1;
  }
  std::memcpy(bytes, packet, length);
  *peer = (static_cast<uint64_t>(ntohl(address.sin_addr.s_addr)) << 16) | ntohs(address.sin_port);
  return length;
}

int32_t CoapticNetwork::send(const uint8_t *bytes, uint32_t length, uint64_t peer) {
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(static_cast<uint32_t>(peer >> 16));
  address.sin_port = htons(static_cast<uint16_t>(peer));
  int sent = sendto(socket_, bytes, length, 0, reinterpret_cast<sockaddr *>(&address), sizeof(address));
  if (sent == static_cast<int>(length))
    tx_.store(tx_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
  return sent;
}

uint64_t CoapticNetwork::clock() {
  if (stop_.load(std::memory_order_acquire))
    return UINT64_MAX;
  if (ready_burst_ >= 32) {
    vTaskDelay(1);
    scheduler_yields_.fetch_add(1, std::memory_order_relaxed);
    ready_burst_ = 0;
  }
  fd_set read_set;
  FD_ZERO(&read_set);
  FD_SET(socket_, &read_set);
  timeval timeout{0, 10000};
  const int ready = select(socket_ + 1, &read_set, nullptr, nullptr, &timeout);
  const uint64_t now_us = static_cast<uint64_t>(esp_timer_get_time());
  if (ready > 0) {
    ready_burst_++;
  } else {
    ready_burst_ = 0;
    if (ready == 0) {
      idle_waits_.fetch_add(1, std::memory_order_relaxed);
    } else {
      wait_errors_.fetch_add(1, std::memory_order_relaxed);
      vTaskDelay(1);
    }
  }
  if (stack_checked_us_ == 0 || now_us - stack_checked_us_ >= 1000000) {
    const uint32_t free_bytes = uxTaskGetStackHighWaterMark(nullptr);
    high_water_.store(free_bytes < STACK_BYTES ? STACK_BYTES - free_bytes : 0, std::memory_order_relaxed);
    stack_checked_us_ = now_us;
  }
  polls_.fetch_add(1, std::memory_order_relaxed);
  return stop_.load(std::memory_order_acquire) ? UINT64_MAX : static_cast<uint64_t>(esp_timer_get_time() / 1000);
}

bool CoapticNetwork::security_config(uint8_t *bytes, uint32_t length) {
  if (bytes == nullptr || length != 66 || secret_.size() != 64 || salt_.size() != 32 || context_.size() != 32)
    return false;
  uint32_t offset = 0;
  for (const auto *text : {&secret_, &salt_, &context_}) {
    for (size_t i = 0; i < text->size(); i += 2) {
      auto nibble = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
      const int high = nibble((*text)[i]), low = nibble((*text)[i + 1]);
      if (high < 0 || low < 0) return false;
      bytes[offset++] = static_cast<uint8_t>((high << 4) | low);
    }
  }
  bytes[64] = sender_; bytes[65] = recipient_;
  return sender_ != recipient_;
}

int32_t CoapticNetwork::read_security(uint8_t *bytes, uint32_t length) {
  if (bytes == nullptr || length != 100) return -1;
  if (security_handle_ == 0 && nvs_open("coaptic_sec", NVS_READWRITE, &security_handle_) != ESP_OK) return -1;
  size_t stored = 0;
  const esp_err_t status = nvs_get_blob(security_handle_, "state_v1", nullptr, &stored);
  if (status == ESP_ERR_NVS_NOT_FOUND) return 0;
  if (status != ESP_OK || stored != length) return -1;
  return nvs_get_blob(security_handle_, "state_v1", bytes, &stored) == ESP_OK && stored == length ? 1 : -1;
}

bool CoapticNetwork::commit_security(const uint8_t *bytes, uint32_t length) {
  if (bytes == nullptr || length != 100 || security_handle_ == 0) return false;
  return nvs_set_blob(security_handle_, "state_v1", bytes, length) == ESP_OK && nvs_commit(security_handle_) == ESP_OK;
}

void CoapticNetwork::on_shutdown() {
  stop_.store(true, std::memory_order_release);
  for (uint32_t waited = 0; task_ != nullptr && waited < 1000; waited += 10) {
    if (result_.load(std::memory_order_acquire) != 0) {
      vTaskDelete(task_);
      task_ = nullptr;
      break;
    }
    delay(10);
  }
}

}

extern "C" int32_t coaptic_socket_recv(void *context, uint8_t *bytes, uint32_t capacity, uint64_t *peer) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->receive(bytes, capacity, peer);
}
extern "C" int32_t coaptic_socket_send(void *context, const uint8_t *bytes, uint32_t length, uint64_t peer) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->send(bytes, length, peer);
}
extern "C" uint64_t coaptic_socket_clock(void *context) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->clock();
}
extern "C" bool coaptic_socket_random(uint8_t *bytes, uint32_t length) {
  esp_fill_random(bytes, length);
  return true;
}

static portMUX_TYPE COAPTIC_MUX = portMUX_INITIALIZER_UNLOCKED;
extern "C" void coaptic_enter_critical() {
  portENTER_CRITICAL(&COAPTIC_MUX);
}
extern "C" void coaptic_leave_critical() {
  portEXIT_CRITICAL(&COAPTIC_MUX);
}

extern "C" uint32_t coaptic_security_mode(void *context) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->security_mode();
}
extern "C" bool coaptic_security_config(void *context, uint8_t *bytes, uint32_t length) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->security_config(bytes, length);
}
extern "C" int32_t coaptic_security_read(void *context, uint8_t *bytes, uint32_t length) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->read_security(bytes, length);
}
extern "C" bool coaptic_security_commit(void *context, const uint8_t *bytes, uint32_t length) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->commit_security(bytes, length);
}

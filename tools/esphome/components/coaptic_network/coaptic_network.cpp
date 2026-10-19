#include "coaptic_network.h"
#include "esphome/components/network/util.h"
#include "esphome/components/wifi/wifi_component.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include "esp_random.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_vfs_eventfd.h"
#ifdef COAPTIC_PAIRING
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_select.h"
#include "esp_system.h"
#endif
#include "lwip/sockets.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

extern "C" int32_t coaptic_network_run(void *context, const uint8_t *id);

namespace esphome::coaptic_network {

static constexpr const char *TAG = "coaptic_network";

// One SDK snapshot on the calling stack; no retained buffer or task registry.
// Region low-watermarks may occur at different times: never label their sum a
// measured simultaneous whole-device peak. Task stacks are heap allocations,
// so their reserved bytes must not also be added to heap allocation totals.
static void log_resources(const char *run_id, const char *phase, uint32_t task_stack_bytes) {
  multi_heap_info_t info{};
  heap_caps_get_info(&info, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  ESP_LOGI(TAG, "COAPTIC_RESOURCES {\"run_id\":\"%s\",\"phase\":\"%s\","
           "\"caps\":\"internal_8bit\",\"allocated_bytes\":%lu,\"free_bytes\":%lu,"
           "\"region_min_free_sum_bytes\":%lu,\"largest_free_block_bytes\":%lu,"
           "\"coaptic_task_stack_reserved_bytes\":%lu,\"sdk_snapshot_bytes\":%u}",
           run_id, phase, static_cast<unsigned long>(info.total_allocated_bytes),
           static_cast<unsigned long>(info.total_free_bytes),
           static_cast<unsigned long>(info.minimum_free_bytes),
           static_cast<unsigned long>(info.largest_free_block),
           static_cast<unsigned long>(task_stack_bytes), static_cast<unsigned>(sizeof(info)));
}

// One process-lifetime descriptor, allocated only when the optional Rust driver
// is claimed. Wakers contain no component pointer. Never close/reuse this fd:
// retained external wakers must remain safe after a driver exits.
static std::atomic<int> async_event_fd{-1};

#ifdef COAPTIC_TIMING_TRACE
void CoapticNetwork::trace_event_(uint8_t kind, uint64_t start, uint64_t duration,
                                  uint32_t bytes, uint32_t mid, int8_t result) {
  if (trace_frozen_.load(std::memory_order_acquire)) return;
  const uint32_t index = trace_count_.load(std::memory_order_relaxed);
  if (index >= TRACE_EVENTS) {
    trace_overflow_.store(true, std::memory_order_release);
    return;
  }
  trace_[index] = {start, duration, bytes, mid, kind, result};
  trace_last_ms_.store(static_cast<uint32_t>((start + duration) / 1000), std::memory_order_release);
  trace_count_.store(index + 1, std::memory_order_release);
}

void CoapticNetwork::trace_dump_() {
  if (trace_frozen_.load(std::memory_order_acquire) || rx_.load() == 0) return;
  const uint32_t last = trace_last_ms_.load(std::memory_order_acquire);
  const uint32_t now = static_cast<uint32_t>(esp_timer_get_time() / 1000);
  if (now - last < 2000) return;
  // Freeze after a quiet interval. The worker publishes each completed entry
  // with release ordering; the snapshot includes only published immutable rows.
  trace_frozen_.store(true, std::memory_order_release);
  const uint32_t count = trace_count_.load(std::memory_order_acquire);
  for (uint32_t i = 0; i < count; ++i) {
    const auto &row = trace_[i];
    ESP_LOGI(TAG, "COAPTIC_TIMING {\"run_id\":\"%s\",\"index\":%lu,\"kind\":%u,\"at_us\":%llu,\"duration_us\":%llu,\"bytes\":%lu,\"mid\":%lu,\"result\":%d}",
             run_id_.c_str(), static_cast<unsigned long>(i), row.kind,
             static_cast<unsigned long long>(row.at_us), static_cast<unsigned long long>(row.duration_us),
             static_cast<unsigned long>(row.bytes), static_cast<unsigned long>(row.mid), row.result);
  }
  ESP_LOGI(TAG, "COAPTIC_TIMING_END {\"run_id\":\"%s\",\"events\":%lu,\"overflow\":%s,\"trace_bytes\":%u}",
           run_id_.c_str(), static_cast<unsigned long>(count), trace_overflow_.load() ? "true" : "false",
           static_cast<unsigned>(sizeof(trace_)));
}
#endif

void CoapticNetwork::loop() {
  if (!started_) {
    if (security_mode_ != 5 && !network::is_connected() && !wifi::global_wifi_component->is_ap_active())
      return;
    started_ = true;
    log_resources(run_id_.c_str(), "before_platform_setup", 0);
#ifdef COAPTIC_PAIRING
    if (security_mode_ == 5 && !usb_serial_jtag_is_driver_installed()) {
      usb_serial_jtag_driver_config_t usb_config{};
      usb_config.rx_buffer_size = 1024;
      usb_config.tx_buffer_size = 1024;
      if (usb_serial_jtag_driver_install(&usb_config) != ESP_OK) {
        ESP_LOGE(TAG, "COAPTIC_PAIRING_FAIL USB setup");
        mark_failed();
        return;
      }
    }
#endif
    if (security_mode_ != 2 && security_mode_ != 4) {
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
      log_resources(run_id_.c_str(), "task_allocation_refused", 0);
      close(socket_);
      socket_ = -1;
      task_ = nullptr;
      ESP_LOGE(TAG, "COAPTIC_NETWORK_FAIL task allocation");
      mark_failed();
      return;
    }
    log_resources(run_id_.c_str(), "task_started", STACK_BYTES);
    if (security_mode_ == 4)
      ESP_LOGI(TAG, "COAPTIC_PENDING_PROVISION_START run_id=%s", run_id_.c_str());
    else if (security_mode_ == 2)
      ESP_LOGI(TAG, "COAPTIC_SECURITY_PROVISION_START run_id=%s", run_id_.c_str());
    else
      ESP_LOGI(TAG, "COAPTIC_NETWORK_READY run_id=%s port=%u mode=%lu", run_id_.c_str(), port_, static_cast<unsigned long>(security_mode_));
  }
  if (task_ == nullptr)
    return;
#ifdef COAPTIC_TIMING_TRACE
  trace_dump_();
#endif
  if (result_.load(std::memory_order_acquire) != 0) {
    log_resources(run_id_.c_str(), "worker_stopped", STACK_BYTES);
    ESP_LOGI(TAG, "COAPTIC_STACK_FINAL {\"run_id\":\"%s\",\"used_high_water_bytes\":%lu,\"capacity_bytes\":%lu}",
             run_id_.c_str(), static_cast<unsigned long>(high_water_.load()),
             static_cast<unsigned long>(STACK_BYTES));
    vTaskDelete(task_);
    task_ = nullptr;
    if (security_mode_ == 2 && result_.load() == 1) {
      ESP_LOGI(TAG, "COAPTIC_SECURITY_PROVISIONED run_id=%s; no network service", run_id_.c_str());
    } else if (security_mode_ == 4 && result_.load() == 1) {
      ESP_LOGI(TAG, "COAPTIC_PENDING_PROVISIONED run_id=%s; no network service", run_id_.c_str());
    } else if (security_mode_ == 3 && result_.load() == 1) {
      ESP_LOGI(TAG, "COAPTIC_TELEMETRY_COMPLETE run_id=%s", run_id_.c_str());
    } else {
      ESP_LOGE(TAG, "COAPTIC_NETWORK_STOPPED result=%lu", static_cast<unsigned long>(result_.load()));
      mark_failed();
    }
    return;
  }
  if (millis() - logged_ >= 5000) {
    logged_ = millis();
    log_resources(run_id_.c_str(), "running", STACK_BYTES);
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
  if (self->pairing_handle_ != 0) {
    nvs_close(self->pairing_handle_);
    self->pairing_handle_ = 0;
  }
  // Capture startup/terminal work even when the worker did not reach its next wait.
  const uint32_t free_bytes = uxTaskGetStackHighWaterMark(nullptr);
  self->high_water_.store(free_bytes < STACK_BYTES ? STACK_BYTES - free_bytes : 0,
                          std::memory_order_relaxed);
  self->result_.store(result == 0 ? 1 : static_cast<uint32_t>(-result) + 1, std::memory_order_release);
  for (;;) {
    vTaskDelay(portMAX_DELAY);
  }
}

void CoapticNetwork::admission_diagnostics(uint64_t at_ms, uint32_t token_refused,
                                          uint32_t rx_refused, uint32_t tx_refused,
                                          uint32_t refusal_sent, uint32_t refusal_unsent,
                                          uint32_t hard_rx, uint32_t hard_tx,
                                          uint32_t rx_accepted, uint32_t progress) const {
  ESP_LOGI(TAG, "COAPTIC_ADMISSION {\"run_id\":\"%s\",\"at_ms\":%llu,"
           "\"scope\":\"retained_app\",\"token_refused\":%lu,\"rx_refused\":%lu,"
           "\"tx_refused\":%lu,\"refusal_sent\":%lu,\"refusal_unsent\":%lu,"
           "\"hard_rx\":%lu,\"hard_tx\":%lu,\"rx_accepted\":%lu,\"progress\":%lu}",
           run_id_.c_str(), static_cast<unsigned long long>(at_ms),
           static_cast<unsigned long>(token_refused), static_cast<unsigned long>(rx_refused),
           static_cast<unsigned long>(tx_refused), static_cast<unsigned long>(refusal_sent),
           static_cast<unsigned long>(refusal_unsent), static_cast<unsigned long>(hard_rx),
           static_cast<unsigned long>(hard_tx), static_cast<unsigned long>(rx_accepted),
           static_cast<unsigned long>(progress));
}

int32_t CoapticNetwork::receive(uint8_t *bytes, uint32_t capacity, uint64_t *peer) {
#ifdef COAPTIC_TIMING_TRACE
  const uint64_t trace_start = static_cast<uint64_t>(esp_timer_get_time());
#endif
  // lwIP recvmsg reports MSG_TRUNC and the original UDP datagram length.
  // Receive directly into the borrowed Coaptic slot; no packet-sized staging.
  sockaddr_in address{};
  iovec vector{bytes, capacity};
  msghdr message{};
  message.msg_name = &address;
  message.msg_namelen = sizeof(address);
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  int length = recvmsg(socket_, &message, 0);
  if (length < 0)
    return errno == EAGAIN || errno == EWOULDBLOCK ? -1 : -2;
  rx_.store(rx_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
  if ((message.msg_flags & MSG_TRUNC) != 0 || static_cast<uint32_t>(length) > capacity ||
      message.msg_namelen != sizeof(address) || address.sin_family != AF_INET) {
    dropped_.store(dropped_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
    return -1;
  }
  *peer = (static_cast<uint64_t>(ntohl(address.sin_addr.s_addr)) << 16) | ntohs(address.sin_port);
#ifdef COAPTIC_TIMING_TRACE
  trace_event_(1, trace_start, static_cast<uint64_t>(esp_timer_get_time()) - trace_start,
               length, length >= 4 ? (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3] : 65536, 1);
#endif
  return length;
}

int32_t CoapticNetwork::send(const uint8_t *bytes, uint32_t length, uint64_t peer) {
#ifdef COAPTIC_TIMING_TRACE
  const uint64_t trace_start = static_cast<uint64_t>(esp_timer_get_time());
#endif
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(static_cast<uint32_t>(peer >> 16));
  address.sin_port = htons(static_cast<uint16_t>(peer));
  int sent = sendto(socket_, bytes, length, 0, reinterpret_cast<sockaddr *>(&address), sizeof(address));
  const bool would_block = sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
  if (sent == static_cast<int>(length))
    tx_.store(tx_.load(std::memory_order_relaxed) + 1, std::memory_order_relaxed);
#ifdef COAPTIC_TIMING_TRACE
  trace_event_(2, trace_start, static_cast<uint64_t>(esp_timer_get_time()) - trace_start,
               length, length >= 4 ? (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3] : 65536,
               sent == static_cast<int>(length) ? 1 : -1);
#endif
  return would_block ? -3 : sent;
}

uint64_t CoapticNetwork::async_now() const {
  return stop_.load(std::memory_order_acquire) ? UINT64_MAX : static_cast<uint64_t>(esp_timer_get_time() / 1000);
}

int32_t CoapticNetwork::async_wait(uint32_t interests, uint64_t deadline) {
  const uint64_t now = async_now();
  if (now == UINT64_MAX) return -2;
  const int event = async_event_fd.load(std::memory_order_acquire);
  if (event < 0 || socket_ < 0 || event >= FD_SETSIZE || socket_ >= FD_SETSIZE) return -1;
  fd_set reads, writes;
  FD_ZERO(&reads);
  FD_ZERO(&writes);
  FD_SET(event, &reads);
  if ((interests & 1) != 0) FD_SET(socket_, &reads);
  if ((interests & 2) != 0) FD_SET(socket_, &writes);
  if ((interests & 4) != 0) {
#if defined(COAPTIC_PAIRING) && defined(CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG)
    // Borrow the configured console descriptor only for readiness. Actual
    // reads remain the existing sole-owner raw USB driver calls.
    FD_SET(STDIN_FILENO, &reads);
#else
    return -1;
#endif
  }
  timeval timeout{};
  timeval *timeout_ptr = nullptr;
  if (deadline != UINT64_MAX) {
    const uint64_t remaining = deadline > now ? deadline - now : 0;
    // timeval's seconds may be 32 bit. Cap a long deadline without wrapping;
    // the Rust timer rechecks the absolute clock before reporting completion.
    timeout.tv_sec = static_cast<long>(remaining / 1000 > INT32_MAX ? INT32_MAX : remaining / 1000);
    timeout.tv_usec = static_cast<long>((remaining % 1000) * 1000);
    timeout_ptr = &timeout;
  }
  const int maximum = event > socket_ ? event : socket_;
  const int ready = select(maximum + 1, &reads, &writes, nullptr, timeout_ptr);
  if (ready < 0) return errno == EINTR ? 0 : -1;
  const uint64_t now_us = static_cast<uint64_t>(esp_timer_get_time());
  if (stack_checked_us_ == 0 || now_us - stack_checked_us_ >= 1000000) {
    const uint32_t free_bytes = uxTaskGetStackHighWaterMark(nullptr);
    high_water_.store(free_bytes < STACK_BYTES ? STACK_BYTES - free_bytes : 0, std::memory_order_relaxed);
    stack_checked_us_ = now_us;
  }
  polls_.fetch_add(1, std::memory_order_relaxed);
  if (ready == 0) idle_waits_.fetch_add(1, std::memory_order_relaxed);
  if (FD_ISSET(event, &reads)) {
    uint64_t count;
    if (read(event, &count, sizeof(count)) != sizeof(count)) return -1;
  }
  if (stop_.load(std::memory_order_acquire)) return -2;
  int32_t result = 0;
  if (FD_ISSET(socket_, &reads)) result |= 1;
  if (FD_ISSET(socket_, &writes)) result |= 2;
  if ((interests & 4) != 0 && FD_ISSET(STDIN_FILENO, &reads)) result |= 8;
  if (deadline != UINT64_MAX && async_now() >= deadline) result |= 4;
  return result;
}

uint64_t CoapticNetwork::clock() {
#ifdef COAPTIC_TIMING_TRACE
  const uint64_t trace_clock_start = static_cast<uint64_t>(esp_timer_get_time());
  if (trace_poll_start_us_ != 0) {
    trace_event_(6, trace_poll_start_us_, trace_clock_start - trace_poll_start_us_, 0, 65536, 1);
    trace_poll_start_us_ = 0;
  }
#endif
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
#ifdef COAPTIC_TIMING_TRACE
  if (ready > 0) trace_event_(5, trace_clock_start, now_us - trace_clock_start, 0, 65536, 1);
#endif
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
#ifdef COAPTIC_TIMING_TRACE
  if (ready > 0) trace_poll_start_us_ = static_cast<uint64_t>(esp_timer_get_time());
#endif
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
#ifdef COAPTIC_TIMING_TRACE
  const uint64_t trace_start = static_cast<uint64_t>(esp_timer_get_time());
  const auto read = [&]() -> int32_t {
#endif
  if (bytes == nullptr || length != 100) return -1;
  if (security_handle_ == 0 && nvs_open("coaptic_sec", NVS_READWRITE, &security_handle_) != ESP_OK) return -1;
  size_t stored = 0;
  const esp_err_t status = nvs_get_blob(security_handle_, "state_v1", nullptr, &stored);
  if (status == ESP_ERR_NVS_NOT_FOUND) return 0;
  if (status != ESP_OK || stored != length) return -1;
  return nvs_get_blob(security_handle_, "state_v1", bytes, &stored) == ESP_OK && stored == length ? 1 : -1;
#ifdef COAPTIC_TIMING_TRACE
  };
  const int32_t result = read();
  trace_event_(3, trace_start, static_cast<uint64_t>(esp_timer_get_time()) - trace_start, length, 65536, result);
  return result;
#endif
}

bool CoapticNetwork::commit_security(const uint8_t *bytes, uint32_t length) {
#ifdef COAPTIC_TIMING_TRACE
  const uint64_t trace_start = static_cast<uint64_t>(esp_timer_get_time());
  const auto commit = [&]() -> bool {
#endif
  if (bytes == nullptr || length != 100 || security_handle_ == 0) return false;
  return nvs_set_blob(security_handle_, "state_v1", bytes, length) == ESP_OK && nvs_commit(security_handle_) == ESP_OK;
#ifdef COAPTIC_TIMING_TRACE
  };
  const bool result = commit();
  trace_event_(4, trace_start, static_cast<uint64_t>(esp_timer_get_time()) - trace_start, length, 65536, result ? 1 : -1);
  return result;
#endif
}

int32_t CoapticNetwork::telemetry_config(uint8_t *bytes, uint32_t capacity) {
  const bool provision = security_mode_ == 4;
  const size_t payload_bytes = payload_.size() / 2;
  const size_t length = provision ? 97 + payload_bytes : 76;
  if (bytes == nullptr || capacity < length || payload_.size() % 2 != 0 || payload_bytes > 1024 ||
      (security_mode_ != 3 && security_mode_ != 4) || peer_port_ == 0 || telemetry_timeout_ == 0 ||
      telemetry_timeout_ > 300000 || format_ < -1 || format_ > 65535)
    return -1;
  auto hex = [](const std::string &text, uint8_t *out, size_t expected) -> bool {
    if (text.size() != expected * 2) return false;
    for (size_t i = 0; i < expected; ++i) {
      auto nibble = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
      const int high = nibble(text[i * 2]), low = nibble(text[i * 2 + 1]);
      if (high < 0 || low < 0) return false;
      out[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
  };
  auto integer = [](uint32_t value, uint8_t *out, size_t width) {
    for (size_t i = 0; i < width; ++i) out[width - 1 - i] = static_cast<uint8_t>(value >> (i * 8));
  };
  if (!hex(principal_, bytes, 33) || !hex(resource_, bytes + 34, 32)) return -1;
  bytes[33] = principal_kid_;
  integer(peer_address_, bytes + 66, 4);
  integer(peer_port_, bytes + 70, 2);
  integer(telemetry_timeout_, bytes + 72, 4);
  if (provision) {
    if (!hex(operation_, bytes + 76, 16) || !hex(payload_, bytes + 97, payload_bytes)) return -1;
    bytes[92] = format_ < 0 ? 0 : 1;
    integer(format_ < 0 ? 0 : static_cast<uint32_t>(format_), bytes + 93, 2);
    integer(payload_bytes, bytes + 95, 2);
  }
  return static_cast<int32_t>(length);
}

int32_t CoapticNetwork::read_pending(uint8_t *bytes, uint32_t length) {
  if (bytes == nullptr || length != 1214) return -1;
  // Enrolled work belongs to pairing custody, separate from qualification keys.
  nvs_handle_t &handle = security_mode_ == 5 ? pairing_handle_ : security_handle_;
  const char *space = security_mode_ == 5 ? "coaptic_pair" : "coaptic_sec";
  if (handle == 0 && nvs_open(space, NVS_READWRITE, &handle) != ESP_OK) return -1;
  size_t stored = 0;
  const esp_err_t status = nvs_get_blob(handle, "pending_v1", nullptr, &stored);
  if (status == ESP_ERR_NVS_NOT_FOUND) return 0;
  if (status != ESP_OK || stored != length) return -1;
  return nvs_get_blob(handle, "pending_v1", bytes, &stored) == ESP_OK && stored == length ? 1 : -1;
}

bool CoapticNetwork::commit_pending(const uint8_t *bytes, uint32_t length) {
  const nvs_handle_t handle = security_mode_ == 5 ? pairing_handle_ : security_handle_;
  if (bytes == nullptr || length != 1214 || handle == 0) return false;
  return nvs_set_blob(handle, "pending_v1", bytes, length) == ESP_OK && nvs_commit(handle) == ESP_OK;
}

int32_t CoapticNetwork::read_pairing(uint8_t *bytes, uint32_t capacity) {
  if (security_mode_ != 5 || bytes == nullptr || capacity < 332) return -1;
  if (pairing_handle_ == 0 && nvs_open("coaptic_pair", NVS_READWRITE, &pairing_handle_) != ESP_OK) return -1;
  size_t length = 0;
  const esp_err_t status = nvs_get_blob(pairing_handle_, "custody_v1", nullptr, &length);
  if (status == ESP_ERR_NVS_NOT_FOUND) return 0;
  if (status != ESP_OK || length == 0 || length > 332) return -1;
  return nvs_get_blob(pairing_handle_, "custody_v1", bytes, &length) == ESP_OK ? static_cast<int32_t>(length) : -1;
}

bool CoapticNetwork::commit_pairing(const uint8_t *bytes, uint32_t length) {
  if (security_mode_ != 5 || bytes == nullptr || length == 0 || length > 332 || pairing_handle_ == 0) return false;
  return nvs_set_blob(pairing_handle_, "custody_v1", bytes, length) == ESP_OK && nvs_commit(pairing_handle_) == ESP_OK;
}

void CoapticNetwork::on_shutdown() {
  stop_.store(true, std::memory_order_release);
  const int event = async_event_fd.load(std::memory_order_acquire);
  if (event >= 0) {
    const uint64_t one = 1;
    (void) write(event, &one, sizeof(one));
  }
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

extern "C" bool coaptic_async_init() {
#ifndef CONFIG_VFS_SUPPORT_SELECT
  // Socket-only select cannot monitor eventfd. Refuse instead of sleeping
  // forever or polling when the platform was not built with mixed VFS select.
  return false;
#else
  using namespace esphome::coaptic_network;
  if (async_event_fd.load(std::memory_order_acquire) >= 0) return true;
  // Respect an eventfd VFS already registered by another subsystem. The Rust
  // singleton serializes these calls; global registration is never removed.
  int event = eventfd(0, EFD_SUPPORT_ISR);
  if (event < 0) {
    const esp_vfs_eventfd_config_t config{1};
    if (esp_vfs_eventfd_register(&config) != ESP_OK) return false;
    event = eventfd(0, EFD_SUPPORT_ISR);
  }
  if (event < 0) return false;
  async_event_fd.store(event, std::memory_order_release);
  return true;
#endif
}
extern "C" void coaptic_async_wake() {
  const int event = esphome::coaptic_network::async_event_fd.load(std::memory_order_acquire);
  if (event >= 0) {
    const uint64_t one = 1;
    (void) write(event, &one, sizeof(one));
  }
}
extern "C" uint64_t coaptic_async_now(void *context) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->async_now();
}
extern "C" int32_t coaptic_async_wait(void *context, uint32_t interests, uint64_t deadline) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->async_wait(interests, deadline);
}
extern "C" void coaptic_async_yield() { vTaskDelay(1); }
extern "C" void coaptic_async_storage(uint32_t metadata, uint32_t future) {
  ESP_LOGI("coaptic_network", "COAPTIC_ASYNC_LAYOUT metadata_bytes=%lu future_bytes=%lu",
           static_cast<unsigned long>(metadata), static_cast<unsigned long>(future));
}
#ifdef COAPTIC_PAIRING
extern "C" int32_t coaptic_async_console_ready() {
#ifdef CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
  if (!usb_serial_jtag_is_driver_installed()) return -1;
  return usb_serial_jtag_get_read_bytes_available() > 0 ? 1 : 0;
#else
  return -1;
#endif
}
#endif

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
extern "C" int32_t coaptic_telemetry_config(void *context, uint8_t *bytes, uint32_t capacity) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->telemetry_config(bytes, capacity);
}
extern "C" int32_t coaptic_pending_read(void *context, uint8_t *bytes, uint32_t length) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->read_pending(bytes, length);
}
extern "C" bool coaptic_pending_commit(void *context, const uint8_t *bytes, uint32_t length) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->commit_pending(bytes, length);
}

#ifdef COAPTIC_PAIRING
extern "C" int32_t coaptic_pairing_read(void *context, uint8_t *bytes, uint32_t capacity) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->read_pairing(bytes, capacity);
}
extern "C" bool coaptic_pairing_commit(void *context, const uint8_t *bytes, uint32_t length) {
  return static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->commit_pairing(bytes, length);
}
extern "C" int32_t coaptic_pairing_console_read(void *, uint8_t *bytes, uint32_t capacity) {
  if (bytes == nullptr || capacity == 0 || capacity > 512) return -1;
  return usb_serial_jtag_read_bytes(bytes, capacity, 0);
}
extern "C" bool coaptic_pairing_console_write(void *, const uint8_t *bytes, uint32_t length) {
  if (bytes == nullptr || length == 0 || length > 518) return false;
  return usb_serial_jtag_write_bytes(bytes, length, pdMS_TO_TICKS(250)) == static_cast<int>(length);
}
extern "C" void coaptic_pairing_restart(void *) {
  usb_serial_jtag_wait_tx_done(pdMS_TO_TICKS(250));
  esp_restart();
}
extern "C" void coaptic_pairing_event(void *, uint32_t event) {
  ESP_LOGI("coaptic_network", "COAPTIC_PAIRING_EVENT %lu", static_cast<unsigned long>(event));
}
extern "C" void coaptic_pairing_owner_sizes(void *, uint32_t managed, uint32_t worker) {
  // The managed owner is contained in the worker future; these are not additive.
  ESP_LOGI("coaptic_network", "COAPTIC_OWNERS {\"managed_bytes\":%lu,\"worker_future_bytes\":%lu}",
           static_cast<unsigned long>(managed), static_cast<unsigned long>(worker));
}
extern "C" void coaptic_pairing_diagnostics(void *context, uint64_t at_ms,
                                            uint32_t token_refused, uint32_t rx_refused,
                                            uint32_t tx_refused, uint32_t refusal_sent,
                                            uint32_t refusal_unsent, uint32_t hard_rx,
                                            uint32_t hard_tx, uint32_t rx_accepted,
                                            uint32_t progress) {
  if (context == nullptr) return;
  static_cast<esphome::coaptic_network::CoapticNetwork *>(context)->admission_diagnostics(
      at_ms, token_refused, rx_refused, tx_refused, refusal_sent, refusal_unsent,
      hard_rx, hard_tx, rx_accepted, progress);
}
#endif

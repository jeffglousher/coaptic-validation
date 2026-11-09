#include "mcu_processing_span.h"
#include "sdkconfig.h"
#include "esphome/core/log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>

// Diagnostic-only linker wrappers. The original return value and errno survive
// every path. Wrapping select is solely a quiet-window close hook, not a timer
// for task CPU or a change to the requested wait/deadline.
extern "C" {
ssize_t __real_lwip_recvmsg(int, struct msghdr *, int);
ssize_t __real_lwip_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t __real_lwip_sendmsg(int, const struct msghdr *, int);
ssize_t __real_lwip_sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
int __real_lwip_bind(int, const struct sockaddr *, socklen_t);
int __real_lwip_close(int);
int __real_lwip_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int __real_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
void __real_vTaskDelay(TickType_t);
#if CONFIG_VFS_SUPPORT_SELECT
int __real_esp_vfs_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#endif
}
namespace mcu_span {
namespace {
constexpr char TAG[] = "mcu_span";
#define MCU_SPAN_LOG(...) ::esphome::esp_log_printf_(3, TAG, __LINE__, __VA_ARGS__)
std::atomic<Context *> current{nullptr};
std::atomic<TaskHandle_t> owner{nullptr};
std::atomic<std::uint32_t> startup_stack{0}, startup_internal{0}, startup_all{0}, startup_free{0}, startup_generation{0};
constexpr std::size_t GLOBAL_BYTES = sizeof(current) + sizeof(owner) + sizeof(startup_stack) + sizeof(startup_internal) + sizeof(startup_all) + sizeof(startup_free) + sizeof(startup_generation);
static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "Observer ownership must not require a lock");
static_assert(GLOBAL_BYTES <= 64, "Global observer ownership/startup snapshot exceeds bound");
static_assert(ATOMIC_INT_LOCK_FREE == 2, "Startup snapshot must not require a lock");
Context *owned() {
  // Other tasks never dereference a worker-stack pointer. The worker removes
  // ownership before publishing its terminal result or returning.
  if (owner.load(std::memory_order_acquire) != xTaskGetCurrentTaskHandle()) return nullptr;
  Context *c = current.load(std::memory_order_relaxed);
  return c && !c->busy && !c->frozen ? c : nullptr;
}
Context *selected(int fd) { Context *c = owned(); return c && c->fd == fd ? c : nullptr; }
void inc(Context &c, std::uint32_t &v) {
  if (v == std::numeric_limits<std::uint32_t>::max()) c.saturated = true;
  else ++v;
}
bool peer(const struct sockaddr *address, socklen_t n, Peer &out) {
  if (!address || n < sizeof(sockaddr_in) || address->sa_family != AF_INET) return false;
  const auto *a = reinterpret_cast<const sockaddr_in *>(address);
  out.ip = ntohl(a->sin_addr.s_addr); out.port = ntohs(a->sin_port); return true;
}
bool gather(std::uint8_t *out, const struct iovec *v, std::size_t count, std::size_t n) {
  if (!v || count == 0 || count > 4 || n > PACKET_BYTES) return false;
  std::size_t copied = 0;
  for (std::size_t i = 0; i < count && copied < n; ++i) {
    const std::size_t part = std::min(n - copied, v[i].iov_len);
    if (part && !v[i].iov_base) return false;
    if (part) std::memcpy(out + copied, v[i].iov_base, part);
    copied += part;
  }
  return copied == n;
}
std::size_t message_bytes(const struct msghdr *m) {
  if (!m || !m->msg_iov || m->msg_iovlen == 0 || m->msg_iovlen > 4) return std::numeric_limits<std::size_t>::max();
  std::size_t n = 0;
  for (std::size_t i = 0; i < m->msg_iovlen; ++i) {
    if (m->msg_iov[i].iov_len > std::numeric_limits<std::size_t>::max() - n) return std::numeric_limits<std::size_t>::max();
    n += m->msg_iov[i].iov_len;
  }
  return n;
}
void log_pause() {
  const int saved = errno;
  __real_vTaskDelay(pdMS_TO_TICKS(LOG_PAUSE_MS));
  errno = saved;
}
// All serialization and pacing remain after send-return with busy set.
void base64(const std::uint8_t *bytes, std::size_t n, char (&out)[121]) {
  constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::size_t used = 0;
  for (std::size_t i = 0; i < n; i += 3) {
    const auto v = (static_cast<std::uint32_t>(bytes[i]) << 16) |
      (i+1 < n ? static_cast<std::uint32_t>(bytes[i+1]) << 8 : 0) | (i+2 < n ? bytes[i+2] : 0);
    out[used++] = alphabet[(v >> 18)&63]; out[used++] = alphabet[(v >> 12)&63];
    out[used++] = i+1 < n ? alphabet[(v >> 6)&63] : '=';
    out[used++] = i+2 < n ? alphabet[v&63] : '=';
  }
  out[used] = 0;
}
std::size_t run_length(const std::uint8_t *bytes, std::size_t offset, std::size_t n) {
  std::size_t length = 1;
  while (offset + length < n && bytes[offset + length] == bytes[offset]) ++length;
  return length;
}
void wire(const Context &c, std::uint32_t row, const char *side,
          const std::uint8_t *bytes, std::size_t n) {
  std::size_t offset = 0;
  while (offset < n) {
    const auto run = run_length(bytes, offset, n);
    if (run >= 16) {
      MCU_SPAN_LOG("COAPTIC_MCU_SPAN_FILL %s %lu %s %u %u %u", c.run_id,
        static_cast<unsigned long>(row), side, static_cast<unsigned>(offset), static_cast<unsigned>(run), static_cast<unsigned>(bytes[offset]));
      offset += run;
    } else {
      const auto start = offset;
      offset += run;
      while (offset < n && offset - start < WIRE_BYTES) {
        const auto next = run_length(bytes, offset, n);
        if (next >= 16) break;
        offset += std::min(next, WIRE_BYTES - (offset - start));
      }
      char encoded[121]; base64(bytes + start, offset - start, encoded);
      MCU_SPAN_LOG("COAPTIC_MCU_SPAN_WIRE %s %lu %s %u %s", c.run_id,
        static_cast<unsigned long>(row), side, static_cast<unsigned>(start), encoded);
    }
    log_pause();
  }
}
struct RowEncoder {
  std::uint8_t bytes[224]{};
  std::size_t size{};
  bool valid{true};
  void byte(std::uint8_t value) { if (size < sizeof(bytes)) bytes[size++] = value; else valid = false; }
  void head(unsigned major, std::uint64_t value) {
    if (value < 24) { byte(static_cast<std::uint8_t>((major << 5) | value)); return; }
    const unsigned width = value <= 0xff ? 1 : value <= 0xffff ? 2 : value <= 0xffffffffULL ? 4 : 8;
    byte(static_cast<std::uint8_t>((major << 5) | (width == 1 ? 24 : width == 2 ? 25 : width == 4 ? 26 : 27)));
    for (unsigned i = width; i > 0; --i) byte(static_cast<std::uint8_t>(value >> ((i-1)*8)));
  }
  void u(std::uint64_t value) { head(0, value); }
  void s(std::int64_t value) { if (value < 0) head(1, static_cast<std::uint64_t>(-(value + 1))); else head(0, static_cast<std::uint64_t>(value)); }
};
static_assert(sizeof(RowEncoder) <= 256, "Bounded CBOR row encoder exceeds stack-owner budget");
void row(Context &c, std::uint32_t index, ssize_t result, int error, std::size_t n,
         std::int64_t entry, std::int64_t returned, bool matched, const Peer &p) {
  RowEncoder encoded;
  encoded.head(4, 24); // Definite canonical CBOR array, 24 exact integers.
  encoded.u(1); encoded.u(index); encoded.u(c.rx_sequence); encoded.u((c.active ? 1U : 0U) | (matched ? 2U : 0U));
  encoded.u(c.active ? c.rx_bytes : 0); encoded.u(n); encoded.s(result); encoded.s(error);
  encoded.u(c.rx_peer.ip); encoded.u(c.rx_peer.port); encoded.u(p.ip); encoded.u(p.port);
  encoded.s(c.recv_entry_us); encoded.s(c.recv_return_us); encoded.s(entry); encoded.s(returned);
  encoded.u(c.native.waits); encoded.u(c.native.wait_us); encoded.u(c.native.yields); encoded.u(c.native.yield_us);
  encoded.u(c.native.nested_waits); encoded.u(c.native.nested_yields); encoded.s(c.fd); encoded.u(c.port);
  if (!encoded.valid) { inc(c, c.counts.rows_refused); return; }
  for (std::size_t offset = 0; offset < encoded.size; offset += WIRE_BYTES) {
    char text[121]; base64(encoded.bytes + offset, std::min(WIRE_BYTES, encoded.size - offset), text);
    MCU_SPAN_LOG("COAPTIC_MCU_SPAN_ROW %s %lu %u %u %s", c.run_id, static_cast<unsigned long>(index),
      static_cast<unsigned>(offset), static_cast<unsigned>(encoded.size), text); log_pause();
  }
}
bool header_match(const Context &c, const Peer &p, std::size_t n) {
  if (!c.active || c.rx_bytes < 4 || n < 4 || p.ip != c.rx_peer.ip || p.port != c.rx_peer.port) return false;
  const auto *a = c.rx_packet; const auto *b = c.tx_packet;
  const unsigned token = a[0] & 15;
  // This finite static GET diagnosis expects piggybacked 2.05 ACKs. Full wire
  // options/payload/Block2 validation belongs to the retained offline matcher.
  return (a[0] >> 6) == 1 && ((a[0] >> 4) & 3) == 0 && a[1] == 1 && token <= 8 &&
      c.rx_bytes >= 4 + token && (b[0] >> 6) == 1 && ((b[0] >> 4) & 3) == 2 && b[1] == 69 &&
      (b[0] & 15) == token && n >= 4 + token && a[2] == b[2] && a[3] == b[3] &&
      std::memcmp(a + 4, b + 4, token) == 0;
}
void received(Context &c, ssize_t n, int error, int flags, std::int64_t start, std::int64_t end,
              bool copied, bool addressed, const Peer &p) {
  if (flags & MSG_PEEK) { inc(c, c.counts.peek); return; }
  if (n < 0) {
    if (error == EAGAIN || error == EWOULDBLOCK) inc(c, c.counts.would_block);
    else inc(c, c.counts.rx_error);
    return;
  }
  inc(c, c.counts.rx); c.last_activity_us = end;
  if (c.active) inc(c, c.counts.rx_replaced);
  c.active = false;
  if (!copied || !addressed || n > static_cast<ssize_t>(PACKET_BYTES)) { inc(c, c.counts.rx_refused); return; }
  c.rx_sequence = c.counts.rx; c.rx_bytes = static_cast<std::uint32_t>(n);
  c.rx_peer = p; c.recv_entry_us = start; c.recv_return_us = end; c.native = {}; c.active = true;
}
void sent(Context &c, ssize_t result, int error, std::size_t n, std::int64_t entry,
          std::int64_t returned, bool copied, bool addressed, const Peer &p) {
  c.busy = true; // No observer re-entry/quiet close while complete wire rows are emitted.
  inc(c, c.counts.tx); c.last_activity_us = returned;
  const bool length_known = n != std::numeric_limits<std::size_t>::max();
  const bool success = length_known && result >= 0 && static_cast<std::size_t>(result) == n;
  if (result < 0) inc(c, c.counts.tx_failed);
  else if (length_known && !success) inc(c, c.counts.tx_partial);
  if (success) inc(c, c.counts.tx_success);
  if (!copied || !addressed) inc(c, c.counts.tx_refused);
  const bool matched = copied && addressed && header_match(c, p, n);
  if (!matched) inc(c, c.counts.tx_unmatched);
  // Logging and TX copying occur after the send-return timestamp. Never infer
  // clean RTT/CPU performance from this instrumented application.
  if (c.counts.rows < MAX_LOGGED_ATTEMPTS) {
    const std::uint32_t row = c.counts.rows; inc(c, c.counts.rows);
    mcu_span::row(c, row, result, error, n, entry, returned, matched, p);
    if (c.active) wire(c, row, "rx", c.rx_packet, c.rx_bytes);
    if (copied) wire(c, row, "tx", c.tx_packet, n);
  } else inc(c, c.counts.rows_refused);
  if (success && matched) c.active = false;
  c.busy = false;
}
void quiet(Context &c, std::int64_t now) {
  if (c.counts.rx >= EXPECTED_DATAGRAMS && now >= c.last_activity_us &&
      now - c.last_activity_us >= QUIET_US) finish(c, false);
}
void emit_metadata(Context &c, std::uint32_t sequence) {
  const bool prior = c.busy; c.busy = true;
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_BEGIN {\"r\":\"%s\",\"f\":%d,\"p\":%u,\"c\":%u,\"g\":%u,\"b\":%u,\"m\":%lu,\"n\":%lu,\"q\":%lld,\"s\":%lu}",
    c.run_id, c.initial_fd, c.port, static_cast<unsigned>(sizeof(c)), static_cast<unsigned>(GLOBAL_BYTES), static_cast<unsigned>(PACKET_BYTES), static_cast<unsigned long>(MAX_LOGGED_ATTEMPTS), static_cast<unsigned long>(EXPECTED_DATAGRAMS), static_cast<long long>(QUIET_US), static_cast<unsigned long>(c.stack_bytes)); log_pause();
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_SOCKET {\"r\":\"%s\",\"f\":%d,\"p\":%u}", c.run_id, c.observed_fd, c.port); log_pause();
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_STARTUP {\"r\":\"%s\",\"s\":%lu,\"i\":%lu,\"a\":%lu,\"f\":%lu,\"w\":true}",
    c.run_id, static_cast<unsigned long>(c.startup.stack), static_cast<unsigned long>(c.startup.largest_internal), static_cast<unsigned long>(c.startup.largest_all), static_cast<unsigned long>(c.startup.free_all)); log_pause();
  multi_heap_info_t info{}; heap_caps_get_info(&info, MALLOC_CAP_8BIT);
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_RESOURCES {\"r\":\"%s\",\"v\":%lu,\"f\":%lu,\"l\":%lu,\"m\":%lu,\"t\":%lu,\"p\":\"%s\"}", c.run_id,
    static_cast<unsigned long>(sequence), static_cast<unsigned long>(info.total_free_bytes), static_cast<unsigned long>(info.largest_free_block), static_cast<unsigned long>(info.minimum_free_bytes), static_cast<unsigned long>(info.total_free_bytes + info.total_allocated_bytes), c.fd >= 0 ? "running" : "after_service"); log_pause();
  const auto free_stack = uxTaskGetStackHighWaterMark(nullptr);
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_STACK {\"r\":\"%s\",\"v\":%lu,\"s\":%lu,\"u\":%lu}", c.run_id,
    static_cast<unsigned long>(sequence), static_cast<unsigned long>(c.stack_bytes), static_cast<unsigned long>(free_stack < c.stack_bytes ? c.stack_bytes - free_stack : 0)); log_pause();
  c.busy = prior;
}
void idle_metadata(Context &c) {
  if (c.active || c.counts.rx != 0 || c.observed_fd < 0 || c.metadata_replays >= 8) return;
  const auto now = esp_timer_get_time();
  if (c.metadata_replays && now - c.last_metadata_us < 1000000) return;
  ++c.metadata_replays; c.last_metadata_us = now; emit_metadata(c, c.metadata_replays);
}
// Only calls entered with a pending consumed RX contribute wall time. Nested
// native calls are counted separately; their duration is already in the outer
// native call, so it is never added twice. UDP syscalls and post-span logging
// set busy and are excluded. The residual remains wall+preemption+observer work.
struct NativeCall { Context *context{}; std::int64_t start{}; std::uint32_t rx_sequence{}; bool measured{}, outer{}, yielding{}; };
NativeCall native_enter(bool yielding) {
  Context *c = owned();
  if (!c) return {};
  if (c->native_depth == 0) idle_metadata(*c);
  if (c->native_depth >= 8) { inc(*c, c->counts.native_refused); return {}; }
  const bool measured = c->active;
  const bool outer = c->native_depth == 0;
  ++c->native_depth;
  if (measured) {
    if (outer) inc(*c, yielding ? c->native.yields : c->native.waits);
    else inc(*c, yielding ? c->native.nested_yields : c->native.nested_waits);
  }
  return {c, measured && outer ? esp_timer_get_time() : 0, c->rx_sequence, measured, outer, yielding};
}
void native_leave(const NativeCall &call) {
  Context *c = call.context;
  if (!c) return;
  const auto now = esp_timer_get_time();
  --c->native_depth;
  if (call.measured && call.outer) {
    if (!c->active || c->rx_sequence != call.rx_sequence || now < call.start) inc(*c, c->counts.native_refused);
    else {
      auto &total = call.yielding ? c->native.yield_us : c->native.wait_us;
      const auto elapsed = static_cast<std::uint64_t>(now - call.start);
      if (elapsed > std::numeric_limits<std::uint64_t>::max() - total) inc(*c, c->counts.native_refused);
      else total += elapsed;
    }
  }
  if (call.outer) quiet(*c, now);
}
}  // namespace
void before_task(std::uint32_t stack) {
  // Single ESPHome creator; every shared field is atomic so a concurrent reader
  // can refuse an inconsistent generation without a data race or spinning.
  startup_generation.fetch_add(1, std::memory_order_acq_rel);
  startup_stack.store(stack, std::memory_order_relaxed);
  startup_internal.store(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT), std::memory_order_relaxed);
  startup_all.store(heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), std::memory_order_relaxed);
  startup_free.store(heap_caps_get_free_size(MALLOC_CAP_8BIT), std::memory_order_relaxed);
  startup_generation.fetch_add(1, std::memory_order_release);
}
void attach(Context &c, const char *id, int fd, std::uint16_t port, std::uint32_t stack) {
  c.run_id = id; c.fd = c.initial_fd = c.observed_fd = fd; c.port = port; c.stack_bytes = stack;
  for (unsigned attempt = 0; attempt < 2; ++attempt) {
    const auto generation = startup_generation.load(std::memory_order_acquire);
    if (generation & 1) continue;
    Startup snapshot{startup_stack.load(std::memory_order_relaxed), startup_internal.load(std::memory_order_relaxed), startup_all.load(std::memory_order_relaxed), startup_free.load(std::memory_order_relaxed)};
    if (generation == startup_generation.load(std::memory_order_acquire) && snapshot.stack == stack) { c.startup = snapshot; break; }
  }
  Context *none = nullptr;
  if (!current.compare_exchange_strong(none, &c, std::memory_order_release, std::memory_order_relaxed)) {
    c.frozen = true; ::esphome::esp_log_printf_(1, TAG, __LINE__, "COAPTIC_MCU_SPAN_REFUSED owner_conflict run_id=%s", id); return;
  }
  owner.store(xTaskGetCurrentTaskHandle(), std::memory_order_release);
}
void finish(Context &c, bool forced) {
  if (c.frozen) return;
  c.frozen = true;
  owner.store(nullptr, std::memory_order_release);
  Context *expected = &c;
  (void)current.compare_exchange_strong(expected, nullptr, std::memory_order_release, std::memory_order_relaxed);
  // Final metadata is replayed after the span; identical constants are allowed.
  c.busy = true; emit_metadata(c, c.metadata_replays + 1);
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_COUNTS {\"r\":\"%s\",\"g\":\"rx\",\"a\":%lu,\"b\":%lu,\"c\":%lu,\"d\":%lu,\"e\":%lu,\"f\":%lu,\"h\":%lu}", c.run_id,
    static_cast<unsigned long>(c.counts.rx), static_cast<unsigned long>(c.counts.would_block), static_cast<unsigned long>(c.counts.peek), static_cast<unsigned long>(c.counts.rx_error), static_cast<unsigned long>(c.counts.rx_refused), static_cast<unsigned long>(c.counts.rx_replaced), static_cast<unsigned long>(c.counts.rx_abandoned)); log_pause();
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_COUNTS {\"r\":\"%s\",\"g\":\"tx\",\"a\":%lu,\"b\":%lu,\"c\":%lu,\"d\":%lu,\"e\":%lu,\"f\":%lu}", c.run_id,
    static_cast<unsigned long>(c.counts.tx), static_cast<unsigned long>(c.counts.tx_success), static_cast<unsigned long>(c.counts.tx_failed), static_cast<unsigned long>(c.counts.tx_partial), static_cast<unsigned long>(c.counts.tx_unmatched), static_cast<unsigned long>(c.counts.tx_refused)); log_pause();
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_COUNTS {\"r\":\"%s\",\"g\":\"observer\",\"a\":%lu,\"b\":%lu,\"c\":%lu,\"d\":%lu,\"e\":%lu,\"s\":%s}", c.run_id,
    static_cast<unsigned long>(c.counts.rows), static_cast<unsigned long>(c.counts.rows_refused), static_cast<unsigned long>(c.counts.bind_conflict), static_cast<unsigned long>(c.counts.fd_reuse), static_cast<unsigned long>(c.counts.native_refused), c.saturated ? "true" : "false"); log_pause();
  MCU_SPAN_LOG("COAPTIC_MCU_SPAN_END {\"r\":\"%s\",\"a\":%lu,\"p\":%s,\"f\":%s,\"w\":true}", c.run_id,
    static_cast<unsigned long>(c.counts.rows), c.active ? "true" : "false", forced ? "true" : "false"); log_pause();
  c.busy = false;

}
}  // namespace mcu_span

extern "C" ssize_t __wrap_lwip_recvmsg(int fd, struct msghdr *m, int flags) {
  const int before = errno; const auto entry = esp_timer_get_time(); errno = before;
  auto *c = mcu_span::selected(fd); if (!c) return __real_lwip_recvmsg(fd, m, flags);
  c->busy = true; const ssize_t n = __real_lwip_recvmsg(fd, m, flags); const int saved = errno;
  const auto returned = esp_timer_get_time(); c->busy = false; mcu_span::Peer p{};
  const bool copied = !(flags & MSG_PEEK) && n >= 0 && m && !(m->msg_flags & MSG_TRUNC) && mcu_span::gather(c->rx_packet, m->msg_iov, m->msg_iovlen, static_cast<std::size_t>(n));
  const bool addressed = m && mcu_span::peer(static_cast<const sockaddr *>(m->msg_name), m->msg_namelen, p);
  mcu_span::received(*c, n, saved, flags, entry, returned, copied, addressed, p); errno = saved; return n;
}
extern "C" ssize_t __wrap_lwip_recvfrom(int fd, void *data, size_t capacity, int flags, struct sockaddr *address, socklen_t *length) {
  const int before = errno; const auto entry = esp_timer_get_time(); errno = before;
  auto *c = mcu_span::selected(fd); if (!c) return __real_lwip_recvfrom(fd, data, capacity, flags, address, length);
  c->busy = true; const ssize_t n = __real_lwip_recvfrom(fd, data, capacity, flags, address, length); const int saved = errno;
  const auto returned = esp_timer_get_time(); c->busy = false; mcu_span::Peer p{};
  const iovec v{data, capacity}; const bool copied = !(flags & MSG_PEEK) && n >= 0 && static_cast<std::size_t>(n) < capacity && mcu_span::gather(c->rx_packet, &v, 1, static_cast<std::size_t>(n));
  const bool addressed = length && mcu_span::peer(address, *length, p);
  mcu_span::received(*c, n, saved, flags, entry, returned, copied, addressed, p); errno = saved; return n;
}
extern "C" ssize_t __wrap_lwip_sendmsg(int fd, const struct msghdr *m, int flags) {
  const int before = errno; const auto entry = esp_timer_get_time(); errno = before;
  auto *c = mcu_span::selected(fd); if (!c) return __real_lwip_sendmsg(fd, m, flags);
  c->busy = true; const ssize_t n = __real_lwip_sendmsg(fd, m, flags); const int saved = errno;
  const auto returned = esp_timer_get_time(); c->busy = false; mcu_span::Peer p{};
  const std::size_t bytes = mcu_span::message_bytes(m);
  const bool copied = m && mcu_span::gather(c->tx_packet, m->msg_iov, m->msg_iovlen, bytes);
  const bool addressed = m && mcu_span::peer(static_cast<const sockaddr *>(m->msg_name), m->msg_namelen, p);
  mcu_span::sent(*c, n, saved, bytes, entry, returned, copied, addressed, p); errno = saved; return n;
}
extern "C" ssize_t __wrap_lwip_sendto(int fd, const void *data, size_t bytes, int flags, const struct sockaddr *address, socklen_t length) {
  const int before = errno; const auto entry = esp_timer_get_time(); errno = before;
  auto *c = mcu_span::selected(fd); if (!c) return __real_lwip_sendto(fd, data, bytes, flags, address, length);
  c->busy = true; const ssize_t n = __real_lwip_sendto(fd, data, bytes, flags, address, length); const int saved = errno;
  const auto returned = esp_timer_get_time(); c->busy = false; mcu_span::Peer p{};
  const iovec v{const_cast<void *>(data), bytes}; const bool copied = mcu_span::gather(c->tx_packet, &v, 1, bytes);
  const bool addressed = mcu_span::peer(address, length, p);
  mcu_span::sent(*c, n, saved, bytes, entry, returned, copied, addressed, p); errno = saved; return n;
}
extern "C" int __wrap_lwip_bind(int fd, const struct sockaddr *address, socklen_t length) {
  auto *c = mcu_span::owned(); if (c) c->busy = true;
  const int n = __real_lwip_bind(fd, address, length); const int saved = errno;
  if (c) { c->busy = false; mcu_span::Peer p{};
    if (n == 0 && mcu_span::peer(address, length, p) && p.port == c->port) {
      if (c->fd == -1) {
        if (c->observed_fd >= 0) mcu_span::inc(*c, c->counts.fd_reuse);
        else c->observed_fd = fd;
        c->fd = fd;
      } else if (c->fd != fd) mcu_span::inc(*c, c->counts.bind_conflict);
    }
  }
  errno = saved; return n;
}
extern "C" int __wrap_lwip_close(int fd) {
  auto *c = mcu_span::selected(fd); if (c) c->busy = true;
  const int n = __real_lwip_close(fd); const int saved = errno;
  if (c) { c->busy = false; if (n == 0) {
    if (c->active) mcu_span::inc(*c, c->counts.rx_abandoned);
    c->active = false; c->fd = -1;
  } }
  errno = saved; return n;
}
#define MCU_SPAN_SELECT(NAME) \
extern "C" int __wrap_##NAME(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t) { \
  const int before = errno; const auto call = mcu_span::native_enter(false); errno = before; \
  const int value = __real_##NAME(n, r, w, e, t); const int saved = errno; \
  mcu_span::native_leave(call); errno = saved; return value; \
}
MCU_SPAN_SELECT(lwip_select)
MCU_SPAN_SELECT(select)
#if CONFIG_VFS_SUPPORT_SELECT
MCU_SPAN_SELECT(esp_vfs_select)
#endif
#undef MCU_SPAN_SELECT
extern "C" void __wrap_vTaskDelay(TickType_t ticks) {
  const int before = errno; const auto call = mcu_span::native_enter(true); errno = before;
  __real_vTaskDelay(ticks); const int saved = errno;
  mcu_span::native_leave(call); errno = saved;
}

extern "C" { extern const std::uint32_t mcu_span_size_witness[2] = {sizeof(mcu_span::Context), static_cast<std::uint32_t>(mcu_span::GLOBAL_BYTES)}; }

#pragma once
#include <cstddef>
#include <cstdint>

namespace mcu_span {
constexpr std::size_t PACKET_BYTES = 1152;
constexpr std::uint32_t EXPECTED_DATAGRAMS = 64;
constexpr std::uint32_t MAX_LOGGED_ATTEMPTS = 96;
constexpr std::int64_t QUIET_US = 15000000;
constexpr std::size_t WIRE_BYTES = 90;
constexpr std::uint32_t LOG_PAUSE_MS = 50;
struct Peer { std::uint32_t ip{}; std::uint16_t port{}; };
struct Counters {
  std::uint32_t rx{}, would_block{}, peek{}, rx_error{}, rx_refused{}, rx_replaced{}, rx_abandoned{};
  std::uint32_t tx{}, tx_success{}, tx_failed{}, tx_partial{}, tx_unmatched{}, tx_refused{};
  std::uint32_t rows{}, rows_refused{}, bind_conflict{}, fd_reuse{}, native_refused{};
};
struct Native { std::uint64_t wait_us{}, yield_us{}; std::uint32_t waits{}, yields{}, nested_waits{}, nested_yields{}; };
struct Startup { std::uint32_t stack{}, largest_internal{}, largest_all{}, free_all{}; };
// Worker-owned lifetime. No packet pointer escapes a syscall wrapper.
// This owner uses the original reserved worker stack, not additional heap backing.
struct Context {
  std::uint8_t rx_packet[PACKET_BYTES]{};
  std::uint8_t tx_packet[PACKET_BYTES]{};
  const char *run_id{};
  Counters counts{};
  Startup startup{};
  Native native{};
  std::uint32_t native_depth{}, metadata_replays{};
  std::int64_t last_metadata_us{};
  Peer rx_peer{};
  std::int64_t recv_entry_us{}, recv_return_us{}, last_activity_us{};
  std::uint32_t rx_sequence{}, rx_bytes{}, stack_bytes{};
  int fd{-1}, initial_fd{-1}, observed_fd{-1};
  std::uint16_t port{};
  bool active{}, frozen{}, busy{}, saturated{};
};
static_assert(sizeof(Context) <= 3072, "Diagnostic worker stack owner exceeds its bound");
// Called only by the existing single ESPHome creator before its unchanged task call.
void before_task(std::uint32_t original_stack_bytes);
void attach(Context &context, const char *run_id, int fd, std::uint16_t port,
            std::uint32_t original_stack_bytes);
void finish(Context &context, bool forced);
}  // namespace mcu_span

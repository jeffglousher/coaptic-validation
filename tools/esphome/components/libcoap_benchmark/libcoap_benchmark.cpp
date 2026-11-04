#include "libcoap_benchmark.h"

#include "coap_config.h"

#include "coap3/coap.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esphome/components/network/util.h"
#include "esphome/core/log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include <array>
#include <cinttypes>

namespace esphome::libcoap_benchmark {
namespace {
constexpr const char *TAG = "libcoap_benchmark";
constexpr uint32_t STACK_BYTES = 16384;
constexpr uint32_t OPERATIONS = 24;
constexpr uint32_t POLL_LIMIT = 100000;
constexpr int64_t TIMEOUT_US = 5000000;

struct Operation {
  const uint8_t *identity{};
  uint8_t token[8]{};
  size_t token_length{};
  unsigned resource{};
  bool active{};
  bool done{};
  const char *error{};
};

const char *path(unsigned resource) {
  return resource == 0 ? "identity" : resource == 1 ? "test" : "large";
}

size_t expected_length(unsigned resource) {
  return resource == 0 ? 32 : resource == 1 ? 7 : 2000;
}

bool token_matches(const coap_pdu_t *pdu, const Operation &operation) {
  const auto token = coap_pdu_get_token(pdu);
  return token.length == operation.token_length &&
         std::memcmp(token.s, operation.token, token.length) == 0;
}

coap_response_t response(coap_session_t *session, const coap_pdu_t *,
                         const coap_pdu_t *received, coap_mid_t) {
  auto *operation =
      static_cast<Operation *>(coap_session_get_app_data(session));
  if (operation == nullptr || !operation->active ||
      !token_matches(received, *operation))
    return COAP_RESPONSE_FAIL;
  if (operation->done || operation->error != nullptr)
    return COAP_RESPONSE_OK;
  if (coap_pdu_get_code(received) != COAP_RESPONSE_CODE_CONTENT) {
    operation->error = "response_status";
    return COAP_RESPONSE_FAIL;
  }
  // The matched Coaptic service handlers deliberately leave Content-Format
  // unset. Accepting explicit 0 would silently change that representation.
  coap_opt_iterator_t iterator{};
  if (coap_check_option(received, COAP_OPTION_CONTENT_FORMAT, &iterator) !=
          nullptr ||
      coap_check_option(received, COAP_OPTION_OBSERVE, &iterator) != nullptr) {
    operation->error = "response_metadata";
    return COAP_RESPONSE_FAIL;
  }
  auto *etag = coap_check_option(received, COAP_OPTION_ETAG, &iterator);
  if (etag != nullptr &&
      (coap_opt_length(etag) == 0 || coap_opt_length(etag) > 8)) {
    operation->error = "response_etag";
    return COAP_RESPONSE_FAIL;
  }
  unsigned etags = 0;
  coap_option_iterator_init(received, &iterator, COAP_OPT_ALL);
  while (coap_option_next(&iterator) != nullptr) {
    if (iterator.number == COAP_OPTION_ETAG && ++etags > 1) {
      operation->error = "response_duplicate_etag";
      return COAP_RESPONSE_FAIL;
    }
  }
  // libcoap marks normal iterator exhaustion (including a payload marker)
  // as bad. PDU parsing validates wire options before this callback; only
  // the application metadata and duplicate checks above belong here.
  size_t length = 0, offset = 0, total = 0;
  const uint8_t *data = nullptr;
  const size_t expected = expected_length(operation->resource);
  // SINGLE_BODY makes libcoap own complete Block2 assembly and representation
  // consistency. No callback-owned payload pointer escapes this invocation.
  if (!coap_get_data_large(received, &length, &data, &offset, &total) ||
      offset != 0 || length != expected || total != expected ||
      data == nullptr) {
    operation->error = "response_length_or_partial";
    return COAP_RESPONSE_FAIL;
  }
  for (size_t i = 0; i < length; ++i) {
    const uint8_t expected_byte =
        operation->resource == 0   ? operation->identity[i]
        : operation->resource == 1 ? static_cast<uint8_t>("coaptic"[i])
                                   : 0x5a;
    if (data[i] != expected_byte) {
      operation->error = "response_bytes_or_identity";
      return COAP_RESPONSE_FAIL;
    }
  }
  operation->done = true;
  return COAP_RESPONSE_OK;
}

void nack(coap_session_t *session, const coap_pdu_t *sent, coap_nack_reason_t,
          coap_mid_t) {
  auto *operation =
      static_cast<Operation *>(coap_session_get_app_data(session));
  if (operation != nullptr && operation->active && !operation->done &&
      (sent == nullptr || token_matches(sent, *operation)))
    operation->error = "negative_acknowledgement";
}

bool perform(coap_session_t *session, Operation &operation) {
  auto *request =
      coap_new_pdu(COAP_MESSAGE_CON, COAP_REQUEST_CODE_GET, session);
  if (request == nullptr) {
    operation.error = "request_allocation";
    return false;
  }
  operation.token_length = sizeof(operation.token);
  coap_session_new_token(session, &operation.token_length, operation.token);
  const char *resource = path(operation.resource);
  if (operation.token_length == 0 ||
      operation.token_length > sizeof(operation.token) ||
      !coap_add_token(request, operation.token_length, operation.token) ||
      !coap_add_option(request, COAP_OPTION_URI_PATH, std::strlen(resource),
                       reinterpret_cast<const uint8_t *>(resource))) {
    coap_delete_pdu(request);
    operation.error = "request_encoding";
    return false;
  }
  // coap_send owns the PDU on success and failure; the context owns any retry.
  if (coap_send(session, request) == COAP_INVALID_MID) {
    operation.error = "request_send";
    return false;
  }
  return true;
}

#ifdef LIBCOAP_BENCH_SERVER
// BEGIN HOST-TESTABLE SERVER HANDLERS
constexpr auto LARGE_REPRESENTATION = [] {
  std::array<uint8_t, 2000> bytes{};
  for (auto &byte : bytes)
    byte = 0x5a;
  return bytes;
}();

struct ServerState {
  uint32_t peer_address{};
  uint32_t handler_calls{};
  uint32_t refused_peers{};
  const char *error{};
};

struct Representation {
  ServerState *state{};
  const uint8_t *data{};
  size_t length{};
};

void server_get(coap_resource_t *resource, coap_session_t *session,
                const coap_pdu_t *request, const coap_string_t *,
                coap_pdu_t *reply) {
  auto *representation =
      static_cast<Representation *>(coap_resource_get_userdata(resource));
  const auto *remote = coap_session_get_addr_remote(session);
  if (representation == nullptr || representation->state == nullptr) {
    coap_pdu_set_code(reply, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  auto &state = *representation->state;
  if (remote == nullptr || remote->addr.sin.sin_family != AF_INET ||
      ntohl(remote->addr.sin.sin_addr.s_addr) != state.peer_address) {
    ++state.refused_peers;
    coap_pdu_set_code(reply, COAP_RESPONSE_CODE_UNAUTHORIZED);
    return;
  }
  ++state.handler_calls;
  coap_pdu_set_code(reply, COAP_RESPONSE_CODE_CONTENT);
  coap_block_b_t block{};
  const bool requested =
      coap_get_block_b(session, request, COAP_OPTION_BLOCK2, &block) != 0;
  if (!requested && representation->length <= 1024) {
    if (!coap_add_data(reply, representation->length, representation->data)) {
      state.error = "response_allocation";
      coap_pdu_set_code(reply, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    }
    return;
  }
  if (!requested) {
    block.szx = 6;
    block.aszx = 6;
  }
  // Public helpers choose SZX/M/NUM and the exact payload window. The static
  // representation is borrowed again on each GET, as in the Coaptic fixture.
  // No Content-Format, retained whole-body copy or custom wire encoder is used.
  const int encoded = coap_write_block_b_opt(
      session, &block, COAP_OPTION_BLOCK2, reply, representation->length);
  if (encoded == -2) {
    coap_pdu_set_code(reply, COAP_RESPONSE_CODE_BAD_REQUEST);
    return;
  }
  if (encoded <= 0 || !coap_add_block_b_data(reply, representation->length,
                                             representation->data, &block)) {
    state.error = "response_block_allocation";
    coap_pdu_set_code(reply, COAP_RESPONSE_CODE_INTERNAL_ERROR);
  }
}
// END HOST-TESTABLE SERVER HANDLERS
#endif
} // namespace

void LibcoapBenchmark::setup() { setup_us_ = esp_timer_get_time(); }

void LibcoapBenchmark::loop() {
  if (launched_)
    return;
  const int64_t elapsed_us = esp_timer_get_time() - setup_us_;
  if (elapsed_us < static_cast<int64_t>(start_delay_ms_) * 1000)
    return;
  if (!network::is_connected()) {
    if (elapsed_us >= (static_cast<int64_t>(start_delay_ms_) + 30000) * 1000) {
      launched_ = true;
      ESP_LOGE(TAG,
               "LIBCOAP_BENCH_TERMINAL "
               "{\"passed\":false,\"run_id\":\"%s\",\"completed\":0,\"error\":"
               "\"network_deadline\"}",
               run_id_);
      mark_failed();
    }
    return;
  }
  launched_ = true;
  const size_t heap_before_task = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  const int64_t start_us = esp_timer_get_time();
  TaskHandle_t task = nullptr;
  const BaseType_t created =
      xTaskCreate(task_, "libcoap_bench", STACK_BYTES, this, 1, &task);
  const int64_t end_us = esp_timer_get_time();
  ESP_LOGI(TAG,
           "LIBCOAP_BENCH_STARTUP "
           "{\"run_id\":\"%s\",\"task_created\":%s,\"task_create_ns\":%" PRId64
           ",\"heap_before_task_bytes\":%u,\"stack_reserved_bytes\":%u}",
           run_id_, created == pdPASS ? "true" : "false",
           (end_us - start_us) * 1000, static_cast<unsigned>(heap_before_task),
           STACK_BYTES);
  if (created != pdPASS) {
    ESP_LOGE(TAG,
             "LIBCOAP_BENCH_TERMINAL "
             "{\"passed\":false,\"run_id\":\"%s\",\"completed\":0,\"error\":"
             "\"task_allocation\"}",
             run_id_);
    mark_failed();
  } else {
    // Startup logging must finish before the client enters measured work.
    xTaskNotifyGive(task);
  }
}

void LibcoapBenchmark::task_(void *argument) {
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  static_cast<LibcoapBenchmark *>(argument)->run_();
  vTaskDelete(nullptr);
}

void LibcoapBenchmark::run_() {
#ifdef LIBCOAP_BENCH_SERVER
  if (server_) {
    run_server_();
    return;
  }
#endif
  const int64_t preparation_start_us = esp_timer_get_time();
  const size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  const size_t internal_before =
      heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  auto *context = coap_new_context(nullptr);
  coap_session_t *session = nullptr;
  const char *error = nullptr;
  uint32_t completed = 0;
  Operation operation{};
  operation.identity = reinterpret_cast<const uint8_t *>(server_run_id_);
  if (context == nullptr) {
    error = "context_allocation";
  } else {
    coap_context_set_block_mode(context, COAP_BLOCK_USE_LIBCOAP |
                                             COAP_BLOCK_SINGLE_BODY);
    coap_register_response_handler(context, response);
    coap_register_nack_handler(context, nack);
    coap_address_t destination;
    coap_address_init(&destination);
    destination.addr.sin.sin_family = AF_INET;
    destination.addr.sin.sin_port = htons(peer_port_);
    destination.addr.sin.sin_addr.s_addr = htonl(peer_address_);
    destination.size = sizeof(destination.addr.sin);
    session =
        coap_new_client_session(context, nullptr, &destination, COAP_PROTO_UDP);
    if (session == nullptr) {
      error = "session_allocation";
    } else {
      coap_session_set_mtu(session, 1152);
      coap_session_set_app_data(session, &operation);
    }
  }
  const int64_t preparation_end_us = esp_timer_get_time();
  ESP_LOGI(
      TAG,
      "LIBCOAP_BENCH_PREPARATION "
      "{\"run_id\":\"%s\",\"server_run_id\":\"%s\",\"component\":\"espressif/"
      "coap4.3.5~8\",\"libcoap_version\":\"%s\",\"security\":\"unprotected\","
      "\"io_mode\":\"libcoap-event-loop\",\"operations\":24,\"concurrency\":1,"
      "\"single_body\":true,\"prepare_ns\":%" PRId64 "}",
      run_id_, server_run_id_, coap_package_version(),
      (preparation_end_us - preparation_start_us) * 1000);
  ESP_LOGI(TAG,
           "LIBCOAP_BENCH_MEMORY {\"run_id\":\"%s\","
           "\"heap_before_bytes\":%u,\"heap_ready_bytes\":%u,\"internal_before_"
           "bytes\":%u,\"internal_ready_bytes\":%u,\"tick_ms\":%u}",
           run_id_, static_cast<unsigned>(heap_before),
           static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_8BIT)),
           static_cast<unsigned>(internal_before),
           static_cast<unsigned>(
               heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
           static_cast<unsigned>(portTICK_PERIOD_MS));
  for (uint32_t index = 0; index < OPERATIONS && error == nullptr; ++index) {
    operation.resource = index % 3;
    operation.active = true;
    operation.done = false;
    operation.error = nullptr;
    uint32_t polls = 0;
    const int64_t start_us = esp_timer_get_time();
    if (perform(session, operation)) {
      while (!operation.done && operation.error == nullptr) {
        if (esp_timer_get_time() - start_us >= TIMEOUT_US ||
            polls == POLL_LIMIT) {
          operation.error = "operation_deadline_or_poll_bound";
          break;
        }
        ++polls;
        if (coap_io_process(context, 1) < 0) {
          operation.error = "io_process";
          break;
        }
        if ((polls % 32) == 0 && !operation.done)
          vTaskDelay(1);
      }
    }
    const int64_t end_us = esp_timer_get_time();
    if (end_us - start_us >= TIMEOUT_US && operation.error == nullptr)
      operation.error = "late_response";
    operation.active = false;
    const bool passed = operation.done && operation.error == nullptr;
    if (passed)
      ++completed;
    else
      error = operation.error != nullptr ? operation.error : "incomplete";
    ESP_LOGI(TAG,
             "LIBCOAP_BENCH_OPERATION "
             "{\"passed\":%s,\"run_id\":\"%s\",\"iteration\":%u,\"path\":\"%"
             "s\",\"bytes\":%u,\"start_ns\":%" PRId64 ",\"elapsed_ns\":%" PRId64
             ",\"polls\":%u,\"error\":\"%s\"}",
             passed ? "true" : "false", run_id_, index / 3,
             path(operation.resource),
             static_cast<unsigned>(expected_length(operation.resource)),
             start_us * 1000, (end_us - start_us) * 1000, polls,
             passed ? "" : error);
  }
  const size_t heap_before_cleanup = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  if (session != nullptr)
    coap_session_release(session);
  if (context != nullptr)
    coap_free_context(context);
  coap_cleanup();
  ESP_LOGI(
      TAG,
      "LIBCOAP_BENCH_TERMINAL "
      "{\"passed\":%s,\"run_id\":\"%s\",\"security\":\"unprotected\","
      "\"completed\":%u,\"error\":\"%s\",\"heap_before_cleanup_bytes\":%u,"
      "\"heap_after_cleanup_bytes\":%u,\"global_min_heap_since_boot_bytes\":%u,"
      "\"task_stack_high_water_free_bytes\":%u,\"stack_reserved_bytes\":%u}",
      completed == OPERATIONS && error == nullptr ? "true" : "false", run_id_,
      completed, error != nullptr ? error : "",
      static_cast<unsigned>(heap_before_cleanup),
      static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_8BIT)),
      static_cast<unsigned>(heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT)),
      static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)), STACK_BYTES);
}

#ifdef LIBCOAP_BENCH_SERVER
void LibcoapBenchmark::run_server_() {
  const int64_t preparation_start_us = esp_timer_get_time();
  const size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  auto *context = coap_new_context(nullptr);
  const char *error = nullptr;
  ServerState state{};
  state.peer_address = peer_address_;
  Representation representations[3] = {
      {&state, reinterpret_cast<const uint8_t *>(run_id_), 32},
      {&state, reinterpret_cast<const uint8_t *>("coaptic"), 7},
      {&state, LARGE_REPRESENTATION.data(), LARGE_REPRESENTATION.size()}};
  if (context == nullptr) {
    error = "context_allocation";
  } else {
    coap_context_set_block_mode(context, COAP_BLOCK_USE_LIBCOAP |
                                             COAP_BLOCK_STLESS_BLOCK2);
    coap_context_set_max_idle_sessions(context, 4);
    coap_address_t address;
    coap_address_init(&address);
    address.addr.sin.sin_family = AF_INET;
    address.addr.sin.sin_port = htons(listen_port_);
    address.addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
    address.size = sizeof(address.addr.sin);
    auto *endpoint = coap_new_endpoint(context, &address, COAP_PROTO_UDP);
    if (endpoint == nullptr) {
      error = "server_bind";
    } else {
      coap_endpoint_set_default_mtu(endpoint, 1152);
      for (unsigned index = 0; index < 3 && error == nullptr; ++index) {
        auto *resource =
            coap_resource_init(coap_make_str_const(path(index)), 0);
        if (resource == nullptr) {
          error = "resource_allocation";
          break;
        }
        coap_resource_set_userdata(resource, &representations[index]);
        coap_register_handler(resource, COAP_REQUEST_GET, server_get);
        coap_add_resource(context, resource);
      }
    }
  }
  const int64_t preparation_end_us = esp_timer_get_time();
  ESP_LOGI(
      TAG,
      "LIBCOAP_BENCH_SERVER_MEMORY {\"run_id\":\"%s\",\"prepare_ns\":%" PRId64
      ",\"heap_before_bytes\":%u,\"heap_ready_bytes\":%u,\"stack_reserved_"
      "bytes\":%u}",
      run_id_, (preparation_end_us - preparation_start_us) * 1000,
      static_cast<unsigned>(heap_before),
      static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_8BIT)),
      STACK_BYTES);
  uint32_t polls = 0;
  if (error == nullptr) {
    // No request is dispatched until this readiness record has been emitted.
    ESP_LOGI(
        TAG,
        "LIBCOAP_BENCH_SERVER_READY {\"run_id\":\"%s\",\"role\":\"server\","
        "\"security\":\"unprotected\",\"listen_port\":%u,\"service_ms\":30000,"
        "\"representation\":\"static-borrowed-handler-per-block\"}",
        run_id_, listen_port_);
    const int64_t service_start_us = esp_timer_get_time();
    while (esp_timer_get_time() - service_start_us < 30000000 &&
           state.error == nullptr) {
      if (polls == POLL_LIMIT) {
        error = "server_poll_bound";
        break;
      }
      ++polls;
      if (coap_io_process(context, 10) < 0) {
        error = "server_io_process";
        break;
      }
      if ((polls % 32) == 0)
        vTaskDelay(1);
    }
    if (error == nullptr)
      error = state.error;
  }
  const size_t heap_before_cleanup = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  if (context != nullptr)
    coap_free_context(context);
  coap_cleanup();
  ESP_LOGI(
      TAG,
      "LIBCOAP_BENCH_SERVER_TERMINAL {\"passed\":%s,\"run_id\":\"%s\","
      "\"role\":\"server\",\"handler_calls\":%u,\"refused_peers\":%u,\"polls\":"
      "%u,"
      "\"error\":\"%s\",\"heap_before_cleanup_bytes\":%u,\"heap_after_cleanup_"
      "bytes\":%u,"
      "\"global_min_heap_since_boot_bytes\":%u,\"task_stack_high_water_free_"
      "bytes\":%u}",
      error == nullptr && state.handler_calls > 0 ? "true" : "false", run_id_,
      state.handler_calls, state.refused_peers, polls,
      error != nullptr ? error : "", static_cast<unsigned>(heap_before_cleanup),
      static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_8BIT)),
      static_cast<unsigned>(heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT)),
      static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
}
#endif

} // namespace esphome::libcoap_benchmark

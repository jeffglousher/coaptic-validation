#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
/* Independent libcoap fixture. No Coaptic codecs or library code. */
#include <coap3/coap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

static unsigned counter, upload_accepted, upload_calls;
static int patch_present = 1;
static unsigned patch_n;
static uint8_t cond_body[64];
static size_t cond_len;
static int cond_exists;
static uint8_t cond_etag;
static uint8_t method_body[64];
static size_t method_length;
static int method_exists;
static uint8_t large_body[2000];
static const uint8_t small_body[] = "core-test-payload";
static int complete;
static int observe_mode;
static char observe_joined[192];
static size_t observe_joined_len;
static int observe_count;
static uint8_t pending_token[8];
static size_t pending_token_len;
static uint64_t started;
static uint64_t clock_resolution_ns;
#ifdef _WIN32
static uint64_t clock_frequency;
#define CLOCK_NAME "QueryPerformanceCounter"
#else
#define CLOCK_NAME "CLOCK_MONOTONIC"
#endif


static void failure(const char *message) {
  /* Only fixed diagnostics are passed, never unescaped external strings. */
  printf("{\"schema\":\"coaptic-peer/2\",\"event\":\"error\",\"message\":\"%s\"}\n", message);
}
/* Measure intervals with the OS monotonic clock, independently of libcoap's
 * protocol tick granularity. Capture before payload-to-JSON formatting. */
static void clock_failure(void) {
  failure("monotonic clock unavailable");
  exit(1);
}
static void clock_init(void) {
#ifdef _WIN32
  LARGE_INTEGER frequency;
  if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) clock_failure();
  clock_frequency = (uint64_t)frequency.QuadPart;
  clock_resolution_ns = 1000000000ULL / clock_frequency + (1000000000ULL % clock_frequency != 0);
#else
  struct timespec resolution;
  if (clock_getres(CLOCK_MONOTONIC, &resolution) != 0) clock_failure();
  clock_resolution_ns = (uint64_t)resolution.tv_sec * 1000000000ULL + (uint64_t)resolution.tv_nsec;
#endif
}
static uint64_t clock_stamp(void) {
#ifdef _WIN32
  LARGE_INTEGER value;
  if (!QueryPerformanceCounter(&value)) clock_failure();
  return (uint64_t)value.QuadPart;
#else
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) clock_failure();
  return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
#endif
}
static uint64_t elapsed_ns(void) {
  uint64_t now = clock_stamp();
  if (now < started) clock_failure();
  uint64_t delta = now - started;
#ifdef _WIN32
  return (delta / clock_frequency) * 1000000000ULL +
      (uint64_t)((long double)(delta % clock_frequency) * 1000000000.0L / clock_frequency);
#else
  return delta;
#endif
}
static void get_fixture(coap_resource_t *resource, coap_session_t *session,
                        const coap_pdu_t *request, const coap_string_t *query,
                        coap_pdu_t *response) {
  const coap_str_const_t *path = coap_resource_get_uri_path(resource);
  const uint8_t *body = small_body;
  size_t len = sizeof(small_body)-1;
  char count[32];
  if (path->length == 5 && memcmp(path->s,"large",5)==0) {
    body=large_body; len=sizeof(large_body);
  } else if (path->length == 7 && memcmp(path->s,"counter",7)==0) {
    len=(size_t)snprintf(count,sizeof(count),"%u",counter);body=(const uint8_t *)count;
  }
  coap_pdu_set_code(response,COAP_RESPONSE_CODE_CONTENT);
  if (body == (const uint8_t *)count) {
    coap_add_data(response,len,body);
  } else {
    coap_add_data_large_response(resource,session,request,response,query,
        COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,60,0,len,body,NULL,NULL);
  }
}
static void get_separate(coap_resource_t *resource, coap_session_t *session,
                        const coap_pdu_t *request, const coap_string_t *query,
                        coap_pdu_t *response) {
  (void)resource; (void)query;
  coap_bin_const_t token = coap_pdu_get_token(request);
  coap_async_t *async = coap_find_async(session, token);
  if (!async) {
    /* Leaving the code unset sends an empty ACK. The handler runs again after the delay. */
    if (!coap_register_async(session, request, COAP_TICKS_PER_SECOND))
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_INTERNAL_ERROR);
    return;
  }
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
  coap_add_data(response, sizeof("separate-payload") - 1, (const uint8_t *)"separate-payload");
}
static int cond_precondition(const coap_pdu_t *request) {
  coap_opt_iterator_t it;
  coap_opt_t *opt = coap_check_option(request, COAP_OPTION_IF_MATCH, &it);
  int saw_match = 0, empty = 0, matched = 0;
  while (opt) {
    size_t n = coap_opt_length(opt);
    saw_match = 1;
    if (n == 0) empty = 1;
    else if (cond_exists && n == 1 && coap_opt_value(opt)[0] == cond_etag) matched = 1;
    opt = coap_option_next(&it);
  }
  if (coap_check_option(request, COAP_OPTION_IF_NONE_MATCH, &it) && cond_exists) return 0;
  if (!saw_match) return 1;
  return empty ? cond_exists : matched;
}
static void cond_resource(coap_resource_t *resource, coap_session_t *session,
                        const coap_pdu_t *request, const coap_string_t *query,
                        coap_pdu_t *response) {
  (void)resource; (void)session; (void)query;
  coap_string_t *path = coap_get_uri_path(request);
  int is_cond = path && ((path->length == 4 && memcmp(path->s, "cond", 4) == 0) ||
                         (path->length == 5 && memcmp(path->s, "/cond", 5) == 0));
  if (path) coap_delete_string(path);
  if (!is_cond) { coap_pdu_set_code(response, (coap_pdu_code_t)132); return; }
  unsigned method = (unsigned)coap_pdu_get_code(request);
  size_t len = 0; const uint8_t *data = NULL;
  coap_get_data(request, &len, &data);
  if (!cond_precondition(request)) {
    coap_pdu_set_code(response, (coap_pdu_code_t)140);
    return;
  }
  if (method == 1) {
    if (!cond_exists) { coap_pdu_set_code(response, (coap_pdu_code_t)132); return; }
    coap_pdu_set_code(response, (coap_pdu_code_t)69);
    coap_add_option(response, COAP_OPTION_ETAG, 1, &cond_etag);
    if (cond_len) coap_add_data(response, cond_len, cond_body);
    return;
  }
  if (method == 3) {
    int created = !cond_exists;
    if (len > sizeof(cond_body)) { coap_pdu_set_code(response, (coap_pdu_code_t)141); return; }
    if (len) memcpy(cond_body, data, len);
    cond_len = len;
    cond_exists = 1;
    cond_etag++;
    coap_pdu_set_code(response, (coap_pdu_code_t)(created ? 65 : 68));
    return;
  }
  if (method == 4) {
    if (!cond_exists) { coap_pdu_set_code(response, (coap_pdu_code_t)132); return; }
    cond_exists = 0;
    cond_len = 0;
    coap_pdu_set_code(response, (coap_pdu_code_t)66);
    return;
  }
  coap_pdu_set_code(response, (coap_pdu_code_t)133);
}
static int parse_merge_n(const uint8_t *data, size_t len, int *present, unsigned *value) {
  unsigned n = 0;
  size_t i;
  if (len == 10 && memcmp(data, "{\"n\":null}", 10) == 0) { *present = 0; return 1; }
  if (len < 7 || len > 16 || memcmp(data, "{\"n\":", 5) || data[len - 1] != '}') return 0;
  if (len > 7 && data[5] == '0') return 0;
  for (i = 5; i + 1 < len; i++) {
    if (data[i] < '0' || data[i] > '9') return 0;
    if (n > 429496729u || (n == 429496729u && data[i] > '5')) return 0;
    n = n * 10u + (unsigned)(data[i] - '0');
  }
  *present = 1;
  *value = n;
  return 1;
}
static int parse_json_patch(const uint8_t *data, size_t len, int *remove, unsigned *value) {
  static const char prefix[] = "[{\"op\":\"replace\",\"path\":\"/n\",\"value\":";
  static const char remove_doc[] = "[{\"op\":\"remove\",\"path\":\"/n\"}]";
  const size_t prefix_len = sizeof(prefix) - 1;
  size_t digits, i;
  unsigned n = 0;
  if (len == sizeof(remove_doc) - 1 && memcmp(data, remove_doc, len) == 0) {
    *remove = 1;
    return 1;
  }
  if (len < prefix_len + 3 || memcmp(data, prefix, prefix_len) || data[len - 2] != '}' || data[len - 1] != ']')
    return 0;
  digits = len - prefix_len - 2;
  if (digits == 0 || digits > 10 || (digits > 1 && data[prefix_len] == '0')) return 0;
  for (i = 0; i < digits; i++) {
    unsigned char digit = data[prefix_len + i];
    if (digit < '0' || digit > '9') return 0;
    if (n > 429496729u || (n == 429496729u && digit > '5')) return 0;
    n = n * 10u + (unsigned)(digit - '0');
  }
  *remove = 0;
  *value = n;
  return 1;
}
static void patch_resource(coap_resource_t *resource, coap_session_t *session,
                        const coap_pdu_t *request, const coap_string_t *query,
                        coap_pdu_t *response) {
  (void)resource; (void)session; (void)query;
  unsigned method = (unsigned)coap_pdu_get_code(request);
  char body[24];
  int n;
  if (method == 1) {
    if (!patch_present) { coap_pdu_set_code(response, (coap_pdu_code_t)132); return; }
    n = snprintf(body, sizeof(body), "{\"n\":%u}", patch_n);
    if (n < 0 || (size_t)n >= sizeof(body)) { coap_pdu_set_code(response, (coap_pdu_code_t)160); return; }
    coap_pdu_set_code(response, (coap_pdu_code_t)69);
    const uint8_t format = 50;
    coap_add_option(response, COAP_OPTION_CONTENT_FORMAT, 1, &format);
    coap_add_data(response, (size_t)n, (const uint8_t *)body);
    return;
  }
  if (method == 6) {
    size_t len = 0; const uint8_t *data = NULL;
    coap_opt_iterator_t it;
    coap_opt_t *format = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &it);
    int present = 0; unsigned value = 0; int remove = 0;
    unsigned format_id;
    coap_get_data(request, &len, &data);
    if (!format || coap_opt_length(format) > 2) {
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT); return;
    }
    format_id = coap_decode_var_bytes(coap_opt_value(format), coap_opt_length(format));
    if (format_id == 52) {
      if (!data || !parse_merge_n(data, len, &present, &value)) {
        coap_pdu_set_code(response, (coap_pdu_code_t)128); return;
      }
      patch_present = present;
      patch_n = value;
      coap_pdu_set_code(response, (coap_pdu_code_t)68);
      return;
    }
    if (format_id != 51) {
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT); return;
    }
    if (!data || !parse_json_patch(data, len, &remove, &value)) {
      coap_pdu_set_code(response, (coap_pdu_code_t)128); return;
    }
    if (!patch_present) { coap_pdu_set_code(response, (coap_pdu_code_t)132); return; }
    if (remove) patch_present = 0;
    else patch_n = value;
    coap_pdu_set_code(response, (coap_pdu_code_t)68);
    return;
  }
  coap_pdu_set_code(response, (coap_pdu_code_t)133);
}
static void post_counter(coap_resource_t *resource, coap_session_t *session,
                        const coap_pdu_t *request, const coap_string_t *query,
                        coap_pdu_t *response) {
  (void)session;(void)request;(void)query;
  counter++;coap_pdu_set_code(response,COAP_RESPONSE_CODE_CHANGED);
  coap_resource_notify_observers(resource,NULL);
}
/* Bounded application workflow fixture; each CoAP stack owns its wire parsing. */
static void method_resource(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response) {
  (void)resource; (void)session; (void)query;
  unsigned method = (unsigned)coap_pdu_get_code(request);
  size_t len = 0; const uint8_t *data = NULL;
  coap_get_data(request, &len, &data);
  unsigned code = 68;
  if (method == 2 || method == 3 || method == 5 || method == 6 || method == 7) {
    coap_opt_iterator_t it;
    coap_opt_t *format = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &it);
    if (!format || coap_opt_length(format) > 2 || coap_decode_var_bytes(coap_opt_value(format), coap_opt_length(format)) != 42) {
      coap_pdu_set_code(response, COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT); return;
    }
  }
  if (len > sizeof(method_body)) { coap_pdu_set_code(response, COAP_RESPONSE_CODE_REQUEST_TOO_LARGE); return; }
  if (method == 1 || method == 5) {
    if (method == 5 && (len != 5 || memcmp(data, "value", 5))) code = 128;
    else if (!method_exists) code = 132;
    else { code = 69; if (method_length) coap_add_data(response, method_length, method_body); }
  } else if (method == 3) {
    code = method_exists ? 68 : 65;
    if (len) memcpy(method_body, data, len);
    method_length = len; method_exists = 1;
  } else if (method == 4) {
    code = method_exists ? 66 : 132;
    method_exists = 0; method_length = 0;
  } else if (method == 2 || method == 6 || method == 7) {
    if (!method_exists) code = 132;
    else if ((method == 6 && (!len || data[0] != '+')) || (method == 7 && (!len || data[0] != '='))) code = 128;
    else {
      size_t skip = method == 2 ? 0 : 1;
      size_t keep = method == 7 ? 0 : method_length;
      if (keep + len - skip > sizeof(method_body)) code = 141;
      else {
        if (len > skip) memcpy(method_body + keep, data + skip, len - skip);
        method_length = keep + len - skip;
      }
    }
  } else code = 133;
  coap_pdu_set_code(response, (coap_pdu_code_t)code);
}
static void upload_resource(coap_resource_t *resource, coap_session_t *session,
    const coap_pdu_t *request, const coap_string_t *query, coap_pdu_t *response) {
  (void)resource; (void)session; (void)query;
  if(coap_pdu_get_code(request) == COAP_REQUEST_CODE_GET) {
    char counts[48];
    int n = snprintf(counts, sizeof(counts), "%u:%u", upload_accepted, upload_calls);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data(response, (size_t)n, (const uint8_t *)counts);
    return;
  }
  upload_calls++;
  size_t length = 0; const uint8_t *data = NULL;
  coap_get_data(request, &length, &data);
  coap_opt_iterator_t it;
  coap_opt_t *format = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &it);
  if(!format || coap_opt_length(format) > 2 || coap_decode_var_bytes(coap_opt_value(format), coap_opt_length(format)) != 42) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT); return;
  }
  if(length != 2000 && length != 4096) { coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST); return; }
  for(size_t i=0;i<length;i++) if(data[i] != i % 251) { coap_pdu_set_code(response, COAP_RESPONSE_CODE_BAD_REQUEST); return; }
  upload_accepted++;
  coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
}
static int hex_digit(char c) {
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static coap_response_t response_handler(coap_session_t *session,
    const coap_pdu_t *sent,const coap_pdu_t *received,const coap_mid_t mid) {
  (void)session;(void)sent;(void)mid;
  /* libcoap's Q-Block probe is a separate GET /.well-known/core. Ignore it. */
  coap_bin_const_t token = coap_pdu_get_token(received);
  if(token.length != pending_token_len || memcmp(token.s, pending_token, pending_token_len) != 0)
    return COAP_RESPONSE_OK;
  const uint8_t *data=NULL;size_t len=0,offset=0,total=0;
  coap_get_data_large(received,&len,&data,&offset,&total);
  if (offset || total>len) return COAP_RESPONSE_FAIL;
  if(observe_mode) {
    if(observe_count >= 3) return COAP_RESPONSE_OK;
    if(observe_count && observe_joined_len + 1 < sizeof(observe_joined))
      observe_joined[observe_joined_len++] = ',';
    if(observe_joined_len + len >= sizeof(observe_joined)) return COAP_RESPONSE_FAIL;
    if(len && data) memcpy(observe_joined + observe_joined_len, data, len);
    observe_joined_len += len;
    if(++observe_count < 3) return COAP_RESPONSE_OK;
    data = (const uint8_t *)observe_joined;
    len = observe_joined_len;
  }
  uint64_t elapsed = elapsed_ns();
  printf("{\"schema\":\"coaptic-peer/2\",\"event\":\"response\",\"code\":%u,\"payload_hex\":\"",(unsigned)coap_pdu_get_code(received));
  for(size_t i=0;i<len;i++)printf("%02x",data[i]);
  printf("\",\"elapsed_ns\":%llu,\"elapsed_us\":%.3f,\"clock\":{\"name\":\"%s\",\"resolution_ns\":%llu}}\n",
      (unsigned long long)elapsed, (double)elapsed / 1000.0, CLOCK_NAME,
      (unsigned long long)clock_resolution_ns);
  complete=1;return COAP_RESPONSE_OK;
}
static coap_oscore_conf_t *oscore_config(int server, int wrong_key, uint64_t sequence) {
  char conf[512];
  int length = snprintf(conf, sizeof(conf),
    "master_secret,hex,\"%s\"\nmaster_salt,hex,\"9e7ca92223786340\"\n"
    "sender_id,hex,\"%s\"\nrecipient_id,hex,\"%s\"\n"
    "replay_window,integer,32\naead_alg,integer,10\nhkdf_alg,integer,-10\nssn_freq,integer,1\n",
    wrong_key ? "fe02030405060708090a0b0c0d0e0f10" : "0102030405060708090a0b0c0d0e0f10",
    server ? "01" : "", server ? "" : "01");
  if(length < 0 || (size_t)length >= sizeof(conf)) return NULL;
  coap_str_const_t text = {(size_t)length, (const uint8_t *)conf};
  return coap_new_oscore_conf(text, NULL, NULL, sequence);
}

int main(int argc,char **argv) {
  setvbuf(stdout,NULL,_IONBF,0);
  int q_block1 = 0, q_block2 = 0, observe = 0, json_patch = 0;
  while(argc > 8 && (!strcmp(argv[argc-1],"qblock1") || !strcmp(argv[argc-1],"qblock2") || !strcmp(argv[argc-1],"observe") || !strcmp(argv[argc-1],"jsonpatch"))) {
    if(!strcmp(argv[argc-1],"qblock1")) q_block1 = 1;
    else if(!strcmp(argv[argc-1],"qblock2")) q_block2 = 1;
    else if(!strcmp(argv[argc-1],"observe")) observe = 1;
    else json_patch = 1;
    argc--;
  }
  const int q_block = q_block1 || q_block2;
  observe_mode = observe;
  if(argc<8 || argc>11){failure("invalid arguments");return 2;}
  const char *family = argc >= 9 ? argv[8] : "ipv4";
  if(strcmp(family,"ipv4") && strcmp(family,"ipv6")){failure("invalid address family");return 2;}
  const int ipv6 = strcmp(family,"ipv6")==0;
  const int server=strcmp(argv[1],"server")==0,dtls=strcmp(argv[2],"dtls")==0;
  const int oscore=strcmp(argv[2],"oscore")==0;
  if ((!server && strcmp(argv[1],"client")) || (!dtls && !oscore && strcmp(argv[2],"udp"))) {failure("invalid mode");return 2;}
  char *end=NULL;long port=strtol(argv[3],&end,10);
  if(*end || port<1 || port>65535){failure("invalid port");return 2;}
  long timeout=strtol(argv[7],&end,10);
  if(*end || timeout<100 || timeout>30000){failure("invalid timeout");return 2;}
  if(strcmp(argv[5],"test") && strcmp(argv[5],"large") && strcmp(argv[5],"counter") && strcmp(argv[5],"missing") && strcmp(argv[5],"methods") && strcmp(argv[5],"upload") && strcmp(argv[5],"separate") && strcmp(argv[5],"patch")){failure("unsupported path");return 2;}
  const char *methods[] = {"GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "IPATCH"};
  unsigned method = 0;
  for(unsigned i = 0; i < 7; i++) if(!strcmp(argv[6], methods[i])) method = i + 1;
  if(!method) { failure("unsupported method"); return 2; }
  const char *hex = argc >= 10 ? argv[9] : "";
  size_t payload_length = strlen(hex) / 2;
  uint8_t payload[4096];
  if(strlen(hex) % 2 || payload_length > sizeof(payload)) { failure("invalid bounded payload hex"); return 2; }
  for(size_t i = 0; i < payload_length; i++) {
    int hi = hex_digit(hex[i*2]), lo = hex_digit(hex[i*2+1]);
    if(hi < 0 || lo < 0) { failure("invalid bounded payload hex"); return 2; }
    payload[i] = (uint8_t)(hi*16 + lo);
  }
  if(strlen(argv[4])<1 || strlen(argv[4])>64){failure("invalid PSK length");return 2;}
  uint64_t sequence=0;
  if(argc==11) {
    if(!argv[10][0] || strspn(argv[10],"0123456789")!=strlen(argv[10]) || strlen(argv[10])>13) { failure("invalid sequence");return 2; }
    sequence=strtoull(argv[10],&end,10);
    if(*end || sequence >= (1ULL<<40)) { failure("invalid sequence");return 2; }
  }
  clock_init();started=clock_stamp();
  coap_startup();coap_set_log_level(COAP_LOG_EMERG);
  if(dtls && !coap_dtls_is_supported()){failure("DTLS unavailable in libcoap build");coap_cleanup();return 2;}
  if(oscore && !coap_oscore_is_supported()){failure("OSCORE unavailable in libcoap build");coap_cleanup();return 2;}
  if(q_block && !coap_q_block_is_supported()){failure("Q-Block unavailable in libcoap build");coap_cleanup();return 2;}
  for(size_t i=0;i<sizeof(large_body);i++)large_body[i]=(uint8_t)(i%251);
  coap_context_t *ctx=coap_new_context(NULL);
  if(!ctx){failure("context failed");coap_cleanup();return 1;}
  /* A server with Q-Block answers Q-Block requests and still serves classic Block. */
  const int try_q_block=(server||q_block)&&coap_q_block_is_supported();
  coap_context_set_block_mode(ctx,COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY|(try_q_block?COAP_BLOCK_TRY_Q_BLOCK:0));
  coap_address_t addr;coap_address_init(&addr);
  if(ipv6) {
    addr.addr.sin6.sin6_family=AF_INET6;
    addr.addr.sin6.sin6_addr.s6_addr[15]=1;
    addr.addr.sin6.sin6_port=htons((uint16_t)port);
    addr.size=sizeof(addr.addr.sin6);
  } else {
    addr.addr.sin.sin_family=AF_INET;addr.addr.sin.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.addr.sin.sin_port=htons((uint16_t)port);addr.size=sizeof(addr.addr.sin);
  }
  coap_proto_t proto=dtls?COAP_PROTO_DTLS:COAP_PROTO_UDP;
  int status=0;
  coap_oscore_conf_t *oscore_conf=oscore?oscore_config(server,strcmp(argv[4],"sesame")!=0,sequence):NULL;
  if(oscore && !oscore_conf) { failure("OSCORE configuration failed");status=1;goto done; }
  if(server) {
    if(oscore && !coap_context_oscore_server(ctx,oscore_conf)) { failure("OSCORE configuration failed");status=1;goto done; }
    if(dtls && !coap_context_set_psk(ctx,"password",(const uint8_t *)argv[4],(unsigned)strlen(argv[4]))){failure("PSK setup failed");status=1;goto done;}
    if(!coap_new_endpoint(ctx,&addr,proto)){failure("bind failed");status=1;goto done;}
    const char *paths[]={"test","large","counter"};
    for(size_t i=0;i<3;i++) {
      coap_resource_t *r=coap_resource_init(coap_make_str_const(paths[i]),oscore?COAP_RESOURCE_FLAGS_OSCORE_ONLY:0);
      coap_register_handler(r,COAP_REQUEST_GET,get_fixture);
      if(i==2){coap_register_handler(r,COAP_REQUEST_POST,post_counter);coap_resource_set_get_observable(r,1);}
      coap_add_resource(ctx,r);
    }
    coap_resource_t *methods_resource = coap_resource_init(coap_make_str_const("methods"), oscore?COAP_RESOURCE_FLAGS_OSCORE_ONLY:0);
    for(unsigned i = 1; i <= 7; i++) coap_register_handler(methods_resource, (coap_request_t)i, method_resource);
    coap_add_resource(ctx, methods_resource);
    coap_resource_t *upload = coap_resource_init(coap_make_str_const("upload"), oscore?COAP_RESOURCE_FLAGS_OSCORE_ONLY:0);
    coap_register_handler(upload, COAP_REQUEST_GET, upload_resource);
    coap_register_handler(upload, COAP_REQUEST_POST, upload_resource);
    coap_add_resource(ctx, upload);
    coap_resource_t *patch = coap_resource_init(coap_make_str_const("patch"), oscore?COAP_RESOURCE_FLAGS_OSCORE_ONLY:0);
    coap_register_handler(patch, COAP_REQUEST_GET, patch_resource);
    coap_register_handler(patch, (coap_request_t)6, patch_resource);
    coap_add_resource(ctx, patch);
    coap_resource_t *separate = coap_resource_init(coap_make_str_const("separate"), oscore?COAP_RESOURCE_FLAGS_OSCORE_ONLY:0);
    coap_register_handler(separate, COAP_REQUEST_GET, get_separate);
    coap_add_resource(ctx, separate);
    coap_resource_t *unknown = coap_resource_unknown_init(cond_resource);
    coap_register_handler(unknown, COAP_REQUEST_GET, cond_resource);
    coap_register_handler(unknown, COAP_REQUEST_DELETE, cond_resource);
    coap_add_resource(ctx, unknown);
    printf("{\"schema\":\"coaptic-peer/2\",\"event\":\"ready\",\"peer\":\"libcoap\",\"stack\":\"libcoap %s\",\"port\":%ld,\"transport\":\"%s\"}\n",LIBCOAP_PACKAGE_VERSION,port,oscore?"oscore":dtls?"dtls":"udp");
    while(coap_io_process(ctx,100)>=0) {}
    status=1;
  } else {
    coap_session_t *session=oscore?coap_new_client_session_oscore(ctx,NULL,&addr,proto,oscore_conf):dtls?coap_new_client_session_psk(ctx,NULL,&addr,proto,"password",(const uint8_t *)argv[4],(unsigned)strlen(argv[4])):coap_new_client_session(ctx,NULL,&addr,proto);
    if(!session){failure("session failed");status=1;goto done;}
    coap_register_response_handler(ctx,response_handler);
    coap_pdu_t *pdu=coap_new_pdu(COAP_MESSAGE_CON,(coap_pdu_code_t)method,session);
    if(!pdu){failure("PDU allocation failed");coap_session_release(session);status=1;goto done;}
    uint8_t token[8];size_t token_len=sizeof(token);coap_session_new_token(session,&token_len,token);
    memcpy(pending_token, token, token_len); pending_token_len = token_len;
    if(!coap_add_token(pdu,token_len,token)){coap_delete_pdu(pdu);failure("PDU construction failed");coap_session_release(session);status=1;goto done;}
    if(observe && !coap_add_option(pdu,COAP_OPTION_OBSERVE,0,(const uint8_t *)"")){coap_delete_pdu(pdu);failure("Observe option failed");coap_session_release(session);status=1;goto done;}
    if(!coap_add_option(pdu,COAP_OPTION_URI_PATH,strlen(argv[5]),(const uint8_t *)argv[5])){coap_delete_pdu(pdu);failure("PDU construction failed");coap_session_release(session);status=1;goto done;}
    if((!strcmp(argv[5], "methods") || !strcmp(argv[5], "upload")) && (method == 2 || method == 3 || method == 5 || method == 6 || method == 7)) {
      const uint8_t format = 42;
      if(!coap_add_option(pdu, COAP_OPTION_CONTENT_FORMAT, 1, &format)) { coap_delete_pdu(pdu); failure("format option failed"); coap_session_release(session); status=1; goto done; }
    }
    if(!strcmp(argv[5], "patch") && method == 6) {
      const uint8_t format = json_patch ? 51 : 52;
      if(!coap_add_option(pdu, COAP_OPTION_CONTENT_FORMAT, 1, &format)) { coap_delete_pdu(pdu); failure("format option failed"); coap_session_release(session); status=1; goto done; }
    }
    if(q_block2) {
      /* NUM=0, M=0, SZX=6. libcoap sets M after the Q-Block probe. */
      const uint8_t qblock2 = 0x06;
      if(!coap_add_option(pdu, COAP_OPTION_Q_BLOCK2, 1, &qblock2)) { coap_delete_pdu(pdu); failure("Q-Block2 option failed"); coap_session_release(session); status=1; goto done; }
    }
    if(payload_length && !coap_add_data_large_request(session, pdu, payload_length, payload, NULL, NULL)) { coap_delete_pdu(pdu); failure("payload failed"); coap_session_release(session); status=1; goto done; }
    if(coap_send(session,pdu)==COAP_INVALID_MID){failure("send failed");status=1;} else {
      while(!complete) {if(elapsed_ns()>=(uint64_t)timeout*1000000ULL)break;if(coap_io_process(ctx,10)<0)break;}
      if(!complete){failure("request timed out");status=1;}
    }
    coap_session_release(session);
  }
done:coap_free_context(ctx);coap_cleanup();return status;
}

/* Opt-in host-fixture observations, never a TLS policy override. */
#ifdef COAPTIC_OPENSSL_DIAGNOSTICS
#include <openssl/ssl.h>
#endif

static unsigned diagnostic_rows;
static int diagnostic_enabled;

static int diagnostic_room(void) {
  if (diagnostic_rows < 32) {
    diagnostic_rows++;
    return 1;
  }
  if (diagnostic_rows == 32) {
    diagnostic_rows++;
    fputs("{\"diagnostic\":\"overflow\"}\n", stderr);
    fflush(stderr);
  }
  return 0;
}

static void diagnostic_log(coap_log_t level, const char *message) {
  /* Never forward backend text: it can include identities, paths or packets.
   * These fixed categories are observations, not a root-cause classifier. */
  static const char *reasons[] = {
    "no shared cipher", "no ciphers available", "unsupported protocol",
    "no suitable signature algorithm", "bad record mac", "decryption failed",
    "psk identity not found", "insufficient security", "handshake failure"
  };
  static const char *descriptions[] = {
    "handshake failure", "insufficient security", "protocol version",
    "bad record mac", "decrypt error", "unknown PSK identity", "close notify"
  };
  const char *reason = "unclassified-suppressed", *direction = "unknown";
  const char *description = "unclassified-suppressed";
  size_t i;
  (void)level;
  if (!diagnostic_room()) return;
  if (strstr(message, "SSL3 alert ")) {
    if (strstr(message, "SSL3 alert read:")) direction = "read";
    if (strstr(message, "SSL3 alert write:")) direction = "write";
    for (i = 0; i < sizeof(descriptions)/sizeof(descriptions[0]); i++) {
      if (strstr(message, descriptions[i])) { description = descriptions[i]; break; }
    }
    fprintf(stderr, "{\"diagnostic\":\"alert\",\"direction\":\"%s\",\"description\":\"%s\"}\n",
            direction, description);
  } else {
    for (i = 0; i < sizeof(reasons)/sizeof(reasons[0]); i++) {
      if (strstr(message, reasons[i])) { reason = reasons[i]; break; }
    }
    fprintf(stderr, "{\"diagnostic\":\"reason\",\"reason\":\"%s\"}\n", reason);
  }
  fflush(stderr);
}

static int diagnostic_event(coap_session_t *session, const coap_event_t event) {
  const char *name;
  int security_level = -1;
  if (event == COAP_EVENT_DTLS_ERROR) name = "dtls-error";
  else if (event == COAP_EVENT_DTLS_CONNECTED) name = "dtls-connected";
  else if (event == COAP_EVENT_SERVER_SESSION_NEW) name = "server-session-new";
  else return 0;
  if (!diagnostic_room()) return 0;
#ifdef COAPTIC_OPENSSL_DIAGNOSTICS
  {
    coap_tls_library_t library = COAP_TLS_LIBRARY_NOTLS;
    void *native = coap_session_get_tls(session, &library);
    if (native && library == COAP_TLS_LIBRARY_OPENSSL)
      security_level = SSL_get_security_level((const SSL *)native);
  }
#else
  (void)session;
#endif
  if (security_level >= 0)
    fprintf(stderr, "{\"diagnostic\":\"session\",\"event\":\"%s\",\"security_level\":%d}\n",
            name, security_level);
  else
    fprintf(stderr, "{\"diagnostic\":\"session\",\"event\":\"%s\",\"security_level\":null}\n", name);
  fflush(stderr);
  return 0;
}

static void diagnostic_start(int dtls) {
  const char *setting = getenv("COAPTIC_DTLS_DIAGNOSTICS");
  diagnostic_enabled = dtls && setting && strcmp(setting, "1") == 0;
  if (diagnostic_enabled) {
    coap_tls_version_t *version = coap_get_tls_library_version();
    if (diagnostic_room()) {
      if (version)
        fprintf(stderr, "{\"diagnostic\":\"backend\",\"library\":%d,\"runtime_version\":%llu,\"built_version\":%llu}\n",
                (int)version->type, (unsigned long long)version->version,
                (unsigned long long)version->built_version);
      else
        fputs("{\"diagnostic\":\"backend-unavailable\"}\n", stderr);
      fflush(stderr);
    }
    coap_set_log_handler(diagnostic_log);
    coap_set_log_level(COAP_LOG_WARN);
    coap_dtls_set_log_level(COAP_LOG_WARN);
  }
}

#include <coap3/coap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *body;
static size_t body_size;

static int read_credentials(const char *path, uint8_t material[24]) {
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    size_t n = fread(material, 1, 24, file);
    int trailing = fgetc(file);
    int valid = n == 24 && trailing == EOF && !ferror(file);
    fclose(file);
    return valid;
}

static coap_oscore_conf_t *oscore_configuration(const uint8_t material[24]) {
    /* Credentials are fresh per cell. Retain libcoap's authenticated Echo
     * initialization of the recipient replay window; the matched driver
     * completes this setup before warmup and measured operations. */
    static const char digits[] = "0123456789abcdef";
    char secret[33], salt[17], conf[512];
    for (size_t i = 0; i < 16; ++i) {
        secret[2 * i] = digits[material[i] >> 4];
        secret[2 * i + 1] = digits[material[i] & 15];
    }
    secret[32] = 0;
    for (size_t i = 0; i < 8; ++i) {
        salt[2 * i] = digits[material[16 + i] >> 4];
        salt[2 * i + 1] = digits[material[16 + i] & 15];
    }
    salt[16] = 0;
    int n = snprintf(conf, sizeof(conf),
        "master_secret,hex,\"%s\"\nmaster_salt,hex,\"%s\"\n"
        "sender_id,hex,\"01\"\nrecipient_id,hex,\"\"\n"
        "replay_window,integer,32\naead_alg,integer,10\nhkdf_alg,integer,-10\nssn_freq,integer,1\n",
        secret, salt);
    if (n < 0 || (size_t)n >= sizeof(conf)) return NULL;
    coap_str_const_t text = {(size_t)n, (const uint8_t *)conf};
    return coap_new_oscore_conf(text, NULL, NULL, 0);
}

static void representation(coap_resource_t *resource, coap_session_t *session,
                           const coap_pdu_t *request, const coap_string_t *query,
                           coap_pdu_t *response) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response, query,
        /* The immutable fixture is determined uniquely by its length. Supply
         * its nonzero validator instead of hashing the body per transfer.
         * -1 omits Max-Age's already implicit 60-second default. */
        COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, -1, (uint64_t)body_size,
        body_size, body, NULL, NULL);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--security-profile") == 0) {
        coap_startup();
        printf("{\"oscore\":%s,\"dtls\":%s}\n",
            coap_oscore_is_supported() ? "true" : "false",
            coap_dtls_is_supported() ? "true" : "false");
        coap_cleanup();
        return 0;
    }
    if (argc != 4 && argc != 6) {
        fprintf(stderr, "bench-libcoap HOST PORT BYTES [oscore|dtls CREDENTIALS]\n");
        return 2;
    }
    int oscore = argc == 6 && strcmp(argv[4], "oscore") == 0;
    int dtls = argc == 6 && strcmp(argv[4], "dtls") == 0;
    if (argc == 6 && !oscore && !dtls) return 2;
    uint8_t material[24] = {0};
    if (argc == 6 && !read_credentials(argv[5], material)) return 2;
    char *end;
    unsigned long size = strtoul(argv[3], &end, 10);
    if (*end || size < 1 || size > 1048576) return 2;
    unsigned long port = strtoul(argv[2], &end, 10);
    if (*end || port < 1 || port > 65535) return 2;
    if (strcmp(argv[1], "127.0.0.1") != 0) return 2;
    body_size = (size_t)size;
    body = malloc(body_size);
    if (!body) return 2;
    for (size_t index = 0; index < body_size; ++index) body[index] = (unsigned char)(index % 251);
    coap_startup();
    coap_set_log_level(COAP_LOG_ERR);
    if ((oscore && !coap_oscore_is_supported()) || (dtls && !coap_dtls_is_supported())) {
        fprintf(stderr, "requested native security is unavailable in this libcoap build\n");
        return 2;
    }
    coap_context_t *context = coap_new_context(NULL);
    if (!context) return 2;
    coap_context_set_block_mode(context, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
    coap_address_t address;
    coap_address_init(&address);
    address.addr.sin.sin_family = AF_INET;
    address.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.addr.sin.sin_port = htons((uint16_t)port);
    if (oscore) {
        coap_oscore_conf_t *conf = oscore_configuration(material);
        if (!conf || !coap_context_oscore_server(context, conf)) return 2;
    }
    if (dtls && !coap_context_set_psk(context, "benchmark", material, 16)) return 2;
    /* libcoap retains the PSK pointer for future DTLS sessions. The main
     * stack frame owns it until the context and all sessions are released. */
    if (!dtls) memset(material, 0, sizeof(material));
    if (!coap_new_endpoint(context, &address, dtls ? COAP_PROTO_DTLS : COAP_PROTO_UDP)) return 2;
    coap_resource_t *resource = coap_resource_init(coap_make_str_const("bench"),
        oscore ? COAP_RESOURCE_FLAGS_OSCORE_ONLY : 0);
    if (!resource) return 2;
    coap_register_handler(resource, COAP_REQUEST_GET, representation);
    coap_add_resource(context, resource);
    while (coap_io_process(context, COAP_IO_WAIT) >= 0) {}
    coap_free_context(context);
    memset(material, 0, sizeof(material));
    coap_cleanup();
    free(body);
    return 1;
}

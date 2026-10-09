#include <coap3/coap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *body;
static size_t body_size;

static void representation(coap_resource_t *resource, coap_session_t *session,
                           const coap_pdu_t *request, const coap_string_t *query,
                           coap_pdu_t *response) {
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response, query,
        COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, 60, 0, body_size, body, NULL, NULL);
}

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "bench-libcoap HOST PORT BYTES\n"); return 2; }
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
    coap_context_t *context = coap_new_context(NULL);
    if (!context) return 2;
    coap_context_set_block_mode(context, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
    coap_address_t address;
    coap_address_init(&address);
    address.addr.sin.sin_family = AF_INET;
    address.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.addr.sin.sin_port = htons((uint16_t)port);
    if (!coap_new_endpoint(context, &address, COAP_PROTO_UDP)) return 2;
    coap_resource_t *resource = coap_resource_init(coap_make_str_const("bench"), 0);
    if (!resource) return 2;
    coap_register_handler(resource, COAP_REQUEST_GET, representation);
    coap_add_resource(context, resource);
    while (coap_io_process(context, COAP_IO_WAIT) >= 0) {}
    coap_free_context(context);
    coap_cleanup();
    free(body);
    return 1;
}

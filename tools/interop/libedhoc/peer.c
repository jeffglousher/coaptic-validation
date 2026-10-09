#include <edhoc/edhoc.h>
#include <edhoc/cipher_suite.h>
#include <psa/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESSAGE_CAPACITY 192
#define CREDENTIAL_CAPACITY 82

struct identity {
    uint8_t kid;
    uint8_t credential[CREDENTIAL_CAPACITY];
    uint8_t public_x[32];
    psa_key_id_t private_key;
};
struct peer_policy {
    struct identity local;
    struct identity expected;
    unsigned int authenticated;
};

static void wipe(void *buffer, size_t length)
{
    volatile unsigned char *position = buffer;
    while (length-- != 0) *position++ = 0;
}

static void fail(const char *phase, int error)
{
    fprintf(stderr, "%s failed: %d\n", phase, error);
    printf("{\"error\":\"%s\",\"code\":%d}\n", phase, error);
    fflush(stdout);
    exit(1);
}

static void check(const char *phase, int result)
{
    if (result != EDHOC_SUCCESS) fail(phase, result);
}

static void identity_init(struct identity *identity, uint8_t kid, uint8_t scalar)
{
    uint8_t secret[32] = {0};
    uint8_t public_key[65] = {0};
    size_t public_length = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    secret[31] = scalar;
    identity->kid = kid;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    check("identity-import", psa_import_key(&attributes, secret, sizeof(secret), &identity->private_key));
    wipe(secret, sizeof(secret));
    psa_reset_key_attributes(&attributes);
    check("public-export", psa_export_public_key(identity->private_key, public_key, sizeof(public_key), &public_length));
    if (public_length != sizeof(public_key) || public_key[0] != 4) fail("public-format", -1);
    const uint8_t prefix[] = {0xa1,0x08,0xa1,0x01,0xa5,0x01,0x02,0x02,0x41,0,0x20,0x01,0x21,0x58,0x20};
    memcpy(identity->credential, prefix, sizeof(prefix));
    identity->credential[9] = kid;
    memcpy(identity->credential + sizeof(prefix), public_key + 1, 32);
    identity->credential[47] = 0x22;
    identity->credential[48] = 0x58;
    identity->credential[49] = 0x20;
    memcpy(identity->credential + 50, public_key + 33, 32);
    memcpy(identity->public_x, public_key + 1, 32);
}

static int select_local(void *context, const struct edhoc_call_context *call,
                        struct edhoc_credential_selected *selected)
{
    struct peer_policy *policy = context;
    if (call->method != EDHOC_METHOD_3 || call->selected_cipher_suite != 2) return EDHOC_ERROR_CREDENTIALS_FAILURE;
    selected->asymmetric.label = EDHOC_COSE_HEADER_KID;
    selected->asymmetric.kid.identifier.value = &policy->local.kid;
    selected->asymmetric.kid.identifier.length = 1;
    selected->asymmetric.kid.credential.value = policy->local.credential;
    selected->asymmetric.kid.credential.length = sizeof(policy->local.credential);
    selected->asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
    _Static_assert(sizeof(psa_key_id_t) == CONFIG_LIBEDHOC_KEY_ID_LEN, "key handle layout");
    memcpy(selected->asymmetric.private_key_id, &policy->local.private_key, sizeof(psa_key_id_t));
    return EDHOC_SUCCESS;
}

static int authenticate_peer(void *context, const struct edhoc_call_context *call,
                             const struct edhoc_credential_received *received,
                             struct edhoc_credential_trusted *trusted)
{
    struct peer_policy *policy = context;
    if (call->method != EDHOC_METHOD_3 || call->selected_cipher_suite != 2 ||
        received->label != EDHOC_COSE_HEADER_KID || received->kid.identifier.length != 1 ||
        received->kid.identifier.value[0] != policy->expected.kid) return EDHOC_ERROR_CREDENTIALS_FAILURE;
    trusted->asymmetric.credential.value = policy->expected.credential;
    trusted->asymmetric.credential.length = sizeof(policy->expected.credential);
    trusted->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
    trusted->asymmetric.public_key.value = policy->expected.public_x;
    trusted->asymmetric.public_key.length = sizeof(policy->expected.public_x);
    policy->authenticated++;
    return EDHOC_SUCCESS;
}

static void print_hex(const uint8_t *bytes, size_t length)
{
    for (size_t index = 0; index < length; index++) printf("%02x", bytes[index]);
}

static void emit_message(unsigned int number, const uint8_t *bytes, size_t length)
{
    printf("{\"message\":%u,\"hex\":\"", number);
    print_hex(bytes, length);
    printf("\"}\n");
    fflush(stdout);
}

static unsigned int digit(char character)
{
    if (character >= '0' && character <= '9') return (unsigned int)(character - '0');
    if (character >= 'a' && character <= 'f') return (unsigned int)(character - 'a' + 10);
    if (character >= 'A' && character <= 'F') return (unsigned int)(character - 'A' + 10);
    fail("hex-digit", -1);
    return 0;
}

static size_t read_message(uint8_t bytes[MESSAGE_CAPACITY])
{
    char line[2 * MESSAGE_CAPACITY + 3];
    if (fgets(line, sizeof(line), stdin) == NULL) fail("input-eof", -1);
    size_t length = strcspn(line, "\r\n");
    if (length == 0 || length > 2 * MESSAGE_CAPACITY || length % 2 != 0 ||
        (line[length] == 0 && !feof(stdin))) fail("input-length", -1);
    for (size_t index = 0; index < length / 2; index++)
        bytes[index] = (uint8_t)((digit(line[2 * index]) << 4) | digit(line[2 * index + 1]));
    return length / 2;
}

static void export_result(struct edhoc_context *context, const struct peer_policy *policy)
{
    uint8_t secret[16], salt[8], sender[1], recipient[1];
    size_t sender_length = 0, recipient_length = 0;
    if (policy->authenticated != 1) fail("pin-authentication-count", -1);
    check("oscore-export", edhoc_export_oscore_context_raw(context, secret, sizeof(secret), salt,
          sizeof(salt), sender, sizeof(sender), &sender_length, recipient, sizeof(recipient), &recipient_length));
    printf("{\"master_secret\":\""); print_hex(secret, sizeof(secret));
    printf("\",\"master_salt\":\""); print_hex(salt, sizeof(salt));
    printf("\",\"sender_id\":\""); print_hex(sender, sender_length);
    printf("\",\"recipient_id\":\""); print_hex(recipient, recipient_length);
    printf("\",\"peer_credential\":\""); print_hex(policy->expected.credential, sizeof(policy->expected.credential));
    printf("\",\"local_credential\":\""); print_hex(policy->local.credential, sizeof(policy->local.credential));
    printf("\",\"method\":3,\"suite\":2,\"message4\":true}\n");
    fflush(stdout);
    wipe(secret, sizeof(secret)); wipe(salt, sizeof(salt));
}

int main(int argc, char **argv)
{
    if (argc < 2 ||
        (strcmp(argv[1], "initiator") != 0 && strcmp(argv[1], "responder") != 0)) {
        fprintf(stderr, "usage: libedhoc-peer initiator|responder [wrong-identity] [--cid 0..23]\n");
        return 2;
    }
    const int initiator = strcmp(argv[1], "initiator") == 0;
    int wrong_identity = 0, cid_supplied = 0;
    uint8_t cid = initiator ? 0 : 1;
    for (int index = 2; index < argc; index++) {
        if (strcmp(argv[index], "wrong-identity") == 0 && !wrong_identity) {
            wrong_identity = 1;
        } else if (strcmp(argv[index], "--cid") == 0 && !cid_supplied && index + 1 < argc) {
            char *end = NULL;
            const char *value = argv[++index];
            unsigned long parsed = strtoul(value, &end, 10);
            if (*value == 0 || *end != 0 || parsed > 23 || value[0] < '0' || value[0] > '9') return 2;
            cid = (uint8_t)parsed;
            cid_supplied = 1;
        } else {
            return 2;
        }
    }
    struct peer_policy policy = {0};
    check("psa-init", psa_crypto_init());
    identity_init(&policy.local, initiator ? 0 : 1, wrong_identity ? 3 : (initiator ? 1 : 2));
    identity_init(&policy.expected, initiator ? 1 : 0, initiator ? 2 : 1);
    check("expected-private-destroy", psa_destroy_key(policy.expected.private_key));
    policy.expected.private_key = PSA_KEY_ID_NULL;
    struct edhoc_context *context = calloc(1, edhoc_context_size());
    if (context == NULL) fail("context-allocation", -1);
    check("context-init", edhoc_context_init(context));
    const enum edhoc_method method = EDHOC_METHOD_3;
    const struct edhoc_cipher_suite *suite = edhoc_cipher_suite_get_params(EDHOC_CIPHER_SUITE_2);
    const struct edhoc_crypto *crypto = edhoc_cipher_suite_get_crypto(EDHOC_CIPHER_SUITE_2);
    if (suite == NULL || crypto == NULL) fail("suite-config", -1);
    const struct edhoc_buffer connection_id = {.value = &cid, .length = 1};
    const struct edhoc_platform platform = {.zeroize = wipe};
    const struct edhoc_credentials credentials = {.select_local = select_local, .authenticate_peer = authenticate_peer};
    check("methods", edhoc_set_methods(context, &method, 1));
    check("suites", edhoc_set_cipher_suites(context, suite, 1));
    check("connection-id", edhoc_set_connection_id(context, &connection_id));
    check("user-context", edhoc_set_user_context(context, &policy));
    check("bind-crypto", edhoc_bind_crypto(context, crypto));
    check("bind-platform", edhoc_bind_platform(context, &platform));
    check("bind-credentials", edhoc_bind_credentials(context, &credentials));
    uint8_t message[MESSAGE_CAPACITY] = {0};
    size_t length = 0;
    if (initiator) {
        check("compose-m1", edhoc_message_1_compose(context, message, sizeof(message), &length));
        emit_message(1, message, length);
        length = read_message(message);
        check("process-m2", edhoc_message_2_process(context, message, length));
        check("compose-m3", edhoc_message_3_compose(context, message, sizeof(message), &length));
        emit_message(3, message, length);
        length = read_message(message);
        check("process-m4", edhoc_message_4_process(context, message, length));
    } else {
        printf("{\"ready\":true}\n"); fflush(stdout);
        length = read_message(message);
        check("process-m1", edhoc_message_1_process(context, message, length));
        check("compose-m2", edhoc_message_2_compose(context, message, sizeof(message), &length));
        emit_message(2, message, length);
        length = read_message(message);
        check("process-m3", edhoc_message_3_process(context, message, length));
        check("compose-m4", edhoc_message_4_compose(context, message, sizeof(message), &length));
        emit_message(4, message, length);
    }
    export_result(context, &policy);
    check("context-deinit", edhoc_context_deinit(context));
    wipe(context, edhoc_context_size());
    free(context);
    check("local-private-destroy", psa_destroy_key(policy.local.private_key));
    return 0;
}


/* Host-only profile adapter. The EDHOC state machine and cryptographic
 * primitives remain the pinned libedhoc/PSA implementation. */
static const struct edhoc_crypto *reference_crypto;
static int profile_expand(void *user_context, const void *prk, const uint8_t *info,
                          size_t info_length, enum edhoc_key_usage usage, void *output_key)
{
    struct peer_policy *policy = user_context;
    if (policy->suite != 3 || usage != EDHOC_KEY_USAGE_AEAD)
        return reference_crypto->expand(user_context, prk, info, info_length, usage, output_key);
    uint8_t material[16] = {0};
    int result = reference_crypto->expand_raw(user_context, prk, info, info_length, material, sizeof(material));
    if (result != EDHOC_SUCCESS) { wipe(material, sizeof(material)); return result; }
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    const psa_status_t status = psa_import_key(&attributes, material, sizeof(material), &key);
    wipe(material, sizeof(material)); psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS) return EDHOC_ERROR_CRYPTO_FAILURE;
    memcpy(output_key, &key, sizeof(key));
    return EDHOC_SUCCESS;
}
static int compose_ead(void *user_context, const struct edhoc_call_context *call,
                       struct edhoc_ead_token *tokens, size_t capacity, size_t *count)
{
    struct peer_policy *policy = user_context;
    static const uint8_t stages[4][2] = {{1,0},{2,0},{3,0},{4,0}};
    *count = 0;
    if (!policy->ead) return EDHOC_SUCCESS;
    unsigned stage = (unsigned)call->message + 1;
    if (stage > 4 || capacity < 3) return EDHOC_ERROR_INVALID_ARGUMENT;
    tokens[0] = (struct edhoc_ead_token){.label=policy->critical_stage == stage ? -32771 : -32768,.value={.value=stages[stage-1],.length=1}};
    tokens[1] = (struct edhoc_ead_token){.label=32769,.value={.value=NULL,.length=0}};
    tokens[2] = (struct edhoc_ead_token){.label=32770,.value={.value=stages[stage-1],.length=0}};
    *count = 3;
    return EDHOC_SUCCESS;
}
static int process_ead(void *user_context, const struct edhoc_call_context *call,
                       const struct edhoc_ead_token *tokens, size_t count)
{
    struct peer_policy *policy = user_context;
    unsigned stage = (unsigned)call->message + 1;
    if (stage > 4 || count > 3) return EDHOC_ERROR_INVALID_ARGUMENT;
    for (size_t i=0; i<count; i++) {
        const struct edhoc_ead_token *item = &tokens[i];
        if (item->label == 0) continue; /* Padding has no application effect. */
        if (item->label == -32771) return EDHOC_ERROR_EAD_PROCESS_FAILURE;
        unsigned position = ++policy->ead_received[stage-1];
        int valid = (position==1 && item->label==-32768 && item->value.length==1 && item->value.value && item->value.value[0]==stage)
                 || (position==2 && item->label==32769 && item->value.length==0 && item->value.value==NULL)
                 || (position==3 && item->label==32770 && item->value.length==0 && item->value.value!=NULL);
        if (!valid) return EDHOC_ERROR_EAD_PROCESS_FAILURE;
    }
    /* These receipts are emitted only after the complete successful exchange;
     * credential-key selection alone is not authentication evidence. */
    if (stage != 1) policy->ead_after_success |= 1u << (stage-1);
    return EDHOC_SUCCESS;
}
static void emit_export_vectors(struct edhoc_context *context)
{
    const size_t labels[5] = {32768,65535,32768,32768,32768};
    const size_t contexts[5] = {0,23,24,255,256};
    const size_t lengths[5] = {16,33,64,16,16};
    uint8_t bytes[256], output[64];
    for (size_t i=0;i<sizeof(bytes);i++) bytes[i]=(uint8_t)i;
    printf("\"exports\":[");
    for (size_t i=0;i<5;i++) {
        check("generic-export", edhoc_export_raw(context, labels[i], bytes, contexts[i], output, lengths[i]));
        if (i) printf(",");
        printf("{\"label\":%zu,\"context\":\"",labels[i]);print_hex(bytes,contexts[i]);
        printf("\",\"length\":%zu,\"hex\":\"",lengths[i]);print_hex(output,lengths[i]);printf("\"}");
        wipe(output,sizeof(output));
    }
    printf("]");
}

/* Exercise the independent public error codec, without claiming authentication. */
static int error_codec(int argc, char **argv)
{
    if (argc != 3 || strlen(argv[2]) != 1 || argv[2][0] < '1' || argv[2][0] > '3') return 2;
    enum edhoc_error_code code = (enum edhoc_error_code)(argv[2][0]-'0');
    struct edhoc_context *context = calloc(1, edhoc_context_size());
    if (!context) fail("error-context-allocation", -1);
    check("error-context-init", edhoc_context_init(context));
    uint8_t message[MESSAGE_CAPACITY] = {0};
    char text[32] = "independent refusal";
    int32_t suites[2] = {2,3};
    struct edhoc_error_info info = {0};
    if (code == EDHOC_ERROR_CODE_UNSPECIFIED_ERROR) {
        info.text_string = text; info.entries_size = sizeof(text); info.entries_length = strlen(text);
    } else if (code == EDHOC_ERROR_CODE_WRONG_SELECTED_CIPHER_SUITE) {
        info.cipher_suites = suites; info.entries_size = 2; info.entries_length = 2;
    }
    size_t length = 0;
    if (strcmp(argv[1], "error-compose") == 0) {
        check("compose-error", edhoc_message_error_compose(context, message, sizeof(message), &length, code, &info));
        emit_message(0, message, length);
    } else {
        length = read_message(message);
        enum edhoc_error_code received;
        check("process-error", edhoc_message_error_process(context, message, length, &received, &info));
        if (received != code) fail("error-code-mismatch", -1);
        printf("{\"error_received\":%d,\"entries\":%zu}\n", (int)received, info.entries_length);
        fflush(stdout);
    }
    check("error-context-deinit", edhoc_context_deinit(context));
    wipe(context, edhoc_context_size()); free(context);
    return 0;
}

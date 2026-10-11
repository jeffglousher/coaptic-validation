/* Internal dependency regression, compiled against the exact patched backend. */
#define COAP_API
#include "coap3/coap_libcoap_build.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

int main(void) {
  coap_context_t *ctx;
  coap_session_t *session, *other;
  coap_address_t address;
  coap_pdu_t *queued, *delayed, *unrelated, *copy;
  coap_lg_xmit_t *lg;
  coap_queue_t q = {0}, d = {0}, u = {0};
  uint8_t token = 0x42;
  coap_startup();
  coap_set_log_level(COAP_LOG_EMERG);
  ctx = coap_new_context(NULL);
  CHECK(ctx);
  coap_address_init(&address);
  address.addr.sin.sin_family = AF_INET;
  address.addr.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.addr.sin.sin_port = htons(5683);
  address.size = sizeof(address.addr.sin);
  session = coap_new_client_session(ctx, NULL, &address, COAP_PROTO_UDP);
  address.addr.sin.sin_port = htons(5684);
  other = coap_new_client_session(ctx, NULL, &address, COAP_PROTO_UDP);
  CHECK(session && other);
  coap_lock_lock(ctx, exit(1));
  queued = coap_pdu_init(COAP_MESSAGE_CON, COAP_RESPONSE_CODE_CHANGED, 1, 128);
  delayed = coap_pdu_init(COAP_MESSAGE_CON, COAP_RESPONSE_CODE_CHANGED, 2, 128);
  unrelated = coap_pdu_init(COAP_MESSAGE_CON, COAP_RESPONSE_CODE_CHANGED, 3, 128);
  CHECK(queued && delayed && unrelated);
  CHECK(queued->oscore_q_block2 == 0 && delayed->oscore_q_block2 == 0);
  CHECK(coap_add_token(queued, 1, &token));
  lg = coap_malloc_type(COAP_LG_XMIT, sizeof(*lg));
  CHECK(lg);
  memset(lg, 0, sizeof(*lg));
  lg->pdu.code = COAP_RESPONSE_CODE_CONTENT;
  queued->lg_xmit = delayed->lg_xmit = unrelated->lg_xmit = lg;
  queued->oscore_q_block2 = delayed->oscore_q_block2 = unrelated->oscore_q_block2 = 14;
  copy = coap_pdu_duplicate_lkd(queued, session, 1, &token, NULL);
  CHECK(copy && copy->oscore_q_block2 == 0);
  copy->oscore_q_block2 = 14;
  coap_pdu_clear(copy, 128);
  CHECK(copy->oscore_q_block2 == 0);
  coap_delete_pdu_lkd(copy);

  /* Both queue owners are invalidated before the transfer allocation is freed.
   * Another session's pointer-shaped value must not be treated as this owner. */
  q.session = session; q.pdu = queued; q.next = &u;
  u.session = other; u.pdu = unrelated;
  d.session = session; d.pdu = delayed;
  ctx->sendqueue = &q;
  session->delayqueue = &d;
  coap_block_delete_lg_xmit(session, lg);
  CHECK(!queued->lg_xmit && !queued->oscore_q_block2);
  CHECK(!delayed->lg_xmit && !delayed->oscore_q_block2);
  CHECK(unrelated->oscore_q_block2 == 14);
  CHECK(unrelated->lg_xmit != NULL);
  /* A later allocation cannot reactivate cleared continuation metadata. */
  lg = coap_malloc_type(COAP_LG_XMIT, sizeof(*lg));
  CHECK(lg);
  memset(lg, 0, sizeof(*lg));
  CHECK(!queued->lg_xmit && !delayed->lg_xmit);
  ctx->sendqueue = NULL;
  session->delayqueue = NULL;
  unrelated->lg_xmit = NULL;
  unrelated->oscore_q_block2 = 0;
  coap_delete_pdu_lkd(queued);
  coap_delete_pdu_lkd(delayed);
  coap_delete_pdu_lkd(unrelated);

  /* Existing continuation must refuse to emit while NSTART1 is occupied. */
  {
    uint8_t body[32] = {0};
    coap_block_b_t block = {0};
    coap_pdu_t *plain = coap_pdu_init(COAP_MESSAGE_CON, COAP_RESPONSE_CODE_CONTENT, 4, 128);
    CHECK(plain && coap_add_token(plain, 1, &token));
    block.m = 1;
    lg->option = COAP_OPTION_Q_BLOCK2;
    lg->length = sizeof(body);
    lg->data = body;
    session->con_active = COAP_NSTART(session);
    CHECK(COAP_NSTART(session) == 1);
    CHECK(coap_send_q_blocks(session, lg, block, plain, COAP_SEND_SKIP_PDU) == COAP_INVALID_MID);
    CHECK(session->con_active == 1 && ctx->sendqueue == NULL && session->delayqueue == NULL);
    session->con_active = 0;
    coap_delete_pdu_lkd(plain);
  }
  coap_block_delete_lg_xmit(session, lg);
  coap_lock_unlock(ctx);
  coap_session_release(other);
  coap_session_release(session);
  coap_free_context(ctx);
  coap_cleanup();
  puts("PASS patched Q-Block2 ownership reset/copy/expiry and NSTART refusal");
  return 0;
}

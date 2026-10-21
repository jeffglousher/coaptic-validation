/* Test-only internal lifecycle proof. Transport writes are captured in memory;
 * this executable must pass under ASan/UBSan before any patched peer traffic. */
#define COAP_API
#include "coap3/coap_libcoap_build.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static long fail_after = -1;
void *__real_coap_malloc_type(coap_memory_tag_t, size_t);
void *__wrap_coap_malloc_type(coap_memory_tag_t t, size_t n) {
  if (fail_after == 0) { fail_after = -1; return NULL; }
  if (fail_after > 0) --fail_after;
  return __real_coap_malloc_type(t,n);
}
static uint8_t wire[32][2048];
static size_t lengths[32], writes;
static coap_lg_xmit_t *retire_on_write;
static const oscore_recipient_ctx_t *replay_expected_on_write;
static unsigned replay_write_checks;
static ssize_t capture(coap_session_t *s, const uint8_t *data, size_t n) {
  if(replay_expected_on_write) {
    CHECK(s->recipient_ctx->last_seq==replay_expected_on_write->last_seq&&
          s->recipient_ctx->sliding_window==replay_expected_on_write->sliding_window&&
          s->recipient_ctx->initial_state==replay_expected_on_write->initial_state);
    replay_write_checks++;
  }
  CHECK(writes < 32 && n <= sizeof(wire[0]));
  memcpy(wire[writes],data,n); lengths[writes++]=n;
  if (retire_on_write) {
    coap_lg_xmit_t *lg=retire_on_write;
    retire_on_write=NULL;
    LL_DELETE(s->lg_xmit,lg);
    coap_block_delete_lg_xmit(s,lg);
  }
  return (ssize_t)n;
}
static coap_context_t *ctx;
static coap_session_t *session, *other;
static coap_bin_const_t token={1,(const uint8_t *)"t"};
static coap_bin_const_t rid={0,(const uint8_t *)""};
static unsigned callback_count;
static int save_sequence(uint64_t seq, void *arg) {
  coap_session_t *s=arg;
  (void)seq;
  callback_count++;
  CHECK(s->oscore_q_encrypting > 0);
  CHECK(!coap_delete_oscore_recipient_lkd(s->context,&rid));
  CHECK(s->context->p_osc_ctx->recipient_chain != NULL);
  return 1;
}
static void setup(void) {
  static const char conf[]="master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
    "master_salt,hex,\"9e7ca92223786340\"\nsender_id,hex,\"01\"\nrecipient_id,hex,\"\"\n"
    "aead_alg,integer,10\nhkdf_alg,integer,-10\nssn_freq,integer,1\n";
  coap_str_const_t text={sizeof(conf)-1,(const uint8_t *)conf};
  coap_address_t addr;
  coap_oscore_conf_t *c;
  ctx=coap_new_context(NULL); CHECK(ctx);
  c=coap_new_oscore_conf(text,NULL,NULL,0); CHECK(c);
  CHECK(coap_context_oscore_server(ctx,c));
  coap_address_init(&addr);addr.addr.sin.sin_family=AF_INET;
  addr.addr.sin.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.addr.sin.sin_port=htons(5683);
  addr.size=sizeof(addr.addr.sin);
  session=coap_new_client_session(ctx,NULL,&addr,COAP_PROTO_UDP);
  addr.addr.sin.sin_port=htons(5684);
  other=coap_new_client_session(ctx,NULL,&addr,COAP_PROTO_UDP);CHECK(session&&other);
  session->oscore_encryption=1;
  session->recipient_ctx=ctx->p_osc_ctx->recipient_chain;
  session->sock.lfunc[COAP_LAYER_SESSION].l_write=capture;
  other->sock.lfunc[COAP_LAYER_SESSION].l_write=capture;
  coap_lock_lock(ctx,exit(1)); writes=0;
}
static void teardown(void) {
  coap_lock_unlock(ctx);
  coap_session_release(other);coap_session_release(session);
  coap_free_context(ctx);
}
static coap_pdu_t *response(coap_pdu_type_t type, unsigned num, unsigned more) {
  uint8_t body[16], q=(uint8_t)((num<<4)|(more<<3));
  coap_pdu_t *p=coap_pdu_init(type,COAP_RESPONSE_CODE_CONTENT,123,256);
  memset(body,(int)num,sizeof(body));CHECK(p&&coap_add_token(p,token.length,token.s));
  CHECK(coap_add_option(p,COAP_OPTION_Q_BLOCK2,1,&q));
  CHECK(coap_add_data(p,sizeof(body),body));return p;
}
static coap_lg_xmit_t *transfer(void) {
  static uint8_t body[64];
  coap_pdu_t *template_pdu;
  coap_lg_xmit_t *lg=coap_malloc_type(COAP_LG_XMIT,sizeof(*lg));
  CHECK(lg);memset(lg,0,sizeof(*lg));lg->option=COAP_OPTION_Q_BLOCK2;
  template_pdu=response(COAP_MESSAGE_CON,0,1);
  lg->pdu=*template_pdu;
  coap_free_type(COAP_PDU,template_pdu);
  lg->length=32;lg->data=body;
  LL_PREPEND(session->lg_xmit,lg);return lg;
}
static void association(unsigned value) {
  uint8_t nonce[13]={0},piv=(uint8_t)value,aad[3]={1,2,(uint8_t)value};
  coap_bin_const_t n={sizeof(nonce),nonce},v={1,&piv},a={sizeof(aad),aad};
  oscore_association_t *old=oscore_find_association(session,&token);
  if(old) oscore_delete_association(session,old);
  CHECK(oscore_new_association(session,NULL,&token,ctx->p_osc_ctx->recipient_chain,&a,&n,&v,0));
  oscore_find_association(session,&token)->request_generation=++session->oscore_request_generation;
}
/* Test analogue of the pre-handler response stamp, never a production fallback. */
static void stamp(coap_pdu_t *p) {
  oscore_association_t *a=oscore_find_association(session,&token);
  CHECK(a&&a->request_generation);p->oscore_request_generation=a->request_generation;
}
static void drop_transfer(coap_lg_xmit_t *lg) {
  LL_DELETE(session->lg_xmit,lg);coap_block_delete_lg_xmit(session,lg);
}
static void stale_timer(coap_lg_xmit_t *lg) {
  size_t before=writes;
  CHECK(lg->pdu.oscore_q_generation&&lg->last_payload==0);
  /* Simulate an already-due timer view captured before retirement. */
  lg->last_payload=1;lg->non_timeout_random_ticks=0;lg->offset=0;lg->last_block=0;
  coap_block_check_q_block2_xmit(session,2);
  CHECK(writes==before);
  lg->last_payload=0;
}
static void ownership(void) {
  unsigned i; coap_pdu_t *p,*stale;coap_lg_xmit_t *lg;uint64_t gen;
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);
  CHECK(coap_q_bind_response(session,lg,p));gen=lg->oscore_generation;
  CHECK(!oscore_find_association(session,&token));
  CHECK(coap_q_response_binding(session,p)==lg->oscore_binding);
  CHECK(!coap_q_response_binding(other,p));
  stale=coap_pdu_duplicate_lkd(p,session,1,token.s,NULL);CHECK(stale);
  CHECK(!stale->oscore_q_generation&&!stale->oscore_q_block2&&!stale->oscore_request_generation);
  stale->oscore_q_generation=gen;stale->lg_xmit=lg;
  association(2);stamp(p);
  CHECK(lg->oscore_binding->partial_iv->s[0]==1);
  for(i=0;i<5;i++) {
    oscore_association_t *before=lg->oscore_binding;
    fail_after=(long)i;
    CHECK(!coap_q_bind_response(session,lg,p));fail_after=-1;
    CHECK(lg->oscore_binding==before&&lg->oscore_generation==gen);
    CHECK(oscore_find_association(session,&token)->partial_iv->s[0]==2);
    CHECK(writes==0);
  }
  CHECK(coap_q_bind_response(session,lg,p));
  CHECK(lg->oscore_generation>gen&&lg->oscore_binding->partial_iv->s[0]==2);
  CHECK(!coap_q_response_binding(session,stale));
  /* Retirement plus a newer same-token association cannot be resurrected by
   * timer scheduling, even before a legitimate fresh bind. */
  coap_q_revoke_binding(session,lg);association(3);stamp(p);
  stale_timer(lg);CHECK(writes==0);
  CHECK(coap_q_bind_response(session,lg,p));
  association(4);stamp(p);session->oscore_q_generation=UINT64_MAX;
  CHECK(!coap_q_bind_response(session,lg,p));
  CHECK(lg->oscore_binding->partial_iv->s[0]==3);
  session->oscore_q_generation=lg->oscore_generation;
  p->type=COAP_MESSAGE_NON;CHECK(!coap_q_bind_response(session,lg,p));p->type=COAP_MESSAGE_CON;
  coap_delete_pdu_lkd(stale);coap_delete_pdu_lkd(p);drop_transfer(lg);teardown();
}
static void crypto_and_errors(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *p,*a,*b;coap_opt_iterator_t it;
  coap_opt_t *oa,*ob;uint8_t old_opt[16];size_t old_len;uint64_t seq;unsigned i;
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);
  CHECK(coap_q_bind_response(session,lg,p));
  ctx->p_osc_ctx->save_seq_num_func=save_sequence;
  ctx->p_osc_ctx->save_seq_num_func_param=session;
  callback_count=0;
  a=coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV);CHECK(a);
  CHECK(session->oscore_q_encrypting==0&&callback_count>0);
  oa=coap_check_option(a,COAP_OPTION_OSCORE,&it);CHECK(oa);
  old_len=coap_opt_length(oa);CHECK(old_len>1&&old_len<=sizeof(old_opt));
  memcpy(old_opt,coap_opt_value(oa),old_len);
  b=coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV);CHECK(b);
  ob=coap_check_option(b,COAP_OPTION_OSCORE,&it);CHECK(ob);
  CHECK(old_len!=coap_opt_length(ob)||memcmp(old_opt,coap_opt_value(ob),old_len));
  CHECK(writes==0);
  coap_delete_pdu_lkd(a);coap_delete_pdu_lkd(b);
  /* Walk allocation positions until success, requiring every failed encoding to
   * restore in-flight state and never rewind sender sequence. */
  for(i=0;i<32;i++) {
    seq=ctx->p_osc_ctx->sender_context->seq;fail_after=i;
    a=coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV);fail_after=-1;
    CHECK(session->oscore_q_encrypting==0);
    CHECK(ctx->p_osc_ctx->sender_context->seq>=seq);
    if(a) {coap_delete_pdu_lkd(a);break;}
  }
  CHECK(i<32);
  session->oscore_q_encrypting=1;
  a=coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV);
  CHECK(a&&session->oscore_q_encrypting==1);coap_delete_pdu_lkd(a);
  session->oscore_q_encrypting=UINT_MAX;
  seq=ctx->p_osc_ctx->sender_context->seq;
  CHECK(!coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV));
  CHECK(session->oscore_q_encrypting==UINT_MAX&&ctx->p_osc_ctx->sender_context->seq==seq);
  session->oscore_q_encrypting=0;
  ctx->p_osc_ctx->sender_context->seq=OSCORE_SEQ_MAX-1;
  CHECK(!coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV));
  CHECK(session->oscore_q_encrypting==0&&ctx->p_osc_ctx->sender_context->seq==OSCORE_SEQ_MAX);
  /* Dynamic removal outside encoding succeeds and makes retained PDUs refuse. */
  CHECK(coap_delete_oscore_recipient_lkd(ctx,&rid));
  CHECK(!lg->oscore_binding&&!coap_q_response_binding(session,p));
  CHECK(!coap_oscore_new_pdu_encrypted_lkd(session,p,NULL,OSCORE_SEND_PARTIAL_IV));
  CHECK(session->oscore_q_encrypting==0);
  CHECK(lg->pdu.oscore_q_generation&&lg->last_payload==0);
  stale_timer(lg);CHECK(writes==0);
  coap_delete_pdu_lkd(p);drop_transfer(lg);teardown();
}
static void queue_expiry_and_context(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *p,*queued,*delayed;coap_queue_t q={0},d={0};coap_tick_t remaining;
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);
  CHECK(coap_q_bind_response(session,lg,p));
  queued=response(COAP_MESSAGE_CON,0,1);delayed=response(COAP_MESSAGE_CON,0,1);
  queued->lg_xmit=delayed->lg_xmit=lg;
  queued->oscore_q_generation=delayed->oscore_q_generation=lg->oscore_generation;
  queued->oscore_q_block2=delayed->oscore_q_block2=0x80000008U;
  q.session=session;q.pdu=queued;d.session=session;d.pdu=delayed;
  ctx->sendqueue=&q;session->delayqueue=&d;lg->last_sent=1;
  coap_block_check_lg_xmit_timeouts(session,COAP_MAX_TRANSMIT_WAIT_TICKS(session)+2,&remaining);
  CHECK(!session->lg_xmit&&!queued->lg_xmit&&!delayed->lg_xmit);
  CHECK(!queued->oscore_q_block2&&!delayed->oscore_q_block2);
  CHECK(queued->oscore_q_generation&&delayed->oscore_q_generation);
  ctx->sendqueue=NULL;session->delayqueue=NULL;
  CHECK(!coap_q_response_binding(session,p));
  coap_delete_pdu_lkd(p);coap_delete_pdu_lkd(queued);coap_delete_pdu_lkd(delayed);
  lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(2);stamp(p);CHECK(coap_q_bind_response(session,lg,p));
  coap_delete_all_oscore(ctx);CHECK(!lg->oscore_binding);
  CHECK(!coap_q_response_binding(session,p));coap_delete_pdu_lkd(p);
  teardown();
}
static void transport_and_allocation(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *p;coap_block_b_t block={0};uint64_t gen;
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);
  CHECK(coap_q_bind_response(session,lg,p));gen=lg->oscore_generation;block.m=1;
  session->con_active=1;
  CHECK(COAP_NSTART(session)==1);
  CHECK(coap_send_q_blocks(session,lg,block,p,COAP_SEND_SKIP_PDU)==COAP_INVALID_MID);
  CHECK(writes==0&&session->con_active==1&&lg->oscore_generation==gen);
  session->con_active=0;fail_after=0;
  CHECK(coap_send_q_blocks(session,lg,block,p,COAP_SEND_SKIP_PDU)==COAP_INVALID_MID);
  fail_after=-1;CHECK(writes==0&&lg->oscore_binding);
  /* ACK conversion sends an empty ACK through the in-memory writer. Retiring
   * the transfer there must prevent ciphertext publication after the callback. */
  p->type=COAP_MESSAGE_ACK;retire_on_write=lg;
  CHECK(coap_send_q_blocks(session,lg,block,p,COAP_SEND_INC_PDU)==COAP_INVALID_MID);
  CHECK(writes==1&&lengths[0]==4&&!session->lg_xmit);
  CHECK(session->oscore_q_encrypting==0);
  teardown();
}
static void ack(coap_session_t *s, coap_mid_t mid) {
  coap_pdu_t *p=coap_pdu_init(COAP_MESSAGE_ACK,COAP_EMPTY_CODE,mid,16);CHECK(p);
  coap_dispatch(ctx,s,p);coap_delete_pdu_lkd(p);
}
static void ack_retry_and_final_cleanup(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *p;coap_mid_t mid;coap_queue_t *q;
  size_t n;
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);
  CHECK(coap_q_bind_response(session,lg,p));
  mid=coap_send_internal(session,p);CHECK(mid!=COAP_INVALID_MID&&writes==1);
  CHECK(ctx->sendqueue&&ctx->sendqueue->pdu->oscore_q_block2);
  ack(other,mid);ack(session,(mid+1)&0xffff);CHECK(writes==1&&lg->oscore_binding);
  CHECK(coap_remove_from_queue(&ctx->sendqueue,session,mid,&q));CHECK(q);
  CHECK(coap_retransmit(ctx,q)!=COAP_INVALID_MID);
  CHECK(writes==2&&lengths[0]==lengths[1]&&!memcmp(wire[0],wire[1],lengths[0]));
  ack(session,mid);CHECK(writes==3&&ctx->sendqueue);
  CHECK(lg->oscore_binding&&session->con_active==1);
  mid=ctx->sendqueue->id;n=writes;
  ack(session,mid);CHECK(writes==n&&!lg->oscore_binding&&session->con_active==0);
  CHECK(!ctx->sendqueue);
  association(3);
  CHECK(lg->pdu.oscore_q_generation&&lg->last_payload==0);
  stale_timer(lg);
  CHECK(writes==n&&oscore_find_association(session,&token));
  p=response(COAP_MESSAGE_CON,0,1);stamp(p);CHECK(coap_q_bind_response(session,lg,p));
  CHECK(coap_send_internal(session,p)!=COAP_INVALID_MID&&writes==n+1);
  teardown();
}
static void cached_fresh_request(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *request,*reply,*stale;
  coap_resource_t *resource;uint8_t selector=0x10;uint64_t oldgen;
  setup();lg=transfer();resource=coap_resource_init(coap_make_str_const("large"),0);CHECK(resource);
  coap_add_resource_lkd(ctx,resource);lg->b.b2.resource=resource;lg->b.b2.request_method=COAP_REQUEST_CODE_GET;
  stale=response(COAP_MESSAGE_CON,0,1);association(1);stamp(stale);CHECK(coap_q_bind_response(session,lg,stale));oldgen=lg->oscore_generation;
  request=coap_pdu_init(COAP_MESSAGE_CON,COAP_REQUEST_CODE_GET,500,128);CHECK(request);
  CHECK(coap_add_token(request,1,token.s)&&coap_add_option(request,COAP_OPTION_Q_BLOCK2,1,&selector));
  reply=coap_pdu_init(COAP_MESSAGE_ACK,COAP_EMPTY_CODE,500,256);CHECK(reply&&coap_add_token(reply,1,token.s));
  association(2);stamp(reply);
  CHECK(coap_handle_request_send_block(session,request,reply,resource,NULL));
  CHECK(reply->code==COAP_RESPONSE_CODE_CONTENT&&lg->oscore_generation>oldgen);
  CHECK(lg->oscore_binding->partial_iv->s[0]==2&&!oscore_find_association(session,&token));
  CHECK(!coap_q_response_binding(session,stale));
  /* Mirrors net.c's lg_xmit_ctrl branch: cached response goes straight to send,
   * not through initial-transfer coap_send_q_block2 / a second bind. */
  CHECK(coap_send_internal(session,reply)!=COAP_INVALID_MID);
  CHECK(writes==2);ack(session,ctx->sendqueue->id);CHECK(!lg->oscore_binding);
  coap_delete_pdu_lkd(request);coap_delete_pdu_lkd(stale);
  /* A valid two-selector request is explicitly unsupported before binding/IO. */
  lg->length=64;request=coap_pdu_init(COAP_MESSAGE_CON,COAP_REQUEST_CODE_GET,501,128);CHECK(request);
  CHECK(coap_add_token(request,1,token.s)&&coap_add_option(request,COAP_OPTION_Q_BLOCK2,1,&selector));
  selector=0x20;CHECK(coap_add_option(request,COAP_OPTION_Q_BLOCK2,1,&selector));
  reply=coap_pdu_init(COAP_MESSAGE_ACK,COAP_EMPTY_CODE,501,256);CHECK(reply&&coap_add_token(reply,1,token.s));
  association(3);stamp(reply);oldgen=lg->oscore_generation;
  CHECK(coap_handle_request_send_block(session,request,reply,resource,NULL));
  CHECK(COAP_RESPONSE_CLASS(reply->code)==5&&writes==2&&!lg->oscore_binding);
  CHECK(lg->oscore_generation==oldgen&&oscore_find_association(session,&token));
  coap_delete_pdu_lkd(request);coap_delete_pdu_lkd(reply);teardown();
}
/* Construct ordinary authenticated requests using the same backend, with no
 * socket writes. Optional malformed inner input exercises decoder refusal; it
 * is constructed offline with the request's allocated nonce; neither version
 * is sent to a socket. This is a decoder test, not a wire qualification. */
static coap_pdu_t *authenticated_request_at(unsigned malformed, unsigned b2, uint64_t seq,
                                          const uint8_t *echo) {
  static const char config[]="master_secret,hex,\"0102030405060708090a0b0c0d0e0f10\"\n"
    "master_salt,hex,\"9e7ca92223786340\"\nsender_id,hex,\"\"\nrecipient_id,hex,\"01\"\n";
  coap_str_const_t text={sizeof(config)-1,(const uint8_t *)config};
  coap_context_t *c;coap_session_t *client;
  coap_oscore_conf_t *conf;
  coap_address_t addr;coap_pdu_t *plain,*protected;
  coap_lock_unlock(ctx); /* libcoap uses one global lock across contexts. */
  c=coap_new_context(NULL);conf=coap_new_oscore_conf(text,NULL,NULL,seq);
  CHECK(c&&conf&&coap_context_oscore_server(c,conf));
  coap_address_init(&addr);addr.addr.sin.sin_family=AF_INET;
  addr.addr.sin.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.addr.sin.sin_port=htons(5685);
  addr.size=sizeof(addr.addr.sin);client=coap_new_client_session(c,NULL,&addr,COAP_PROTO_UDP);CHECK(client);
  coap_lock_lock(c,exit(1));client->oscore_encryption=1;client->recipient_ctx=c->p_osc_ctx->recipient_chain;
  if(b2) {
    static const uint8_t id[]={0x71,0x72};
    c->p_osc_ctx->rfc8613_b_2=1;
    oscore_update_ctx(c->p_osc_ctx,coap_new_bin_const(id,sizeof(id)));
    client->b_2_step=COAP_OSCORE_B_2_STEP_1;
  }
  plain=coap_pdu_init(COAP_MESSAGE_CON,COAP_REQUEST_CODE_GET,700,256);CHECK(plain);
  CHECK(coap_add_token(plain,token.length,token.s));
  CHECK(coap_add_option(plain,COAP_OPTION_URI_PATH,5,(const uint8_t *)"large"));
  { uint8_t q=8;CHECK(coap_add_option(plain,COAP_OPTION_Q_BLOCK2,1,&q)); }
  if(echo) CHECK(coap_add_option(plain,COAP_OPTION_ECHO,8,echo));
  protected=coap_oscore_new_pdu_encrypted_lkd(client,plain,NULL,0);CHECK(protected);
  if(malformed) {
    /* Both are authenticated but malformed: CF has forbidden length3; query
     * declares 13 bytes but provides only one. Neither may commit ownership. */
    uint8_t cf[]={1,0xc3,0,0,0},query[]={1,0xdd,2,0,0};
    uint8_t encrypted[64];cose_encrypt0_t cose[1];int n;
    oscore_association_t *a=oscore_find_association(client,&token);CHECK(a);
    cose_encrypt0_init(cose);cose_encrypt0_set_alg(cose,c->p_osc_ctx->aead_alg);
    CHECK(cose_encrypt0_set_key(cose,c->p_osc_ctx->sender_context->sender_key));
    cose_encrypt0_set_aad(cose,a->aad);cose_encrypt0_set_nonce(cose,a->nonce);
    cose_encrypt0_set_plaintext(cose,malformed==1?cf:query,sizeof(cf));
    n=cose_encrypt0_encrypt(cose,encrypted,sizeof(encrypted));CHECK(n>0);
    protected->used_size=(size_t)(protected->data-protected->token)-1;protected->data=NULL;
    CHECK(coap_add_data(protected,(size_t)n,encrypted));
  }
  coap_delete_pdu_lkd(plain);coap_lock_unlock(c);coap_session_release(client);coap_free_context(c);
  coap_lock_lock(ctx,exit(1));return protected;
}
static coap_pdu_t *authenticated_request(unsigned malformed, unsigned b2) {
  return authenticated_request_at(malformed,b2,20,NULL);
}
static void replay_unchanged(const oscore_recipient_ctx_t *expected) {
  const oscore_recipient_ctx_t *actual=ctx->p_osc_ctx->recipient_chain;
  CHECK(actual->last_seq==expected->last_seq&&actual->sliding_window==expected->sliding_window);
  CHECK(actual->initial_state==expected->initial_state);
  CHECK(actual->rollback_last_seq==expected->rollback_last_seq&&
        actual->rollback_sliding_window==expected->rollback_sliding_window);
}
static void authenticated_commit_failures(void) {
  coap_pdu_t *input,*decoded;oscore_association_t *old;uint64_t generation;unsigned i,failures=0,successes=0;
  oscore_recipient_ctx_t before;
  setup();ctx->p_osc_ctx->rfc8613_b_1_2=0;ctx->p_osc_ctx->recipient_chain->initial_state=0;
  association(9);old=oscore_find_association(session,&token);generation=session->oscore_request_generation;
  before=*ctx->p_osc_ctx->recipient_chain;
  input=authenticated_request(0,0);input->data[0]^=1;
  replay_expected_on_write=&before;replay_write_checks=0;
  CHECK(!coap_oscore_decrypt_pdu(session,input));
  replay_expected_on_write=NULL;CHECK(replay_write_checks>0);
  CHECK(oscore_find_association(session,&token)==old&&old->partial_iv->s[0]==9);
  CHECK(session->oscore_request_generation==generation);replay_unchanged(&before);
  input->data[0]^=1;decoded=coap_oscore_decrypt_pdu(session,input);CHECK(decoded);
  CHECK(decoded->oscore_request_generation>generation);
  CHECK(oscore_find_association(session,&token)->request_generation==decoded->oscore_request_generation);
  coap_delete_pdu_lkd(decoded);coap_delete_pdu_lkd(input);teardown();
  for(i=1;i<=2;i++) {
    setup();ctx->p_osc_ctx->rfc8613_b_1_2=0;ctx->p_osc_ctx->recipient_chain->initial_state=0;
    association(9);old=oscore_find_association(session,&token);generation=session->oscore_request_generation;
    before=*ctx->p_osc_ctx->recipient_chain;
    input=authenticated_request(i,0);CHECK(!coap_oscore_decrypt_pdu(session,input));
    replay_unchanged(&before);
    CHECK(oscore_find_association(session,&token)==old&&old->partial_iv->s[0]==9);
    CHECK(session->oscore_request_generation==generation);
    coap_delete_pdu_lkd(input);teardown();
  }
  /* Exercise actual decrypt + transactional association allocation failures,
   * retaining a previous request on every unsuccessful decode. */
  for(i=0;i<32;i++) {
    setup();ctx->p_osc_ctx->rfc8613_b_1_2=0;ctx->p_osc_ctx->recipient_chain->initial_state=0;
    association(9);old=oscore_find_association(session,&token);generation=session->oscore_request_generation;
    before=*ctx->p_osc_ctx->recipient_chain;
    input=authenticated_request(0,0);fail_after=(long)i;
    decoded=coap_oscore_decrypt_pdu(session,input);fail_after=-1;
    if(!decoded) {
      failures++;CHECK(oscore_find_association(session,&token)==old&&old->partial_iv->s[0]==9);
      CHECK(session->oscore_request_generation==generation);replay_unchanged(&before);
    } else {successes++;CHECK(decoded->oscore_request_generation>generation);}
    coap_delete_pdu_lkd(decoded);coap_delete_pdu_lkd(input);teardown();
  }
  CHECK(failures>=5&&successes>0);
  setup();ctx->p_osc_ctx->rfc8613_b_1_2=0;ctx->p_osc_ctx->recipient_chain->initial_state=0;
  association(9);old=oscore_find_association(session,&token);session->oscore_request_generation=UINT64_MAX;
  input=authenticated_request(0,0);CHECK(!coap_oscore_decrypt_pdu(session,input));
  CHECK(session->oscore_request_generation==UINT64_MAX&&oscore_find_association(session,&token)==old);
  coap_delete_pdu_lkd(input);teardown();
}
static void accepted_zero_bad_mac_recovery(void) {
  coap_pdu_t *input,*decoded;oscore_association_t *old;uint64_t generation;
  oscore_recipient_ctx_t before;
  setup();ctx->p_osc_ctx->rfc8613_b_1_2=1;
  /* An outstanding server Echo is a fixture precondition. The incoming request
   * itself is authenticated and accepted through the actual B.1.2 path. */
  memset(ctx->p_osc_ctx->recipient_chain->echo_value,0x4b,8);
  ctx->p_osc_ctx->recipient_chain->initial_state=1;
  input=authenticated_request_at(0,0,0,ctx->p_osc_ctx->recipient_chain->echo_value);
  decoded=coap_oscore_decrypt_pdu(session,input);CHECK(decoded);
  CHECK(ctx->p_osc_ctx->recipient_chain->initial_state==0&&
        ctx->p_osc_ctx->recipient_chain->last_seq==0&&
        ctx->p_osc_ctx->recipient_chain->sliding_window==1);
  old=oscore_find_association(session,&token);CHECK(old&&old->partial_iv->s[0]==0);
  generation=decoded->oscore_request_generation;before=*ctx->p_osc_ctx->recipient_chain;
  coap_delete_pdu_lkd(decoded);coap_delete_pdu_lkd(input);
  input=authenticated_request_at(0,0,21,NULL);input->data[0]^=1;
  replay_expected_on_write=&before;replay_write_checks=0;
  CHECK(!coap_oscore_decrypt_pdu(session,input));replay_unchanged(&before);
  replay_expected_on_write=NULL;CHECK(replay_write_checks>0);
  CHECK(oscore_find_association(session,&token)==old&&old->partial_iv->s[0]==0&&
        session->oscore_request_generation==generation);
  input->data[0]^=1;decoded=coap_oscore_decrypt_pdu(session,input);CHECK(decoded);
  CHECK(decoded->oscore_request_generation>generation&&ctx->p_osc_ctx->recipient_chain->last_seq==21);
  coap_delete_pdu_lkd(decoded);coap_delete_pdu_lkd(input);teardown();
}
static void authenticated_server_challenges(void) {
  unsigned b2;coap_pdu_t *input,*out;coap_opt_iterator_t it;
  for(b2=0;b2<=1;b2++) {
    setup();ctx->p_osc_ctx->rfc8613_b_1_2=!b2;ctx->p_osc_ctx->rfc8613_b_2=b2;
    ctx->p_osc_ctx->recipient_chain->initial_state=1;
    input=authenticated_request(0,b2);
    CHECK(!coap_oscore_decrypt_pdu(session,input));
    CHECK(session->oscore_request_generation==1&&writes>0);
    out=coap_pdu_init(0,0,0,2048);CHECK(out);
    CHECK(coap_pdu_parse(COAP_PROTO_UDP,wire[writes-1],lengths[writes-1],out));
    CHECK(coap_check_option(out,COAP_OPTION_OSCORE,&it));
    CHECK(COAP_RESPONSE_CLASS(out->code)==2&&out->data);
    coap_delete_pdu_lkd(out);coap_delete_pdu_lkd(input);teardown();
  }
}
static unsigned replace_in_handler, handler_calls;
static void origin_handler(coap_resource_t *r,coap_session_t *s,const coap_pdu_t *request,
                           const coap_string_t *query,coap_pdu_t *reply) {
  (void)r;(void)s;(void)query;
  CHECK(request->oscore_request_generation&&
        request->oscore_request_generation==reply->oscore_request_generation);
  handler_calls++;
  if(replace_in_handler) {
    coap_lock_lock(ctx,exit(1));association(7);coap_lock_unlock(ctx);
  }
  reply->code=COAP_RESPONSE_CODE(500);
}
static void callback_request_replacement(void) {
  unsigned replaced;coap_pdu_t *input;coap_resource_t *r;
  for(replaced=0;replaced<=1;replaced++) {
    setup();ctx->p_osc_ctx->rfc8613_b_1_2=0;ctx->p_osc_ctx->recipient_chain->initial_state=0;
    /* Match peer.c admission: Q-Block is a negotiated critical option. */
    ctx->block_mode=COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY|COAP_BLOCK_TRY_Q_BLOCK;
    session->block_mode=ctx->block_mode;
    r=coap_resource_init(coap_make_str_const("large"),COAP_RESOURCE_SAFE_REQUEST_HANDLER);CHECK(r);
    coap_register_handler(r,COAP_REQUEST_GET,origin_handler);coap_add_resource_lkd(ctx,r);
    replace_in_handler=replaced;handler_calls=0;
    input=authenticated_request(0,0);coap_dispatch(ctx,session,input);
    CHECK(handler_calls==1);CHECK(replaced ? writes==0 : writes>0);
    coap_delete_pdu_lkd(input);teardown();
  }
}
static void stale_prebind_request(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *old,*fresh;uint64_t first;
  setup();lg=transfer();association(7);old=response(COAP_MESSAGE_CON,0,1);stamp(old);
  first=old->oscore_request_generation;
  association(7); /* Even identical token/PIV bytes are a different authenticated instance. */
  CHECK(session->oscore_request_generation>first);
  CHECK(!coap_q_bind_response(session,lg,old));
  CHECK(!lg->oscore_binding&&writes==0);
  fresh=response(COAP_MESSAGE_CON,0,1);
  CHECK(!coap_q_bind_response(session,lg,fresh)); /* Unknown/async provenance. */
  stamp(fresh);CHECK(coap_q_bind_response(session,lg,fresh));
  CHECK(lg->oscore_binding->request_generation==fresh->oscore_request_generation);
  coap_delete_pdu_lkd(old);coap_delete_pdu_lkd(fresh);teardown();
}
static void delete_before_bind_and_recreate(void) {
  coap_lg_xmit_t *lg;coap_pdu_t *old_response,*fresh,*input,*decoded;
  coap_bin_const_t *owned_rid;
  setup();lg=transfer();old_response=response(COAP_MESSAGE_CON,0,1);association(1);stamp(old_response);
  CHECK(oscore_find_association(session,&token)&&session->recipient_ctx);
  CHECK(coap_delete_oscore_recipient_lkd(ctx,&rid));
  CHECK(!oscore_find_association(session,&token)&&!session->recipient_ctx);
  CHECK(!coap_q_bind_response(session,lg,old_response));
  CHECK(!lg->oscore_binding&&lg->oscore_generation==0&&writes==0);
  /* Recipient creation takes ownership; deletion/lookups only borrow rid. */
  owned_rid=coap_new_bin_const(rid.s,rid.length);CHECK(owned_rid);
  CHECK(coap_new_oscore_recipient_lkd(ctx,owned_rid));
  /* Re-adding an ID cannot revive deleted request evidence by itself. */
  CHECK(!coap_q_bind_response(session,lg,old_response));
  CHECK(!session->recipient_ctx&&!oscore_find_association(session,&token));
  association(1); /* Same PIV bytes after recipient recreation cannot reuse identity. */
  CHECK(!coap_q_bind_response(session,lg,old_response));
  /* A real new request restores the session recipient and owns a fresh stamp.
   * Merely inserting a synthetic association does not perform that receive path. */
  ctx->p_osc_ctx->rfc8613_b_1_2=0;ctx->p_osc_ctx->recipient_chain->initial_state=0;
  input=authenticated_request(0,0);decoded=coap_oscore_decrypt_pdu(session,input);CHECK(decoded);
  CHECK(session->recipient_ctx==ctx->p_osc_ctx->recipient_chain);
  fresh=response(COAP_MESSAGE_CON,0,1);
  fresh->oscore_request_generation=decoded->oscore_request_generation;
  CHECK(coap_q_bind_response(session,lg,fresh));
  CHECK(lg->oscore_binding->recipient_ctx==ctx->p_osc_ctx->recipient_chain);
  CHECK(lg->oscore_binding->partial_iv->length==1&&lg->oscore_binding->partial_iv->s[0]==20);
  CHECK(coap_send_internal(session,fresh)!=COAP_INVALID_MID&&writes==1);
  coap_delete_pdu_lkd(decoded);coap_delete_pdu_lkd(input);
  coap_delete_pdu_lkd(old_response);teardown();
}
static void context_isolation_and_real_teardown(void) {
  coap_lg_xmit_t *lg,*unrelated;coap_pdu_t *p,*q;
  oscore_ctx_t distinct_context={0};oscore_recipient_ctx_t distinct_recipient={0};
  coap_queue_t *node;
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);CHECK(coap_q_bind_response(session,lg,p));
  unrelated=transfer();q=response(COAP_MESSAGE_CON,0,1);association(2);stamp(q);CHECK(coap_q_bind_response(session,unrelated,q));
  distinct_recipient.osc_ctx=&distinct_context;distinct_recipient.recipient_id=&rid;
  unrelated->oscore_binding->recipient_ctx=&distinct_recipient;
  association(3);oscore_find_association(session,&token)->recipient_ctx=&distinct_recipient;
  other->recipient_ctx=&distinct_recipient;
  CHECK(coap_delete_oscore_recipient_lkd(ctx,&rid));
  CHECK(!lg->oscore_binding&&unrelated->oscore_binding);
  CHECK(oscore_find_association(session,&token)->recipient_ctx==&distinct_recipient);
  CHECK(other->recipient_ctx==&distinct_recipient&&!session->recipient_ctx);
  CHECK(coap_q_response_binding(session,q));
  coap_delete_pdu_lkd(p);coap_delete_pdu_lkd(q);drop_transfer(unrelated);drop_transfer(lg);teardown();
  /* Real delayed-node/session destructor ordering, not a synthetic queue scan. */
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);CHECK(coap_q_bind_response(session,lg,p));
  node=coap_new_node();CHECK(node);node->pdu=p;node->id=p->mid;session->delayqueue=node;
  teardown();
  /* Real context destructor detaches sendqueue before node-release callbacks can
   * trigger session destruction and transfer invalidation. */
  setup();lg=transfer();p=response(COAP_MESSAGE_CON,0,1);association(1);stamp(p);CHECK(coap_q_bind_response(session,lg,p));
  CHECK(coap_send_internal(session,p)!=COAP_INVALID_MID);CHECK(ctx->sendqueue);
  teardown();
}
int main(void) {
  coap_startup();coap_set_log_level(COAP_LOG_EMERG);
  ownership();crypto_and_errors();queue_expiry_and_context();transport_and_allocation();
  ack_retry_and_final_cleanup();cached_fresh_request();context_isolation_and_real_teardown();delete_before_bind_and_recreate();stale_prebind_request();
  authenticated_commit_failures();accepted_zero_bad_mac_recovery();authenticated_server_challenges();callback_request_replacement();
  coap_cleanup();puts("PASS protected Q2 owned binding, generation, rollback, nonce, dynamic teardown and callback retirement");return 0;
}

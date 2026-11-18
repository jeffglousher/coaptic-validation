"""Prepare one diagnostic kernel copy; never modify an installed SDK.

The selected IDF non-SMP kernel runs two cores. Its existing run-time accounting
includes attributed ISR time. Added hooks only observe target task transitions
under the kernel lock. Ready-off-task includes scheduler yields and preemption.
"""
import hashlib
from pathlib import Path

KERNEL_SHA256 = '193c3d8379acc847097632da8e6d4dd2ee0bf8e069d78979d68dd26b653d48df'

ADDITIONS = r'''
#if configGENERATE_RUN_TIME_STATS != 1 || !CONFIG_FREERTOS_RUN_TIME_STATS_USING_ESP_TIMER || !CONFIG_FREERTOS_RUN_TIME_COUNTER_TYPE_U64 || CONFIG_FREERTOS_SMP || configNUMBER_OF_CORES != 2
#error Unsupported Coaptic CPU diagnostic kernel configuration
#endif
_Static_assert(sizeof(configRUN_TIME_COUNTER_TYPE) == 8, "64-bit runtime required");
/* Coaptic finite diagnostic only; all fields are protected by xKernelLock. */
static TCB_t * coaptic_cpu_owner = NULL;
static uint64_t coaptic_cpu_blocked = 0, coaptic_cpu_ready = 0;
static uint64_t coaptic_cpu_changed = 0;
/* 0 running, 1 blocked, 2 ready but not scheduled. */
static unsigned coaptic_cpu_mode = 0;

static void coaptic_cpu_transition( unsigned next, uint64_t now )
{
    configASSERT( now >= coaptic_cpu_changed );
    if( coaptic_cpu_mode == 1 ) coaptic_cpu_blocked += now - coaptic_cpu_changed;
    if( coaptic_cpu_mode == 2 ) coaptic_cpu_ready += now - coaptic_cpu_changed;
    coaptic_cpu_changed = now;
    coaptic_cpu_mode = next;
}
static void coaptic_cpu_became_ready( TCB_t * task )
{
    if( task == coaptic_cpu_owner && coaptic_cpu_mode == 1 )
        coaptic_cpu_transition( 2, portGET_RUN_TIME_COUNTER_VALUE() );
}
static void coaptic_cpu_switched_out( TCB_t * task, uint64_t now )
{
    if( task == coaptic_cpu_owner )
        coaptic_cpu_transition( listIS_CONTAINED_WITHIN( &pxReadyTasksLists[ task->uxPriority ], &task->xStateListItem ) ? 2 : 1, now );
}
static void coaptic_cpu_switched_in( TCB_t * task, uint64_t now )
{
    if( task == coaptic_cpu_owner ) coaptic_cpu_transition( 0, now );
}
/* Only the worker calls this. No counter, scheduler or admission state changes. */
void coaptic_cpu_snapshot( uint64_t values[ 4 ] )
{
    taskENTER_CRITICAL( &xKernelLock );
    const BaseType_t core = portGET_CORE_ID();
    TCB_t * task = pxCurrentTCBs[ core ];
    const uint64_t now = portGET_RUN_TIME_COUNTER_VALUE();
    if( coaptic_cpu_owner == NULL ) { coaptic_cpu_owner = task; coaptic_cpu_changed = now; }
    configASSERT( coaptic_cpu_owner == task );
    configASSERT( coaptic_cpu_mode == 0 );
    configASSERT( now >= ulTaskSwitchedInTime[ core ] );
    values[ 0 ] = now;
    values[ 1 ] = task->ulRunTimeCounter + now - ulTaskSwitchedInTime[ core ];
    values[ 2 ] = coaptic_cpu_blocked;
    values[ 3 ] = coaptic_cpu_ready;
    taskEXIT_CRITICAL( &xKernelLock );
}
'''

def once(source, anchor, replacement):
    if source.count(anchor) != 1:
        raise ValueError('unexpected diagnostic anchor: '+anchor[:70])
    return source.replace(anchor, replacement, 1)


def patch_kernel(data):
    if hashlib.sha256(data).hexdigest() != KERNEL_SHA256:
        raise ValueError('only exact reviewed IDF5.5.5 kernel supported')
    source = data.decode().replace('\r\n','\n')
    marker = '/* File private functions. --------------------------------*/'
    source = once(source, marker, ADDITIONS+'\n'+marker)
    source = once(source, '    tracePOST_MOVED_TASK_TO_READY_STATE( pxTCB )',
                  '    tracePOST_MOVED_TASK_TO_READY_STATE( pxTCB ); \\\n    coaptic_cpu_became_ready( pxTCB )')
    marker = '                ulTaskSwitchedInTime[ xCurCoreID ] = ulTotalRunTime;'
    source = once(source, marker, '                coaptic_cpu_switched_out( pxCurrentTCBs[ xCurCoreID ], ulTotalRunTime );\n'+marker)
    marker = '            traceTASK_SWITCHED_IN();'
    source = once(source, marker, '            coaptic_cpu_switched_in( pxCurrentTCBs[ xCurCoreID ], ulTotalRunTime );\n'+marker)
    return source.encode()


def write_kernel(source: Path, output: Path):
    patched = patch_kernel(source.read_bytes())
    with output.open('xb') as stream:
        stream.write(patched)
    return hashlib.sha256(patched).hexdigest()

CPP_ADDITIONS = r'''
// Finite diagnostic metadata only. Normal firmware does not compile this copy.
extern "C" void coaptic_cpu_snapshot(uint64_t values[4]);
struct CpuRow { uint64_t v[4]; uint32_t mid, hi, lo, bytes; uint8_t kind; };
static constexpr uint32_t CPU_ROWS = 512;
static CpuRow cpu_rows[CPU_ROWS]{};
static std::atomic<uint32_t> cpu_count{0}, cpu_last_ms{0};
static std::atomic<bool> cpu_frozen{false}, cpu_overflow{false};
static bool cpu_active = false;  // sole worker owner
static CpuRow cpu_take(uint8_t kind, const uint8_t *bytes=nullptr, uint32_t length=0) {
  CpuRow row{}; row.kind=kind; row.bytes=length; row.mid=65536;
  coaptic_cpu_snapshot(row.v);
  if (bytes && length >= 4) row.mid=(uint32_t(bytes[2])<<8)|bytes[3];
  if (bytes && length >= 12 && (bytes[0]&15)==8) {
    row.hi=(uint32_t(bytes[4])<<24)|(uint32_t(bytes[5])<<16)|(uint32_t(bytes[6])<<8)|bytes[7];
    row.lo=(uint32_t(bytes[8])<<24)|(uint32_t(bytes[9])<<16)|(uint32_t(bytes[10])<<8)|bytes[11];
  }
  return row;
}
static void cpu_publish(const CpuRow &row) {
  if (cpu_frozen.load(std::memory_order_acquire)) return;
  const auto index=cpu_count.load(std::memory_order_relaxed);
  if (index == CPU_ROWS) { cpu_overflow.store(true,std::memory_order_release); return; }
  cpu_rows[index]=row;
  cpu_count.store(index+1,std::memory_order_release);
}
static void cpu_record(uint8_t kind, const uint8_t *bytes=nullptr, uint32_t length=0) {
  if (!cpu_active || cpu_frozen.load(std::memory_order_acquire)) return;
  cpu_publish(cpu_take(kind,bytes,length));
  if (kind==1 || kind==3) cpu_last_ms.store(esp_timer_get_time()/1000,std::memory_order_release);
}
struct CpuSpan {
  uint8_t end;
  explicit CpuSpan(uint8_t kind):end(kind+1) { cpu_record(kind); }
  ~CpuSpan() { cpu_record(end); }
};
static void cpu_dump(const char *id, uint32_t rx, uint32_t tx, TaskHandle_t task) {
  static uint64_t resource_at=0;
  const uint64_t at=esp_timer_get_time();
  if (!cpu_frozen.load(std::memory_order_acquire) && (resource_at==0 || (rx>0 && at-resource_at>=500000))) {
    resource_at=at;
    const auto caps=MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT;
    ESP_LOGI(TAG,"COAPTIC_CPU_RESOURCE run=%s at=%llu rx=%lu tx=%lu free=%u minimum=%u largest=%u stack_free=%lu",
      id,(unsigned long long)at,(unsigned long)rx,(unsigned long)tx,
      unsigned(heap_caps_get_free_size(caps)),unsigned(heap_caps_get_minimum_free_size(caps)),
      unsigned(heap_caps_get_largest_free_block(caps)),(unsigned long)(task?uxTaskGetStackHighWaterMark(task):0));
  }
  if (cpu_frozen.load(std::memory_order_acquire)) return;
  const auto last=cpu_last_ms.load(std::memory_order_acquire);
  if (!last || uint32_t(esp_timer_get_time()/1000)-last<5000) return;
  cpu_frozen.store(true,std::memory_order_release);
  const auto count=cpu_count.load(std::memory_order_acquire);
  for (uint32_t i=0;i<count;i++) {
    const auto &x=cpu_rows[i];
    ESP_LOGI(TAG,"COAPTIC_CPU run=%s i=%lu k=%u w=%llu c=%llu b=%llu r=%llu mid=%lu tok=%08lx%08lx n=%lu",
      id,(unsigned long)i,x.kind,(unsigned long long)x.v[0],(unsigned long long)x.v[1],
      (unsigned long long)x.v[2],(unsigned long long)x.v[3],(unsigned long)x.mid,
      (unsigned long)x.hi,(unsigned long)x.lo,(unsigned long)x.bytes);
  }
  ESP_LOGI(TAG,"COAPTIC_CPU_END run=%s count=%lu overflow=%s rows_bytes=%u",id,(unsigned long)count,
    cpu_overflow.load()?"true":"false",unsigned(sizeof(cpu_rows)));
}
'''


def patch_component(data):
    source = data.decode().replace('\r\n','\n')
    source = once(source, 'static constexpr const char *TAG = "coaptic_network";',
                  'static constexpr const char *TAG = "coaptic_network";\n'+CPP_ADDITIONS)
    source = once(source, 'void CoapticNetwork::loop() {',
                  'void CoapticNetwork::loop() {\n  cpu_dump(run_id_.c_str(),rx_.load(),tx_.load(),task_);')
    marker = '  *peer = (static_cast<uint64_t>(ntohl(address.sin_addr.s_addr)) << 16) | ntohs(address.sin_port);'
    source = once(source, marker, marker+'\n  cpu_active=true; cpu_record(1,bytes,length);')
    marker = '  int sent = sendto(socket_, bytes, length, 0, reinterpret_cast<sockaddr *>(&address), sizeof(address));'
    source = once(source, marker, '  cpu_record(2,bytes,length);\n'+marker+'\n  cpu_record(3,bytes,length);')
    marker = '  const int ready = select(maximum + 1, &reads, &writes, nullptr, timeout_ptr);'
    source = once(source, marker, '''  const auto cpu_wait_start=cpu_take(8);
'''+marker+'''
  if (ready>0 && FD_ISSET(socket_, &reads)) {
    cpu_publish(cpu_wait_start); cpu_publish(cpu_take(9));
  }''')
    # The same diagnostic can measure sync. Publish a select pair only on input,
    # so idle 10ms polling does not consume the finite ledger before traffic.
    marker = '  const int ready = select(socket_ + 1, &read_set, nullptr, nullptr, &timeout);'
    source = once(source, marker, '''  const auto cpu_wait_start=cpu_take(8);
'''+marker+'''
  if (ready>0) { cpu_publish(cpu_wait_start); cpu_publish(cpu_take(9)); }''')
    source = once(source, 'int32_t CoapticNetwork::read_security(uint8_t *bytes, uint32_t length) {',
                  'int32_t CoapticNetwork::read_security(uint8_t *bytes, uint32_t length) {\n  CpuSpan cpu_span(4);')
    source = once(source, 'bool CoapticNetwork::commit_security(const uint8_t *bytes, uint32_t length) {',
                  'bool CoapticNetwork::commit_security(const uint8_t *bytes, uint32_t length) {\n  CpuSpan cpu_span(6);')
    return source.encode()

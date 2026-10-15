import json
from pathlib import Path

here=Path(__file__).resolve().parent
summary=json.loads((here/'summary.json').read_text())
fields=('case','peer','security','median_completed_per_second','median_goodput_bytes_per_second','median_session_p50_ns',
        'median_session_p99_ns','failed_requests','warmup_failures','driver_failures','invalid_sessions','sessions',
        'comparison_eligible','completed_rate_vs_reference','workload','median_scoped_server_cpu_us_per_completion','interpretation')
data={k:v for k,v in summary.items() if k not in ('matched','regression','regression_provenance')}
for name in ('matched','regression'):
    data[name]=[{k:r[k] for k in fields if k in r} for r in summary[name]]
template=r'''import { useState, useHostTheme, Stack, Row, Grid, H1, H2, Text, Table, Select, Pill, BarChart, Callout, Card, CardHeader, CardBody, Link } from "cursor/canvas";
const evidence = __DATA__;
const names: Record<string,string> = {"coaptic":"Coaptic", "coaptic-oscore":"Coaptic OSCORE", "coaptic-5039":"Coaptic 5039", "aiocoap":"aiocoap", "aiocoap-oscore":"aiocoap OSCORE", "coap-rs":"coap-rs", "go-coap":"plgd/go-coap", "libcoap":"libcoap", "coap-lite-codec":"coap-lite codec fixture"};
const number = (v:number|null|undefined, digits=1) => v == null ? "Unmeasured" : v.toLocaleString(undefined,{maximumFractionDigits:digits});
const interval = (v:{ratio:number|null, confidence_95:number[]|null}) => v.ratio == null ? "Descriptive only" : `${number(v.ratio,3)}×${v.confidence_95 ? ` [${number(v.confidence_95[0],3)}, ${number(v.confidence_95[1],3)}]` : "; interval unavailable"}`;
export default function Performance() {
 const theme=useHostTheme();
 const [tab,setTab]=useState("matched");
 const [security,setSecurity]=useState("OSCORE-AES-CCM-16-64-128");
 const [bytes,setBytes]=useState("65536"); const [mode,setMode]=useState("con"); const [concurrency,setConcurrency]=useState("1");
 const selected=(tab==="native"?evidence.regression:evidence.matched).filter(r=>r.workload.bytes===Number(bytes) && r.workload.mode===mode && r.workload.concurrency===Number(concurrency) && (tab==="native" || r.security===security));
 const overhead=evidence.security_overhead.filter(r=>r.bytes===Number(bytes)&&r.mode===mode&&r.concurrency===Number(concurrency));
 return <Stack gap={16} style={{padding:24,maxWidth:1200,margin:"auto",background:theme.bg.editor,color:theme.text.primary}}>
  <H1>Coaptic: matched network performance</H1>
  <Text>Preliminary Windows loopback measurements of core 9a96d9b and suite 93155b5. Ten complete sessions per campaign. Source baseline: 5039b5a. The full result includes every measured failure.</Text>
  <Row gap={16} wrap><Text weight="semibold">{number(evidence.totals.matched.completed,0)} / {number(evidence.totals.matched.attempted,0)} matched transfers completed</Text><Text>{evidence.totals.matched.failed} measured failures; {evidence.totals.matched.warmup_failed} warmup failures</Text><Text>{number(evidence.totals.regression.completed,0)} native source-comparison transfers completed</Text></Row>
  <Row gap={8}>{[["matched","Matched servers"],["native","Native source comparison"],["scope","Coverage and provenance"]].map(([value,label])=><Pill key={value} active={tab===value} onClick={()=>setTab(value)}>{label}</Pill>)}</Row>
  {tab!=="scope" && <>
   <Row gap={12} wrap>
    {tab==="matched"&&<Select value={security} onChange={setSecurity} options={[{value:"plaintext",label:"Plaintext CoAP"},{value:"OSCORE-AES-CCM-16-64-128",label:"OSCORE / AES-CCM-16-64-128"}]} />}
    <Select value={bytes} onChange={setBytes} options={[{value:"64",label:"64 B / small body"},{value:"1024",label:"1 KiB / small body"},{value:"65536",label:"64 KiB / complete Block2"}]} />
    <Select value={mode} onChange={setMode} options={[{value:"con",label:"Confirmable (CON)"},{value:"non",label:"Non-confirmable (NON)"}]} />
    <Select value={concurrency} onChange={setConcurrency} options={[1,4,16].map(v=>({value:String(v),label:`Concurrency ${v}`}))} />
   </Row>
   <H2>{tab==="native"?"Current versus prior source":"Median completed representation rate"}</H2>
   <Text tone="secondary" size="small">Horizontal axis: verified complete representations/s. Vertical axis: server fixture. Each bar is the median of ten session rates. Source: retained benchmark cells, {evidence.time_range.start} to {evidence.time_range.end}.</Text>
   <BarChart horizontal categories={selected.map(r=>names[r.peer]||r.peer)} series={[{name:"Median complete representations/s",data:selected.map(r=>r.median_completed_per_second||0),tone:"neutral"}]} height={Math.max(210,selected.length*46)} valueSuffix=" /s" showValues />
   <Table headers={["Fixture","Complete /s","Payload MiB/s","Session p50 (µs)","Session p99 (ms)","Failed / warmup","Paired rate ratio [95% CI]","Inference"]}
    rows={selected.map(r=>[names[r.peer]||r.peer,number(r.median_completed_per_second),number((r.median_goodput_bytes_per_second||0)/1048576,3),number((r.median_session_p50_ns||0)/1000),number((r.median_session_p99_ns||0)/1e6,3),`${r.failed_requests} / ${r.warmup_failures}`,interval(r.completed_rate_vs_reference),r.comparison_eligible?"Eligible within profile":"Descriptive"])} columnAlign={["left","right","right","right","right","right","left","left"]} />
   <Text tone="secondary" size="small">Matched ratios compare each server with Coaptic in the same security profile and common Python driver. Native ratios compare current Coaptic with 5039 using the same native Rust driver. Intervals are exploratory and unadjusted across cases. Failed profiles are not ranked.</Text>
   {tab==="matched"&&<>
    <H2>Matched end-to-end OSCORE cost</H2>
    <Table headers={["Implementation","OSCORE rate / plaintext rate [95% CI]","Excluded pairs","Inference"]} rows={overhead.map(r=>[names[r.implementation],interval(r.protected_completed_rate_vs_plaintext),r.excluded_pairs,r.comparison_eligible?"Eligible within profile":"Descriptive"])} />
    <Text tone="secondary">This includes both driver and server cryptography, shared sender sequencing, Python/GIL scheduling and byte validation. It is not isolated cipher cost or a server-capacity measurement.</Text>
   </>}
  </>}
  {tab==="scope"&&<>
   <H2>Scope and unsupported combinations</H2>
   <Table headers={["Fixture / profile","Status","Reason"]} rows={evidence.coverage.map(r=>[r.peer,r.security,r.reason])} />
   <Grid columns={2} gap={24}>
    <Stack><H2>Controlled configuration</H2><Text>IPv4 loopback; 64 B, 1 KiB and 64 KiB; CON/NON; concurrency 1/4/16; one-second complete-body deadline. OSCORE uses one ephemeral shared identity and a 32-entry replay window, with ordered local sequence reservation and dispatch.</Text><Text>Coaptic uses bounded allocation-backed pools: four RX/TX datagram slots, 1472-byte datagrams, eight dedup entries, one RX body and two TX bodies sized to the representation. Other server runtime choices remain identified in the manifest.</Text></Stack>
    <Stack><H2>Host observations</H2><Text>{evidence.host.processor}; 8 physical cores / 16 logical CPUs; {number(evidence.host.memory_total_bytes/1073741824,2)} GiB physical RAM.</Text><Text>Whole-host busy fraction: {number(evidence.host.host_busy_percent.min)}–{number(evidence.host.host_busy_percent.max)}%. Available RAM: {number((evidence.host.available_memory_bytes.min||0)/1073741824,2)}–{number((evidence.host.available_memory_bytes.max||0)/1073741824,2)} GiB. These include colocated work.</Text><Text>Server CPU accounting includes driver startup, warmup and exit. Host RAM is not SUT allocation/RSS or a constrained-device ceiling.</Text></Stack>
   </Grid>
   <H2>Retained pilot</H2><Text>Six complete matched sessions and six native source sessions, plus 27 partial matched cells, remain retained at suite 68bed08. The prototype recorded three measured deadline misses and one warmup miss. Its replay-window mismatch, unsequenced local dispatch and missing sampler keep it separate from final inference.</Text>
   <H2>Methods and limits</H2>{evidence.limits.map((limit,i)=><Text key={i}>{limit}</Text>)}
  </>}
  <Callout tone="warning" title="Interpretation">These are complete-body, closed-loop process/socket measurements on a shared host. Successful-request tails, deadline failures and scoped CPU samples describe this configuration. They do not establish production security, steady-state memory, server saturation, hardware performance or a fastest-library ranking.</Callout>
  <Card collapsible defaultOpen={false}><CardHeader>Source and evidence</CardHeader><CardBody><Stack gap={8}>
   <Text>Core: {evidence.sources.library.revision}; tree {evidence.sources.library.tree}.</Text><Text>Suite: {evidence.sources.suite.revision}; tree {evidence.sources.suite.tree}.</Text><Text>Original sources, binary hashes, lockfile, dependency trees, host metadata, failures and latency samples are retained. No benchmark credentials are included.</Text>
   <Link href="https://github.com/jeffglousher/coaptic-validation/pull/65">Implementation PR #65</Link><Link href="https://github.com/jeffglousher/coaptic/issues/534">Finite campaign and evidence #534</Link><Link href="https://github.com/jeffglousher/coaptic/issues/341">Remaining comparative qualification #341</Link>
  </Stack></CardBody></Card>
 </Stack>;
}
'''
target=Path('C:/Users/jeffg/.cursor/projects/C-Users-jeffg-t3-worktrees-coaptic-t3code-06975ac1/canvases/coaptic-performance-20261013.canvas.tsx')
target.write_text(template.replace('__DATA__',json.dumps(data,separators=(',',':'),allow_nan=False)),encoding='utf-8')
print(target)

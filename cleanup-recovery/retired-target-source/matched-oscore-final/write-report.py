import json
from pathlib import Path

here=Path(__file__).resolve().parent
data=json.loads((here/'summary.json').read_text())
def row(peer,size,collection='matched',concurrency=1,mode='con'):
    return next(r for r in data[collection] if r['peer']==peer and r['workload']['bytes']==size and r['workload']['concurrency']==concurrency and r['workload']['mode']==mode)
def number(value):
    return f'{value:,.1f}'
def ratio(value):
    interval=value['confidence_95']
    return f"{value['ratio']:.3f}x"+(f"; marginal 95% interval [{interval[0]:.3f}, {interval[1]:.3f}]" if interval else '; interval unavailable')
matched=data['totals']['matched']; native=data['totals']['regression']
lines=[f"Measured core `{data['sources']['library']['revision']}` and companion `{data['sources']['suite']['revision']}`; clean sources. Baseline core `5039b5af791bdc95327992caeef798b2740731c8`. Version remains 0.0.10.",
       f"Ten final matched sessions: {matched['completed']:,}/{matched['attempted']:,} complete representations, {matched['failed']} measured failures, {matched['warmup_failed']} warmup failures, {matched['invalid_cells']} invalid cells. Ten separate native source sessions: {native['completed']:,}/{native['attempted']:,} completed, {native['failed']} measured and {native['warmup_failed']} warmup failures.",
       'Median verified complete representations/second for CON, concurrency 1; values are **64 B / 1 KiB / complete 64 KiB Block2**:', '']
for peer in ('coaptic','coap-rs','libcoap','go-coap','aiocoap','coap-lite-codec','coaptic-oscore','aiocoap-oscore'):
    values=' / '.join(number(row(peer,size)['median_completed_per_second']) for size in (64,1024,65536))
    lines.append(f'- {peer}: {values}.')
lines += ['', 'The coap-lite row is a narrower codec fixture. OSCORE rows use the same external Python UDP driver as the plaintext controls, AES-CCM-16-64-128/HKDF-SHA-256, a 32-entry replay window and one ephemeral shared identity. Reservation through local dispatch is serialized. Their rates include driver/server cryptography, Python/GIL scheduling and full byte validation; they are separate from native-driver timings.',
          '', 'Native current/5039 source comparison, identical fixture source, compiler, lockfile, features and resource configuration:', '']
for size,concurrency in ((64,1),(65536,1),(65536,4),(65536,16)):
    current=row('coaptic',size,'regression',concurrency); old=row('coaptic-5039',size,'regression',concurrency)
    lines.append(f"- CON {size:,} B, concurrency {concurrency}: {number(current['median_completed_per_second'])} current versus {number(old['median_completed_per_second'])} prior representations/s; paired rate {ratio(current['completed_rate_vs_reference'])}; {current['interpretation']}.")
labels={name:sum(r['interpretation']==name for r in data['regression'] if r['peer']=='coaptic') for name in ('higher rate in this cell','lower rate in this cell','inconclusive','descriptive')}
lines += ['', f"Across all 18 native source cells: {labels['higher rate in this cell']} have higher-rate intervals, {labels['lower rate in this cell']} lower-rate intervals, {labels['inconclusive']} overlap parity, {labels['descriptive']} are descriptive. These are exploratory, marginal intervals without multiple-comparison adjustment; they do not establish general improvement, regression or equivalence.",
          '', 'Final failing profiles (all attempts and wall time retained):', '']
for r in data['matched']:
    if r['failed_requests'] or r['warmup_failures'] or r['invalid_sessions']:
        lines.append(f"- {r['peer']} / {r['case']}: {r['failed_requests']} measured, {r['warmup_failures']} warmup and {r['invalid_sessions']} invalid-session failures. Paired ranking eligibility: {r['comparison_eligible']}.")
lines += ['', f"Host: AMD Ryzen 7 5800X3D, 8 cores/16 logical CPUs, Windows x64, about 31.9 GiB physical RAM; shared with other work. Per-cell host busy fraction spans {data['host']['host_busy_percent']['min']:.1f}–{data['host']['host_busy_percent']['max']:.1f}%. UTC range: {data['time_range']['start']} to {data['time_range']['end']}.",
          '', 'The retained prototype at suite 68bed08 contains six complete matched/source sessions and 27 partial matched cells, including three measured and one warmup deadline misses. Its unaligned replay retention, unsequenced local dispatch and absent sampler keep it separate from final inference. Original cells and failures remain retained.',
          '', 'Limits: closed-loop IPv4 loopback, unchanged one-second complete-body deadline and no retransmission; no server-saturation, corrected-tail, hardware, enrollment or durable-counter claim. Server CPU includes driver startup/warmup/exit; host available RAM is not SUT allocation/RSS. DTLS, protected libcoap, impairment, HTTP/3, driver capacity, memory/diagnostic-overhead and broader platforms remain #341 work.',
          '', 'Focused verification: 46 Python tests, real UDP protected success/refusal/fresh recovery, 16-cell smoke, four protected 64 KiB/concurrency-16 preflight cells, formatting and warning-free native Clippy. Hosted PR checks passed. Benchmark source, complete samples, binary/dependency hashes, locks, setup methods and original failures are retained separately from this summary.']
(here/'public-results.md').write_text('\n\n'.join(lines),encoding='utf-8')
print('\n'.join(lines))

//! Detached, finite kernel execution cost sample; no NIC or throughput claim.
use aya::{
    Ebpf,
    programs::{TestRun, TestRunOptions, Xdp},
};
use coaptic_ingress_classifier::{COUNTERS, Class, MAX_FRAME, TOTAL, classify};
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const BATCHES: usize = 5;
const REPEAT: u32 = 10_000;
const WARMUP: u32 = 100;

fn frames() -> [(&'static str, Vec<u8>, Class); 4] {
    use crate::probe::vectors::packet;
    let mut plain = vec![0x40, 1, 0, 1, 0xff];
    plain.extend_from_slice(&[0x5a; 32]);
    let mut other_port = packet(&plain, false);
    other_port[34..38].copy_from_slice(&[0x23, 0x28, 0x23, 0x28]);
    // Public RFC 8613 C.4 request; the classifier observes only its outer syntax.
    let protected = [
        0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
        0x6f, 0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
        0x16, 0x68, 0xb3, 0x82, 0x5e,
    ];
    // 126 one-byte Uri-Path options exercise traversal at the 256-byte ceiling.
    let mut options = vec![0x40, 1, 0, 1, 0xb1, b'x'];
    for _ in 0..125 {
        options.extend_from_slice(&[0x01, b'x']);
    }
    [
        ("other-port-ipv4", other_port, Class::Uninspected),
        ("plain-32b-ipv4", packet(&plain, false), Class::CoapSyntax),
        (
            "opaque-oscore-ipv6",
            packet(&protected, true),
            Class::CoapSyntax,
        ),
        (
            "126-options-ipv6",
            packet(&options, true),
            Class::CoapSyntax,
        ),
    ]
}

fn execute(bpf: &Ebpf, name: &str, frame: &[u8], repeat: u32) -> Result<u64> {
    let program: &Xdp = bpf
        .program(name)
        .ok_or("missing cost program")?
        .try_into()?;
    let mut output = [0xa5; MAX_FRAME + 256];
    let result = program.test_run(TestRunOptions {
        data_in: Some(frame),
        data_out: Some(&mut output),
        repeat,
        ..Default::default()
    })?;
    if result.return_value != 2
        || result.data_size_out as usize != frame.len()
        || output[..frame.len()] != *frame
    {
        return Err(format!("cost run changed action/bytes: {name}: {result:?}").into());
    }
    // Linux returns the integer average across repetitions, not total duration.
    Ok(u64::try_from(result.duration.as_nanos())?)
}

pub(super) fn run(object: &str) -> Result<()> {
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if cpu as usize >= libc::CPU_SETSIZE as usize {
        return Err("cost CPU exceeds fixed affinity set".into());
    }
    let _affinity = crate::probe::Affinity::pin(cpu as usize)?;
    let mut bpf = Ebpf::load_file(object)?;
    for name in ["coaptic_pass", "coaptic_observe"] {
        let program: &mut Xdp = bpf
            .program_mut(name)
            .ok_or("missing cost program")?
            .try_into()?;
        program.load()?;
    }
    let initial = crate::probe::counters(&bpf)?;
    let mut expected = initial;
    let mut samples = Vec::with_capacity(4);
    for (ordinal, (name, frame, class)) in frames().into_iter().enumerate() {
        if frame.len() > MAX_FRAME || classify(&frame) != class {
            return Err(format!("cost fixture differs: {name}").into());
        }
        let mut baseline_ns = [0; BATCHES];
        let mut observe_ns = [0; BATCHES];
        for batch in 0..=BATCHES {
            let repeat = if batch == 0 { WARMUP } else { REPEAT };
            // Alternate order to avoid consistently warming one program first.
            for position in 0..2 {
                let observe = (position + batch + ordinal) % 2 == 1;
                let program = if observe {
                    "coaptic_observe"
                } else {
                    "coaptic_pass"
                };
                let ns = execute(&bpf, program, &frame, repeat)?;
                if observe {
                    expected[class as usize] += u64::from(repeat);
                    expected[TOTAL as usize] += u64::from(repeat);
                }
                if crate::probe::counters(&bpf)? != expected {
                    return Err(format!(
                        "cost counter delta differs: {name} {program} batch={batch}"
                    )
                    .into());
                }
                if batch != 0 {
                    if observe {
                        observe_ns[batch - 1] = ns;
                    } else {
                        baseline_ns[batch - 1] = ns;
                    }
                }
            }
        }
        samples.push(serde_json::json!({
            "name": name, "frame_bytes": frame.len(), "class": class as u32,
            "baseline_ns": baseline_ns, "observe_ns": observe_ns,
        }));
    }
    let deltas: [u64; COUNTERS as usize] = std::array::from_fn(|i| expected[i] - initial[i]);
    println!(
        "{}",
        serde_json::json!({
            "kind": "detached-kernel-cost", "cpu": cpu,
            "repeat_per_batch": REPEAT, "batches": BATCHES, "warmup_per_program_frame": WARMUP,
            "unit": "kernel-reported integer average ns/invocation", "samples": samples,
            "classifier_counter_deltas": deltas, "action": "XDP_PASS", "bytes": "unchanged",
            "scope": "detached test_run; no network delivery, NIC throughput or end-to-end benefit claim",
        })
    );
    Ok(())
}

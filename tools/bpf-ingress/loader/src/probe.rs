//! Finite kernel qualification; compiled only in the Linux loader.
use aya::{
    Ebpf,
    maps::PerCpuArray,
    programs::{TestRun, TestRunOptions, Xdp},
};
use coaptic_ingress_classifier::{COUNTERS, TOTAL, classify};
use std::{
    error::Error,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::Command,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[path = "../../vectors.rs"]
pub(super) mod vectors;

pub(super) fn counters(bpf: &Ebpf) -> Result<[u64; COUNTERS as usize]> {
    let counts: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf.map("COUNTS").ok_or("missing COUNTS")?)?;
    let mut out = [0; COUNTERS as usize];
    for (index, value) in out.iter_mut().enumerate() {
        *value = counts.get(&(index as u32), 0)?.iter().copied().sum();
    }
    Ok(out)
}

pub(super) fn differential(bpf: &mut Ebpf) -> Result<()> {
    let mut expected = [0u64; COUNTERS as usize];
    let baseline = counters(bpf)?;
    let mut unavailable_short = 0;
    let mut executed = 0;
    for (ordinal, frame) in vectors::corpus().into_iter().enumerate() {
        let class = classify(&frame) as usize;
        let mut output = vec![0xa5; frame.len() + 256];
        let program: &mut Xdp = bpf
            .program_mut("coaptic_observe")
            .ok_or("missing program")?
            .try_into()?;
        let result = program.test_run(TestRunOptions {
            data_in: Some(&frame),
            data_out: Some(&mut output),
            repeat: 1,
            ..Default::default()
        });
        // Linux refuses inputs shorter than ETH_HLEN before entering XDP. These
        // remain portable-only vectors, never counted as executed hook cases.
        if frame.len() < 14 {
            match result {
                Err(aya::programs::ProgramError::SyscallError(error))
                    if error.io_error.raw_os_error() == Some(libc::EINVAL) =>
                {
                    unavailable_short += 1;
                    if counters(bpf)? != std::array::from_fn(|i| baseline[i] + expected[i]) {
                        return Err("rejected short frame changed counters".into());
                    }
                    continue;
                }
                other => {
                    return Err(
                        format!("unexpected short-frame result {ordinal}: {other:?}").into(),
                    );
                }
            }
        }
        let result = result?;
        if result.return_value != 2
            || result.data_size_out as usize != frame.len()
            || output[..frame.len()] != frame
        {
            return Err(
                format!("kernel changed action/bytes at vector {ordinal}: {result:?}").into(),
            );
        }
        expected[class] += 1;
        expected[TOTAL as usize] += 1;
        let observed = counters(bpf)?;
        for index in 0..COUNTERS as usize {
            if observed[index] != baseline[index] + expected[index] {
                return Err(format!(
                    "counter mismatch vector={ordinal} counter={index} expected={} observed={}",
                    baseline[index] + expected[index],
                    observed[index]
                )
                .into());
            }
        }
        executed += 1;
    }
    println!(
        "kernel differential PASS executed={executed} kernel_refused_short={unavailable_short} deltas={expected:?}; XDP_PASS and exact unchanged bytes"
    );
    Ok(())
}

pub(super) fn attached(name: &str, expected: Option<u32>) -> Result<()> {
    let output = Command::new("ip")
        .args(["-j", "link", "show", "dev", name])
        .output()?;
    if !output.status.success() {
        return Err("interface inspection failed".into());
    }
    let links: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let link = links
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("interface identity ambiguous")?
        .first()
        .unwrap();
    let xdp = link.get("xdp");
    let actual_id = xdp
        .and_then(|x| x.get("prog"))
        .and_then(|prog| prog.get("id"))
        .and_then(|id| id.as_u64());
    let actual_mode = xdp
        .and_then(|x| x.get("mode"))
        .and_then(|mode| mode.as_u64())
        .unwrap_or(0);
    if actual_id != expected.map(u64::from) || actual_mode != if expected.is_some() { 2 } else { 0 }
    {
        return Err(format!(
            "XDP attachment identity/mode differs: {}",
            String::from_utf8_lossy(&output.stdout)
        )
        .into());
    }
    println!(
        "interface-state {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    Ok(())
}

fn socket(index: u32) -> Result<OwnedFd> {
    // AF_PACKET sockets are confined to the two freshly owned veth indices.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(3u16.to_be()),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = 3u16.to_be();
    address.sll_ifindex = i32::try_from(index)?;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as _,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as _,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(fd)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn live_frame(payload: &[u8], ipv6: bool) -> Vec<u8> {
    let mut frame = vectors::packet(payload, ipv6);
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    let udp = if ipv6 { 54 } else { 34 };
    let length = (payload.len() + 8) as u16;
    let mut pseudo = Vec::new();
    if ipv6 {
        frame[21] = 64;
        frame[22..38].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame[38..54].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pseudo.extend_from_slice(&frame[22..54]);
        pseudo.extend_from_slice(&u32::from(length).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
    } else {
        frame[22] = 64;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        let ip_sum = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_sum.to_be_bytes());
        pseudo.extend_from_slice(&frame[26..34]);
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&length.to_be_bytes());
    }
    pseudo.extend_from_slice(&frame[udp..]);
    let udp_sum = checksum(&pseudo);
    frame[udp + 6..udp + 8]
        .copy_from_slice(&if udp_sum == 0 { u16::MAX } else { udp_sum }.to_be_bytes());
    frame
}

pub(super) fn live(ingress: u32, peer: u32, phase: &str) -> Result<()> {
    let mut plain = vec![0x40, 1, 0, 1, 0xff];
    plain.extend_from_slice(&[0x5a; 32]);
    // RFC 8613 Appendix C.4 protected request; bytes stay opaque to this hook.
    let protected = [
        0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68,
        0x6f, 0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77, 0x6f, 0x1c,
        0x16, 0x68, 0xb3, 0x82, 0x5e,
    ];
    for ipv6 in [false, true] {
        for payload in [plain.as_slice(), protected.as_slice()] {
            live_one(ingress, peer, phase, &live_frame(payload, ipv6))?;
        }
    }
    Ok(())
}

fn live_one(ingress: u32, peer: u32, phase: &str, frame: &[u8]) -> Result<()> {
    let receiver = socket(ingress)?;
    let sender = socket(peer)?;
    let written = unsafe { libc::send(sender.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
    if written != frame.len() as isize {
        return Err(std::io::Error::last_os_error().into());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = [0u8; 2048];
    while Instant::now() < deadline {
        let length = unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                received.as_mut_ptr().cast(),
                received.len(),
                0,
            )
        };
        if length > 0 && received[..length as usize] == *frame {
            println!("live-veth PASS phase={phase} exact_bytes={}", frame.len());
            return Ok(());
        }
        if length < 0 {
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Err(error.into());
            }
        }
    }
    Err(format!("live frame not received unchanged during {phase}").into())
}

pub(super) fn live_attached(bpf: &Ebpf, ingress: u32, peer: u32) -> Result<()> {
    let before = counters(bpf)?;
    live(ingress, peer, "attached")?;
    let after = counters(bpf)?;
    let syntax = coaptic_ingress_classifier::Class::CoapSyntax as usize;
    if after[syntax] != before[syntax] + 4 || after[TOTAL as usize] < before[TOTAL as usize] + 4 {
        return Err(format!(
            "live packet did not execute classifier once: before={before:?} after={after:?}"
        )
        .into());
    }
    println!(
        "live counters before={before:?} after={after:?}; ambient non-CoAP traffic is not an exact count claim"
    );
    Ok(())
}

pub(super) fn metadata(bpf: &mut Ebpf, cycle: u32) -> Result<()> {
    let Some(directory) = std::env::var_os("COAPTIC_BPF_EVIDENCE") else {
        return Ok(());
    };
    let directory = std::path::Path::new(&directory);
    let program: &mut Xdp = bpf
        .program_mut("coaptic_observe")
        .ok_or("missing program")?
        .try_into()?;
    let id = program.info()?.id().to_string();
    let output = Command::new("bpftool")
        .args(["-j", "prog", "show", "id", &id])
        .output()?;
    if !output.status.success() {
        return Err("bpftool owned program inspection failed".into());
    }
    std::fs::write(
        directory.join(format!("kernel-program-{cycle}.json")),
        &output.stdout,
    )?;
    let info: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let info = if let Some(array) = info.as_array() {
        array.first().ok_or("empty program info")?
    } else {
        &info
    };
    let maps = info
        .get("map_ids")
        .and_then(|m| m.as_array())
        .ok_or("missing owned map IDs")?;
    for map in maps {
        let map = map.as_u64().ok_or("invalid map id")?.to_string();
        let output = Command::new("bpftool")
            .args(["-j", "map", "show", "id", &map])
            .output()?;
        if !output.status.success() {
            return Err("bpftool owned map inspection failed".into());
        }
        std::fs::write(
            directory.join(format!("kernel-map-{cycle}-{map}.json")),
            output.stdout,
        )?;
    }
    let output = Command::new("bpftool")
        .args(["prog", "dump", "xlated", "id", &id, "linum"])
        .output()?;
    if !output.status.success() {
        return Err("bpftool owned instruction inspection failed".into());
    }
    std::fs::write(
        directory.join(format!("kernel-instructions-{cycle}.txt")),
        output.stdout,
    )?;
    Ok(())
}

pub(super) struct Affinity(libc::cpu_set_t);
impl Affinity {
    fn capture() -> Result<Self> {
        let mut set = unsafe { std::mem::zeroed() };
        if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&set), &mut set) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(set))
    }
    pub(super) fn pin(cpu: usize) -> Result<Self> {
        let original = Self::capture()?;
        let mut set = unsafe { std::mem::zeroed() };
        unsafe {
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(cpu, &mut set);
        }
        if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(original)
    }
}
impl Drop for Affinity {
    fn drop(&mut self) {
        if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&self.0), &self.0) } != 0 {
            eprintln!(
                "cannot restore qualification thread CPU affinity: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn reset_counters(bpf: &mut Ebpf, cpu: Option<usize>) -> Result<()> {
    let mut counts: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf.map_mut("COUNTS").ok_or("missing COUNTS")?)?;
    for key in 0..COUNTERS {
        let mut values = vec![0; counts.get(&key, 0)?.len()];
        if let Some(cpu) = cpu
            && (key == TOTAL || key == coaptic_ingress_classifier::Class::CoapSyntax as u32)
        {
            *values.get_mut(cpu).ok_or("selected CPU outside map")? = u64::MAX - 1;
        }
        counts.set(key, values.try_into()?, 0)?;
    }
    Ok(())
}

pub(super) fn cpu_counters(bpf: &mut Ebpf) -> Result<()> {
    let affinity = Affinity::capture()?;
    let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &affinity.0) })
        .take(2)
        .collect();
    if cpus.len() != 2 {
        return Err(
            "multi-CPU qualification requires two available CPUs; slice remains unqualified".into(),
        );
    }
    reset_counters(bpf, None)?;
    let frame = vectors::packet(&[0x40, 1, 0, 1], false);
    {
        let program: &Xdp = bpf
            .program("coaptic_observe")
            .ok_or("missing program")?
            .try_into()?;
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| -> Result<()> {
            let mut threads = Vec::new();
            for cpu in cpus.iter().copied() {
                let frame = &frame;
                let barrier = &barrier;
                threads.push(scope.spawn(move || -> std::result::Result<(), String> {
                    let affinity = Affinity::pin(cpu).map_err(|error| error.to_string());
                    // Both workers must rendezvous even when one affinity operation fails.
                    barrier.wait();
                    let _affinity = affinity?;
                    let mut output = vec![0; frame.len() + 256];
                    let result = program
                        .test_run(TestRunOptions {
                            data_in: Some(frame),
                            data_out: Some(&mut output),
                            repeat: 8,
                            ..Default::default()
                        })
                        .map_err(|error| error.to_string())?;
                    if result.return_value != 2
                        || result.data_size_out as usize != frame.len()
                        || output[..frame.len()] != *frame
                    {
                        return Err("concurrent test-run changed bytes/action".into());
                    }
                    Ok(())
                }));
            }
            for thread in threads {
                thread
                    .join()
                    .map_err(|_| "counter worker panicked")?
                    .map_err(|error| format!("CPU worker: {error}"))?;
            }
            Ok(())
        })?;
    }
    {
        let counts: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf.map("COUNTS").ok_or("missing COUNTS")?)?;
        if !matches!(
            counts.get(&COUNTERS, 0),
            Err(aya::maps::MapError::OutOfBounds { .. })
        ) {
            return Err("array API did not refuse out-of-range index".into());
        }
        for key in 0..COUNTERS {
            for (cpu, value) in counts.get(&key, 0)?.iter().enumerate() {
                let expected = if cpus.contains(&cpu)
                    && (key == TOTAL || key == coaptic_ingress_classifier::Class::CoapSyntax as u32)
                {
                    8
                } else {
                    0
                };
                if *value != expected {
                    return Err(format!("concurrent finite-batch loss: cpu={cpu} key={key} expected={expected} actual={value}").into());
                }
            }
        }
    }
    reset_counters(bpf, Some(cpus[0]))?;
    {
        let _affinity = Affinity::pin(cpus[0])?;
        let program: &Xdp = bpf
            .program("coaptic_observe")
            .ok_or("missing program")?
            .try_into()?;
        for _ in 0..2 {
            if program
                .test_run(TestRunOptions {
                    data_in: Some(&frame),
                    ..Default::default()
                })?
                .return_value
                != 2
            {
                return Err("saturating counters changed PASS".into());
            }
        }
    }
    {
        let counts: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf.map("COUNTS").ok_or("missing COUNTS")?)?;
        for key in 0..COUNTERS {
            for (cpu, value) in counts.get(&key, 0)?.iter().enumerate() {
                let expected = if cpu == cpus[0]
                    && (key == TOTAL || key == coaptic_ingress_classifier::Class::CoapSyntax as u32)
                {
                    u64::MAX
                } else {
                    0
                };
                if *value != expected {
                    return Err("counter saturation failed".into());
                }
            }
        }
    }
    reset_counters(bpf, None)?;
    println!(
        "counter contract PASS cpus={cpus:?} concurrent_batch=8_each loss=0 saturation=u64MAX array_out_of_range=refused; fixed array has no insertion/full state"
    );
    Ok(())
}

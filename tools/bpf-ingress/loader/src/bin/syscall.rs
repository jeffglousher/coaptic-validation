//! Finite owned-child helper. stdout is a bounded command protocol, never events.
#[path = "../../../syscall_contract.rs"]
#[allow(dead_code)] // Shared host/kernel contract; each binary uses a subset.
mod contract;
#[cfg(target_os = "linux")]
mod linux {
    use super::contract;
    use aya::{
        Ebpf,
        maps::{Array, PerCpuArray},
        programs::TracePoint,
    };
    use std::{
        error::Error,
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::{Duration, Instant},
    };
    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    const OBJECT_LIMIT: usize = 1024 * 1024;
    const TEXT_LIMIT: usize = 16 * 1024;
    const PROGRAM_LIMIT: u64 = 256 * 1024;

    fn read(path: &str, maximum: usize) -> Result<String> {
        let mut data = String::new();
        File::open(path)?
            .take(maximum as u64 + 1)
            .read_to_string(&mut data)?;
        if data.len() > maximum {
            return Err("bounded input exceeded".into());
        }
        Ok(data)
    }
    // Require every raw-syscall ABI field, including common header and signedness.
    // Unknown fields refuse; names/header text and event numeric IDs are observed.
    fn format(text: &str, exit: bool) -> Result<()> {
        let expected: &[(&str, usize, usize, usize)] = if exit {
            &[
                ("unsigned short common_type", 0, 2, 0),
                ("unsigned char common_flags", 2, 1, 0),
                ("unsigned char common_preempt_count", 3, 1, 0),
                ("int common_pid", 4, 4, 1),
                ("long id", 8, 8, 1),
                ("long ret", 16, 8, 1),
            ]
        } else {
            &[
                ("unsigned short common_type", 0, 2, 0),
                ("unsigned char common_flags", 2, 1, 0),
                ("unsigned char common_preempt_count", 3, 1, 0),
                ("int common_pid", 4, 4, 1),
                ("long id", 8, 8, 1),
                ("unsigned long args[6]", 16, 48, 0),
            ]
        };
        let mut fields = Vec::with_capacity(6);
        for line in text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("field:"))
        {
            let parts: Vec<_> = line
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.len() != 4 {
                return Err("unsupported tracepoint field syntax".into());
            }
            fields.push((
                parts[0]
                    .strip_prefix("field:")
                    .ok_or("field prefix")?
                    .trim(),
                parts[1]
                    .strip_prefix("offset:")
                    .ok_or("offset prefix")?
                    .trim()
                    .parse::<usize>()?,
                parts[2]
                    .strip_prefix("size:")
                    .ok_or("size prefix")?
                    .trim()
                    .parse::<usize>()?,
                parts[3]
                    .strip_prefix("signed:")
                    .ok_or("signed prefix")?
                    .trim()
                    .parse::<usize>()?,
            ));
        }
        if fields != expected {
            return Err("unsupported raw_syscalls LP64 tracepoint layout".into());
        }
        Ok(())
    }
    fn identity(pid: u32, start: u64, uid: u32) -> Result<()> {
        let text = read(&format!("/proc/{pid}/stat"), 4096)?;
        let tail = text.rsplit_once(") ").ok_or("proc stat delimiter")?.1;
        let fields: Vec<_> = tail.split_whitespace().collect();
        if fields.len() < 20
            || fields[0] == "Z"
            || fields[17] != "1"
            || fields[19].parse::<u64>()? != start
        {
            return Err("target exited, identity changed or thread count unsupported".into());
        }
        let status = read(&format!("/proc/{pid}/status"), TEXT_LIMIT)?;
        let field = |key: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(str::trim)
        };
        let uid_text = uid.to_string();
        if uid == 0
            || field("Uid:")
                .ok_or("missing target uid")?
                .split_whitespace()
                .collect::<Vec<_>>()
                != vec![uid_text.as_str(); 4]
            || field("Cpus_allowed_list:") != Some("0")
            || field("Tgid:") != Some(pid.to_string().as_str())
        {
            return Err("target credentials or CPU0-only affinity differs".into());
        }
        let mut elf = [0; 20];
        File::open(format!("/proc/{pid}/exe"))?.read_exact(&mut elf)?;
        if &elf[..6] != b"\x7fELF\x02\x01" || elf[18..20] != [62, 0] {
            return Err("target must be x86_64 ELF64 little endian".into());
        }
        Ok(())
    }
    fn command(deadline: Instant) -> Result<String> {
        let mut bytes = Vec::with_capacity(8);
        while bytes.len() < 9 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("helper deadline")?;
            let mut poll = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = remaining.as_millis().min(100) as i32;
            let n = unsafe { libc::poll(&mut poll, 1, timeout) };
            if n < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if n == 0 {
                continue;
            }
            let mut byte = [0];
            if std::io::stdin().read(&mut byte)? != 1 {
                return Err("controller EOF".into());
            }
            bytes.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(String::from_utf8(bytes)?);
            }
        }
        Err("helper command byte bound".into())
    }
    fn emit(value: serde_json::Value) -> Result<()> {
        let line = value.to_string();
        if line.len() >= TEXT_LIMIT {
            return Err("helper output bound".into());
        }
        println!("{line}");
        std::io::stdout().flush()?;
        Ok(())
    }
    fn usage() -> Result<libc::rusage> {
        let mut value = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(value)
    }
    pub fn run() -> Result<()> {
        if !cfg!(all(
            target_arch = "x86_64",
            target_endian = "little",
            target_pointer_width = "64"
        )) {
            return Err("syscall observer requires Linux x86_64 LP64".into());
        }
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 6 {
            return Err(
                "usage: coaptic-syscall-loader OBJECT PID START_TICKS UID MAX_SECONDS".into(),
            );
        }
        let (pid, start, uid, seconds): (u32, u64, u32, u64) = (
            args[2].parse()?,
            args[3].parse()?,
            args[4].parse()?,
            args[5].parse()?,
        );
        if pid <= 1 || start == 0 || uid == 0 || !(1..=60).contains(&seconds) {
            return Err("helper bounds".into());
        }
        let deadline = Instant::now() + Duration::from_secs(seconds);
        identity(pid, start, uid)?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let target = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        identity(pid, start, uid)?;
        let cpus = aya::util::nr_cpus().map_err(|(path, e)| format!("{path}: {e}"))?;
        if cpus == 0 || cpus > contract::MAX_CPUS {
            return Err("possible-CPU budget exceeds 64".into());
        }
        let enter_format = read(
            "/sys/kernel/tracing/events/raw_syscalls/sys_enter/format",
            TEXT_LIMIT,
        )?;
        let exit_format = read(
            "/sys/kernel/tracing/events/raw_syscalls/sys_exit/format",
            TEXT_LIMIT,
        )?;
        format(&enter_format, false)?;
        format(&exit_format, true)?;
        if std::fs::metadata(&args[1])?.len() > OBJECT_LIMIT as u64 {
            return Err("trace object exceeds 1MiB".into());
        }
        let mut object = Vec::with_capacity(OBJECT_LIMIT);
        File::open(&args[1])?
            .take(OBJECT_LIMIT as u64 + 1)
            .read_to_end(&mut object)?;
        if object.len() > OBJECT_LIMIT {
            return Err("trace object grew".into());
        }
        let mut bpf = Ebpf::load(&object)?;
        let mut control: Array<_, u64> =
            Array::try_from(bpf.take_map("SC_CTL").ok_or("missing SC_CTL")?)?;
        let counts: PerCpuArray<_, u64> =
            PerCpuArray::try_from(bpf.take_map("SC_COUNTS").ok_or("missing SC_COUNTS")?)?;
        if control.len() != 1 || counts.len() != contract::COUNTERS || bpf.maps().next().is_some() {
            return Err("trace map inventory differs".into());
        }
        control.set(0, 0, 0)?;
        let mut programs = Vec::with_capacity(2);
        let mut program_bytes = 0u64;
        for name in ["sc_enter", "sc_exit"] {
            let p: &mut TracePoint = bpf
                .program_mut(name)
                .ok_or("missing trace program")?
                .try_into()?;
            p.load()?;
            let info = p.info()?;
            let locked = u64::from(info.memory_locked()?);
            let translated = info.size_translated().ok_or("program size unavailable")?;
            program_bytes = program_bytes
                .checked_add(locked)
                .ok_or("program size overflow")?;
            if program_bytes > PROGRAM_LIMIT || translated > 64 * 1024 {
                return Err("trace program budget".into());
            }
            programs.push(serde_json::json!({"name":name,"id":info.id(),"memlock_bytes":locked,"translated_bytes":translated,"jit_bytes":info.size_jitted()}));
        }
        let enter = {
            let p: &mut TracePoint = bpf.program_mut("sc_enter").unwrap().try_into()?;
            p.attach("raw_syscalls", "sys_enter")?
        };
        let exit = {
            let p: &mut TracePoint = bpf.program_mut("sc_exit").unwrap().try_into()?;
            p.attach("raw_syscalls", "sys_exit")?
        };
        identity(pid, start, uid)?;
        emit(
            serde_json::json!({"event":"ready","pid":pid,"start_ticks":start,"uid":uid,"cpu":0,
            "possible_cpus":cpus,"map_value_bytes":8+8*u64::from(contract::COUNTERS)*cpus as u64,
            "programs":programs,"enter_format":enter_format,"exit_format":exit_format,
            "kernel_map_link_metadata_bytes":null,"kernel_metadata_allowance_bytes":1024*1024,
            "memory_limit_scope":"fixed map values plus capped program memlock; map/link allocator metadata unknown, not whole-kernel memory acceptance"}),
        )?;
        if command(deadline)? != "enable\n" {
            return Err("expected enable".into());
        }
        identity(pid, start, uid)?;
        let mut poll = libc::pollfd {
            fd: target.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
            return Err("target pidfd exited".into());
        }
        control.set(0, (u64::from(pid) << 32) | u64::from(pid), 0)?;
        emit(serde_json::json!({"event":"enabled"}))?;
        if command(deadline)? != "disable\n" {
            return Err("expected disable".into());
        }
        control.set(0, 0, 0)?;
        // Explicit detach errors propagate. Drop also closes owned links/maps on
        // EOF/error; the controller still must settle the privileged process group.
        {
            let p: &mut TracePoint = bpf.program_mut("sc_enter").unwrap().try_into()?;
            p.detach(enter)?;
        }
        {
            let p: &mut TracePoint = bpf.program_mut("sc_exit").unwrap().try_into()?;
            p.detach(exit)?;
        }
        identity(pid, start, uid)?;
        let mut values = [0u64; contract::COUNTERS as usize];
        for index in 0..contract::COUNTERS {
            let per_cpu = counts.get(&index, 0)?;
            if per_cpu.len() != cpus {
                return Err("per-CPU count shape changed".into());
            }
            if per_cpu.iter().skip(1).any(|n| *n != 0) {
                return Err("unexpected non-CPU0 trace counts".into());
            }
            let sum = per_cpu
                .iter()
                .try_fold(0u64, |sum, n| {
                    if *n == u64::MAX {
                        None
                    } else {
                        sum.checked_add(*n)
                    }
                })
                .ok_or("saturated counter")?;
            values[index as usize] = sum;
        }
        let stats = usage()?;
        emit(
            serde_json::json!({"event":"disabled","counts":values.as_slice(),"bins":contract::NAMES,"classes":contract::CLASSES,
            "loader_lifetime_user_us":stats.ru_utime.tv_sec*1_000_000+stats.ru_utime.tv_usec,
            "loader_lifetime_system_us":stats.ru_stime.tv_sec*1_000_000+stats.ru_stime.tv_usec,
            "loader_lifetime_maxrss_kib":stats.ru_maxrss,
            "boundary":"independent entries/exits; enabling/disabling can censor either boundary; no balance invariant or syscall duration",
            "limits":"target is pinned CPU0; callback coverage/filter overhead unestablished; vDSO unobserved; no CPU-share claim"}),
        )?;
        if values[contract::READ_ERROR as usize] != 0
            || values[contract::FOREIGN_THREAD as usize] != 0
        {
            return Err("trace context read failure or foreign-thread anomaly".into());
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rejects_absent_or_changed_layout() {
            assert!(format("", false).is_err());
            assert!(format("field:long id; offset:4; size:8; signed:1;", false).is_err());
        }
    }
}
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("syscall observer requires Linux x86_64; no action");
    std::process::exit(2);
}

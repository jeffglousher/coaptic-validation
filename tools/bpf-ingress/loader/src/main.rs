#[cfg(target_os = "linux")]
mod cost;
#[cfg(target_os = "linux")]
mod probe;
#[cfg(target_os = "linux")]
mod linux {
    use aya::{
        Ebpf,
        maps::PerCpuArray,
        programs::{Xdp, XdpMode},
    };
    use std::{
        error::Error,
        process::Command,
        time::{Duration, Instant},
    };
    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    fn ip(args: &[&str]) -> Result<()> {
        if !Command::new("ip").args(args).status()?.success() {
            return Err(format!("ip {args:?} failed").into());
        }
        Ok(())
    }
    struct Veth {
        name: String,
        peer: String,
        indices: Option<(u32, u32)>,
        owned: bool,
        retain: bool,
    }
    fn interface_value(name: &str, field: &str) -> Result<u32> {
        Ok(
            std::fs::read_to_string(format!("/sys/class/net/{name}/{field}"))?
                .trim()
                .parse()?,
        )
    }
    impl Veth {
        fn create() -> Result<Self> {
            let name = format!("cpb{}a", std::process::id());
            let peer = format!("cpb{}b", std::process::id());
            // Successful creation establishes ownership. Existing names cause refusal.
            ip(&["link", "add", &name, "type", "veth", "peer", "name", &peer])?;
            let mut owned = Self {
                name,
                peer,
                indices: None,
                owned: true,
                retain: false,
            };
            owned.indices = Some((
                interface_value(&owned.name, "ifindex")?,
                interface_value(&owned.peer, "ifindex")?,
            ));
            owned.verify_identity()?;
            ip(&["link", "set", &owned.name, "up"])?;
            owned.verify_identity()?;
            ip(&["link", "set", &owned.peer, "up"])?;
            println!(
                "owned ingress={} peer={} ifindices={:?}",
                owned.name, owned.peer, owned.indices
            );
            println!(
                "OWNED_RECORD {}",
                serde_json::json!({
                    "pid": std::process::id(), "ingress": owned.name, "peer": owned.peer,
                    "ingress_index": owned.indices.map(|v| v.0), "peer_index": owned.indices.map(|v| v.1)
                })
            );
            Ok(owned)
        }
        fn verify_identity(&self) -> Result<u32> {
            let (index, peer_index) = self
                .indices
                .ok_or("veth identity unavailable; retain for manual reconciliation")?;
            if interface_value(&self.name, "ifindex")? != index
                || interface_value(&self.peer, "ifindex")? != peer_index
                || interface_value(&self.name, "iflink")? != peer_index
                || interface_value(&self.peer, "iflink")? != index
            {
                return Err("veth identity changed; refusing attachment or cleanup".into());
            }
            Ok(index)
        }
        fn cleanup(&mut self) -> Result<()> {
            if self.retain {
                return Err("cleanup uncertain; retain ownership record for reconciliation".into());
            }
            if self.owned {
                let cleanup = (|| -> Result<()> {
                    self.verify_identity()?;
                    ip(&["link", "delete", &self.name])?;
                    for name in [&self.name, &self.peer] {
                        if std::path::Path::new(&format!("/sys/class/net/{name}")).try_exists()? {
                            return Err("owned veth remains after deletion".into());
                        }
                    }
                    Ok(())
                })();
                if let Err(error) = cleanup {
                    self.retain = true;
                    return Err(error);
                }
                self.owned = false;
            }
            Ok(())
        }
    }
    impl Drop for Veth {
        fn drop(&mut self) {
            if let Err(error) = self.cleanup() {
                eprintln!(
                    "owned veth cleanup failed: ingress={} peer={} ifindices={:?}: {error}",
                    self.name, self.peer, self.indices
                );
            }
        }
    }
    struct OwnedChild {
        child: std::process::Child,
        record: Option<Veth>,
        waited: bool,
    }
    impl OwnedChild {
        fn stop(&mut self) -> Result<std::process::ExitStatus> {
            let kill = self.child.kill();
            // Always reap before inspecting/removing the recorded network resources.
            let status = self.child.wait()?;
            self.waited = true;
            kill?;
            Ok(status)
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !self.waited && self.stop().is_err() && !self.waited {
                // Without confirmed termination, even a genuine record is not a cleanup grant.
                if let Some(record) = &mut self.record {
                    record.owned = false;
                }
                eprintln!(
                    "cannot confirm owned child termination; retain recorded veth for reconciliation"
                );
            }
            if self.waited
                && let Some(record) = &mut self.record
                && record.verify_identity().is_ok()
            {
                record.owned = true;
            }
        }
    }
    fn terminated_child(object: &str) -> Result<()> {
        use std::{
            io::{BufRead, BufReader},
            os::unix::process::ExitStatusExt,
            process::Stdio,
        };
        let child = std::process::Command::new(std::env::current_exe()?)
            .args([object, "60", "1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut owned = OwnedChild {
            child,
            record: None,
            waited: false,
        };
        let stdout = owned
            .child
            .stdout
            .take()
            .ok_or("child stdout unavailable")?;
        let (send, receive) = std::sync::mpsc::sync_channel(8);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        // Instrumented verifier loads on the recorded hosted kernel exceed 20s.
        // Bound startup separately from the child's post-attachment sleep.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or("child attach timeout")?;
            let line = receive
                .recv_timeout(remaining)
                .map_err(|_| "child did not report attachment")??;
            println!("child {}: {line}", owned.child.id());
            if let Some(record) = line.strip_prefix("OWNED_RECORD ") {
                let record: serde_json::Value = serde_json::from_str(record)?;
                let pid = owned.child.id();
                let name = format!("cpb{pid}a");
                let peer = format!("cpb{pid}b");
                if owned.record.is_some()
                    || record["pid"].as_u64() != Some(u64::from(pid))
                    || record["ingress"].as_str() != Some(name.as_str())
                    || record["peer"].as_str() != Some(peer.as_str())
                {
                    return Err("child ownership record differs from spawned process".into());
                }
                let index = u32::try_from(
                    record["ingress_index"]
                        .as_u64()
                        .ok_or("missing child ingress index")?,
                )?;
                let peer_index = u32::try_from(
                    record["peer_index"]
                        .as_u64()
                        .ok_or("missing child peer index")?,
                )?;
                let veth = Veth {
                    name,
                    peer,
                    indices: Some((index, peer_index)),
                    owned: false,
                    retain: false,
                };
                veth.verify_identity()?;
                owned.record = Some(veth);
            }
            if line.starts_with("attached cycle=0;") {
                break;
            }
        }
        if owned.record.is_none() {
            return Err("child attached without ownership record".into());
        }
        let status = owned.stop()?;
        if status.signal() != Some(libc::SIGKILL) {
            return Err("child was not terminated by SIGKILL".into());
        }
        reader.join().map_err(|_| "child output reader panicked")?;
        let record = owned
            .record
            .as_mut()
            .ok_or("missing stopped child record")?;
        record.verify_identity()?;
        record.owned = true;
        crate::probe::attached(&record.name, None)?;
        record.cleanup()?;
        if std::path::Path::new(&format!("/sys/class/net/{}", record.name)).exists()
            || std::path::Path::new(&format!("/sys/class/net/{}", record.peer)).exists()
        {
            return Err("terminated child veth still exists after owned cleanup".into());
        }
        println!(
            "terminated-child recovery PASS pid={} indices={:?}; wait completed, identities verified, links detached and pair deleted",
            owned.child.id(),
            record.indices
        );
        Ok(())
    }
    fn quick(object: &str, veth: &mut Veth) -> Result<()> {
        let started = Instant::now();
        let result = (|| -> Result<()> {
            let (ingress, peer) = veth.indices.ok_or("missing veth indices")?;
            veth.verify_identity()?;
            crate::probe::attached(&veth.name, None)?;
            let phase = Instant::now();
            crate::probe::live(ingress, peer, "quick-before")?;
            println!(
                "phase=live-before elapsed_ms={}",
                phase.elapsed().as_millis()
            );
            let phase = Instant::now();
            let mut bpf = Ebpf::load_file(object)?;
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            program.load()?;
            println!(
                "phase=load-verify elapsed_ms={}",
                phase.elapsed().as_millis()
            );
            let phase = Instant::now();
            let id = program.info()?.id();
            let link = program.attach_to_if_index(veth.verify_identity()?, XdpMode::Skb)?;
            crate::probe::attached(&veth.name, Some(id))?;
            println!(
                "phase=attach elapsed_ms={} program_id={id} mode=SKB",
                phase.elapsed().as_millis()
            );
            let phase = Instant::now();
            crate::probe::quick_attached(&bpf, ingress, peer)?;
            println!(
                "phase=live-attached elapsed_ms={}",
                phase.elapsed().as_millis()
            );
            let phase = Instant::now();
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            program.detach(link)?;
            veth.verify_identity()?;
            crate::probe::attached(&veth.name, None)?;
            println!(
                "phase=detach-absence elapsed_ms={}",
                phase.elapsed().as_millis()
            );
            let phase = Instant::now();
            let before = crate::probe::counters(&bpf)?;
            crate::probe::live(ingress, peer, "quick-detached-recovery")?;
            let after = crate::probe::counters(&bpf)?;
            if after != before {
                return Err(format!(
                    "detached recovery changed counters: before={before:?} after={after:?}"
                )
                .into());
            }
            println!(
                "phase=live-recovery elapsed_ms={} unchanged_counters={after:?}",
                phase.elapsed().as_millis()
            );
            Ok(())
        })();
        // The object has closed its links on every path. Refuse deletion if
        // attachment absence or pair identity cannot be established afterward.
        let phase = Instant::now();
        if let Err(error) = veth
            .verify_identity()
            .and_then(|_| crate::probe::attached(&veth.name, None))
            .and_then(|_| veth.cleanup())
        {
            veth.retain = true;
            return Err(format!("quick result={result:?}; cleanup uncertain; retained ingress={} peer={} indices={:?}: {error}", veth.name, veth.peer, veth.indices).into());
        }
        println!(
            "phase=delete-absence elapsed_ms={}",
            phase.elapsed().as_millis()
        );
        result?;
        println!(
            "quick PASS elapsed_ms={}; observation only; authentication remains in App",
            started.elapsed().as_millis()
        );
        Ok(())
    }
    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 4 {
            return Err("usage: coaptic-ingress-loader OBJECT quick 1 | OBJECT SECONDS|qualify CYCLES | OBJECT cost 1; cost runs detached, other modes create an owned veth; requires Linux BPF privileges".into());
        }
        if args[2] == "cost" {
            if args[3] != "1" {
                return Err("cost mode runs exactly one finite sample; use OBJECT cost 1".into());
            }
            return crate::cost::run(&args[1]);
        }
        if args[2] == "quick" {
            if args[3] != "1" {
                return Err("quick mode runs exactly one finite batch; use OBJECT quick 1".into());
            }
            let phase = Instant::now();
            let mut veth = Veth::create()?;
            println!(
                "phase=create-identity elapsed_ms={}",
                phase.elapsed().as_millis()
            );
            return quick(&args[1], &mut veth);
        }
        let qualify = args[2] == "qualify";
        let seconds: u64 = if qualify { 1 } else { args[2].parse()? };
        let cycles: u32 = args[3].parse()?;
        if !(1..=60).contains(&seconds) || !(1..=3).contains(&cycles) {
            return Err("seconds must be 1..60; cycles 1..3".into());
        }
        let mut veth = Veth::create()?;
        let (ingress, peer) = veth.indices.ok_or("missing veth indices")?;
        if qualify {
            crate::probe::attached(&veth.name, None)?;
            crate::probe::live(ingress, peer, "before")?;
        }
        for cycle in 0..cycles {
            let mut bpf = Ebpf::load_file(&args[1])?;
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            program.load()?;
            if qualify {
                crate::probe::metadata(&mut bpf, cycle)?;
                crate::probe::differential(&mut bpf)?;
                crate::probe::cpu_counters(&mut bpf)?;
            }
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            let index = veth.verify_identity()?;
            let link = program.attach_to_if_index(index, XdpMode::Skb)?;
            println!("attached cycle={cycle}; observation only; all packets PASS");
            if qualify {
                crate::probe::attached(&veth.name, Some(program.info()?.id()))?;
                crate::probe::live_attached(&bpf, ingress, peer)?;
            } else {
                std::thread::sleep(Duration::from_secs(seconds));
            }
            // Detach before reading so a completed snapshot does not race new packets.
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            program.detach(link)?;
            if qualify {
                crate::probe::attached(&veth.name, None)?;
                crate::probe::live(ingress, peer, "detached")?;
            }
            let counts: PerCpuArray<_, u64> =
                PerCpuArray::try_from(bpf.map("COUNTS").ok_or("missing map")?)?;
            for index in 0..5 {
                let values = counts.get(&index, 0)?;
                let sum = values.iter().fold(0u64, |sum, n| sum.saturating_add(*n));
                println!(
                    "cycle={cycle} counter={index} sum={sum} cpus={}",
                    values.len()
                );
            }
            // Nothing is pinned. Drop closes this cycle's owned object/maps.
        }
        if qualify {
            terminated_child(&args[1])?;
            veth.verify_identity()?;
            crate::probe::attached(&veth.name, None)?;
            println!(
                "concurrent ownership PASS: parent pair survived child termination/recovery unchanged"
            );
        }
        veth.cleanup()?;
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This loader requires Linux with BPF and veth support. No action performed.");
    std::process::exit(2);
}

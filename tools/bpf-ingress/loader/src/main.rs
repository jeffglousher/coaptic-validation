#[cfg(target_os = "linux")]
mod linux {
    use aya::{
        Ebpf,
        maps::PerCpuArray,
        programs::{Xdp, XdpMode},
    };
    use std::{error::Error, process::Command, time::Duration};
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
            if self.owned {
                self.verify_identity()?;
                ip(&["link", "delete", &self.name])?;
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
    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 4 {
            return Err("usage: coaptic-ingress-loader OBJECT SECONDS CYCLES; creates its own disposable veth; requires Linux BPF/network privileges".into());
        }
        let seconds: u64 = args[2].parse()?;
        let cycles: u32 = args[3].parse()?;
        if !(1..=60).contains(&seconds) || !(1..=3).contains(&cycles) {
            return Err("seconds must be 1..60; cycles 1..3".into());
        }
        let mut veth = Veth::create()?;
        for cycle in 0..cycles {
            let mut bpf = Ebpf::load_file(&args[1])?;
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            program.load()?;
            let index = veth.verify_identity()?;
            let link = program.attach_to_if_index(index, XdpMode::Skb)?;
            println!("attached cycle={cycle}; observation only; all packets PASS");
            std::thread::sleep(Duration::from_secs(seconds));
            // Detach before reading so a completed snapshot does not race new packets.
            let program: &mut Xdp = bpf
                .program_mut("coaptic_observe")
                .ok_or("missing program")?
                .try_into()?;
            program.detach(link)?;
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

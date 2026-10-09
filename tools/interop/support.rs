//! Small process protocol. stdout is JSON Lines; diagnostics use stderr.
use std::time::Duration;
pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub const BODY: &[u8] = b"core-test-payload";
pub const LARGE: [u8; 2000] = {
    let mut bytes = [0; 2000];
    let mut i = 0;
    while i < bytes.len() {
        bytes[i] = (i % 251) as u8;
        i += 1;
    }
    bytes
};
pub struct Args {
    pub server: bool,
    pub ipv6: bool,
    pub dtls: bool,
    pub oscore: bool,
    pub sequence: u64,
    pub port: u16,
    pub key: String,
    pub path: String,
    pub method: u8,
    pub payload: Vec<u8>,
    pub timeout: u64,
    pub q_block1: bool,
    pub q_block2: bool,
    pub observe: bool,
    pub echo: bool,
    pub replay: Option<(u64, u32)>,
    pub jsonpatch: bool,
}
impl Args {
    pub fn parse() -> Result<Self, Error> {
        let mut a: Vec<_> = std::env::args().skip(1).collect();
        let (mut q_block1, mut q_block2, mut observe, mut echo, mut jsonpatch) =
            (false, false, false, false, false);
        let mut replay = None;
        while let Some(flag) = a.last().cloned() {
            match flag.as_str() {
                "qblock1" => q_block1 = true,
                "qblock2" => q_block2 = true,
                "observe" => observe = true,
                "echo" => echo = true,
                "jsonpatch" => jsonpatch = true,
                _ => {
                    let Some(rest) = flag.strip_prefix("replay:") else {
                        break;
                    };
                    let mut parts = rest.split(':');
                    let (Some(left), Some(bits), None) = (parts.next(), parts.next(), parts.next())
                    else {
                        return Err("replay checkpoint must be LEFT:BITS".into());
                    };
                    if replay.is_some() {
                        return Err("duplicate replay checkpoint".into());
                    }
                    let left = left.parse::<u64>()?;
                    let bits = bits.parse::<u32>()?;
                    replay = Some((left, bits));
                }
            }
            a.pop();
        }
        if !(7..=10).contains(&a.len()) {
            return Err(
                "usage: PEER server|client udp|dtls|oscore PORT KEY PATH METHOD TIMEOUT_MS [ipv4|ipv6] [PAYLOAD_HEX] [SENDER_SEQUENCE]"
                    .into(),
            );
        }
        if !matches!(a[0].as_str(), "server" | "client")
            || !matches!(a[1].as_str(), "udp" | "dtls" | "oscore")
        {
            return Err("invalid role, transport or method".into());
        }
        if !matches!(
            a[4].as_str(),
            "test" | "large" | "counter" | "missing" | "methods" | "upload" | "separate" | "patch"
        ) {
            return Err("unsupported fixture path".into());
        }
        let method = match a[5].as_str() {
            "GET" => 1,
            "POST" => 2,
            "PUT" => 3,
            "DELETE" => 4,
            "FETCH" => 5,
            "PATCH" => 6,
            "IPATCH" => 7,
            _ => return Err("invalid method".into()),
        };
        let hex = a.get(8).map(String::as_str).unwrap_or("");
        if hex.len() > 8192 || hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid bounded payload hex".into());
        }
        let payload = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("checked hex"))
            .collect();
        let family = a.get(7).map(String::as_str).unwrap_or("ipv4");
        if !matches!(family, "ipv4" | "ipv6") {
            return Err("invalid address family".into());
        }
        let port = a[2].parse()?;
        if port == 0 {
            return Err("port must be nonzero".into());
        }
        if a[3].is_empty() || a[3].len() > 64 {
            return Err("PSK must be 1..64 bytes".into());
        }
        let timeout = a[6].parse()?;
        if !(100..=30000).contains(&timeout) {
            return Err("timeout must be 100..30000 ms".into());
        }
        let sequence = a
            .get(9)
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(0);
        if sequence >= (1u64 << 40) {
            return Err("OSCORE sequence exceeds 40 bits".into());
        }
        Ok(Self {
            server: a[0] == "server",
            ipv6: family == "ipv6",
            dtls: a[1] == "dtls",
            oscore: a[1] == "oscore",
            sequence,
            port,
            key: a[3].clone(),
            path: a[4].clone(),
            method,
            payload,
            timeout,
            q_block1,
            q_block2,
            observe,
            echo,
            replay,
            jsonpatch,
        })
    }
    pub fn address(&self) -> std::net::SocketAddr {
        if self.ipv6 {
            (std::net::Ipv6Addr::LOCALHOST, self.port).into()
        } else {
            ([127, 0, 0, 1], self.port).into()
        }
    }
}
pub fn ready(peer: &str, stack: &str, port: u16, transport: &str) {
    println!(
        "{}",
        serde_json::json!({"schema":"coaptic-peer/2","event":"ready","peer":peer,"stack":stack,"port":port,"transport":transport})
    );
}
pub fn response(code: u8, body: &[u8], elapsed: Duration, echo_retries: Option<u8>) {
    let elapsed_ns = elapsed.as_nanos();
    let hex: String = body.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "{}",
        serde_json::json!({"schema":"coaptic-peer/2","event":"response","code":code,"payload_hex":hex,"echo_retries":echo_retries,"elapsed_ns":elapsed_ns,"elapsed_us":elapsed_ns as f64 / 1000.0,"clock":{"name":"std::time::Duration","resolution_ns":null}})
    );
}
pub fn finish(result: Result<(), Error>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({"schema":"coaptic-peer/2","event":"error","message":e.to_string()})
            );
            std::process::ExitCode::FAILURE
        }
    }
}

/// Application fixture, not a protocol implementation. Independent codecs
/// supply the method, bytes and format. C implements the same contract separately.
#[derive(Default)]
pub struct MethodResource(Option<Vec<u8>>);
impl MethodResource {
    pub const fn new() -> Self {
        Self(None)
    }
    pub fn respond(&mut self, method: u8, payload: &[u8], format_ok: bool) -> (u8, Vec<u8>) {
        if matches!(method, 2 | 3 | 5 | 6 | 7) && !format_ok {
            return (143, vec![]);
        }
        if payload.len() > 64 {
            return (141, vec![]);
        }
        match method {
            1 => self
                .0
                .as_ref()
                .map(|value| (69, value.clone()))
                .unwrap_or((132, vec![])),
            3 => {
                let code = if self.0.is_some() { 68 } else { 65 };
                self.0 = Some(payload.to_vec());
                (code, vec![])
            }
            4 => {
                if self.0.take().is_some() {
                    (66, vec![])
                } else {
                    (132, vec![])
                }
            }
            5 if payload != b"value" => (128, vec![]),
            5 => self
                .0
                .as_ref()
                .map(|value| (69, value.clone()))
                .unwrap_or((132, vec![])),
            2 | 6 | 7 => {
                let Some(value) = self.0.as_mut() else {
                    return (132, vec![]);
                };
                if method == 7 {
                    let Some(body) = payload.strip_prefix(b"=") else {
                        return (128, vec![]);
                    };
                    *value = body.to_vec();
                } else {
                    let body = if method == 6 {
                        let Some(body) = payload.strip_prefix(b"+") else {
                            return (128, vec![]);
                        };
                        body
                    } else {
                        payload
                    };
                    if value.len() + body.len() > 64 {
                        return (141, vec![]);
                    }
                    value.extend_from_slice(body);
                }
                (68, vec![])
            }
            _ => (133, vec![]),
        }
    }
}

/// RFC 8132 merge-patch fixture. Only `{"n":null}` and `{"n":<u32>}` at content-format 52.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MergePatch {
    value: Option<u32>,
}
impl MergePatch {
    pub const fn new() -> Self {
        Self { value: Some(0) }
    }
    pub fn respond(
        &mut self,
        method: u8,
        payload: &[u8],
        format: Option<u16>,
    ) -> (u8, Vec<u8>, Option<u16>) {
        match method {
            1 => match self.value {
                Some(n) => (69, format!("{{\"n\":{n}}}").into_bytes(), Some(50)),
                None => (132, vec![], None),
            },
            6 => match format {
                Some(52) => match parse_merge_n(payload) {
                    Some(next) => {
                        self.value = next;
                        (68, vec![], None)
                    }
                    None => (128, vec![], None),
                },
                Some(51) => match parse_json_patch(payload) {
                    Some(JsonPatch::Replace(n)) if self.value.is_some() => {
                        self.value = Some(n);
                        (68, vec![], None)
                    }
                    Some(JsonPatch::Remove) if self.value.is_some() => {
                        self.value = None;
                        (68, vec![], None)
                    }
                    Some(_) => (132, vec![], None),
                    None => (128, vec![], None),
                },
                _ => (143, vec![], None),
            },
            _ => (133, vec![], None),
        }
    }
}
enum JsonPatch {
    Replace(u32),
    Remove,
}
fn parse_json_patch(payload: &[u8]) -> Option<JsonPatch> {
    if payload == b"[{\"op\":\"remove\",\"path\":\"/n\"}]" {
        return Some(JsonPatch::Remove);
    }
    let digits = payload
        .strip_prefix(b"[{\"op\":\"replace\",\"path\":\"/n\",\"value\":")?
        .strip_suffix(b"}]")?;
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if digits.len() > 1 && digits[0] == b'0' {
        return None;
    }
    Some(JsonPatch::Replace(
        core::str::from_utf8(digits).ok()?.parse().ok()?,
    ))
}
fn parse_merge_n(payload: &[u8]) -> Option<Option<u32>> {
    if payload == b"{\"n\":null}" {
        return Some(None);
    }
    let digits = payload.strip_prefix(b"{\"n\":")?.strip_suffix(b"}")?;
    if digits.is_empty() || digits.len() > 10 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if digits.len() > 1 && digits[0] == b'0' {
        return None;
    }
    Some(Some(core::str::from_utf8(digits).ok()?.parse().ok()?))
}

/// Bounded upload oracle: exact public byte pattern and accepted/handler counts.
#[derive(Default)]
pub struct UploadResource {
    accepted: u32,
    calls: u32,
}
impl UploadResource {
    pub const fn new() -> Self {
        Self {
            accepted: 0,
            calls: 0,
        }
    }
    pub fn respond(&mut self, method: u8, payload: &[u8], format_ok: bool) -> (u8, Vec<u8>) {
        if method == 1 {
            return (69, format!("{}:{}", self.accepted, self.calls).into_bytes());
        }
        if method != 2 {
            return (133, vec![]);
        }
        self.calls += 1;
        if !format_ok {
            return (143, vec![]);
        }
        if !matches!(payload.len(), 2000 | 4096)
            || !payload
                .iter()
                .enumerate()
                .all(|(i, b)| *b == (i % 251) as u8)
        {
            return (128, vec![]);
        }
        self.accepted += 1;
        (65, vec![])
    }
}
#[test]
fn merge_patch_replaces_and_deletes_one_decimal_member() {
    let mut patch = MergePatch::new();
    assert_eq!(
        patch.respond(1, b"", None),
        (69, b"{\"n\":0}".to_vec(), Some(50))
    );
    assert_eq!(patch.respond(6, b"{\"n\":1}", Some(42)).0, 143);
    assert_eq!(patch.respond(6, b"{\"n\":1}", Some(52)), (68, vec![], None));
    assert_eq!(patch.respond(1, b"", None).1, b"{\"n\":1}".to_vec());
    assert_eq!(patch.respond(6, b"{\"n\":01}", Some(52)).0, 128);
    assert_eq!(
        patch.respond(6, b"{\"n\":null}", Some(52)),
        (68, vec![], None)
    );
    assert_eq!(patch.respond(1, b"", None).0, 132);
    assert_eq!(patch.value, None);
}

#[test]
fn json_patch_replaces_and_removes_one_member() {
    let mut patch = MergePatch::new();
    let replace = b"[{\"op\":\"replace\",\"path\":\"/n\",\"value\":3}]";
    let remove = b"[{\"op\":\"remove\",\"path\":\"/n\"}]";
    assert_eq!(patch.respond(6, replace, Some(51)), (68, vec![], None));
    assert_eq!(patch.respond(1, b"", None).1, b"{\"n\":3}".to_vec());
    assert_eq!(patch.respond(6, b"{\"n\":1}", Some(51)).0, 128);
    assert_eq!(patch.respond(1, b"", None).1, b"{\"n\":3}".to_vec());
    assert_eq!(patch.respond(6, remove, Some(51)), (68, vec![], None));
    assert_eq!(patch.respond(6, replace, Some(51)).0, 132);
}

#[test]
fn upload_oracle_checks_every_byte_length_format_and_handler_effect() {
    let mut resource = UploadResource::new();
    for length in [2000, 4096] {
        let payload: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
        assert_eq!(resource.respond(2, &payload, true).0, 65);
    }
    assert_eq!(resource.respond(1, &[], false), (69, b"2:2".to_vec()));
    assert_eq!(resource.respond(2, &LARGE[..1999], true).0, 128);
    let mut changed = LARGE;
    changed[1999] ^= 1;
    assert_eq!(resource.respond(2, &changed, true).0, 128);
    assert_eq!(resource.respond(2, &LARGE, false).0, 143);
    assert_eq!(resource.respond(1, &[], false), (69, b"2:5".to_vec()));
}

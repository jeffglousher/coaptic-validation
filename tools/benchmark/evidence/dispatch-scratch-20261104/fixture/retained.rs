#![allow(dead_code)]
//! Deferred bounded Q-Block2 selector lists retain complete snapshots.
use coaptic::app::AppStorage;
use coaptic::message::ContentFormat;
use coaptic::message::decode;
use coaptic::message::{BlockValue, Message, MessageId, Opt, Token, Type, encode};
use coaptic::resources::Resources;
use coaptic::storage::DatagramIo;
use coaptic::{App, Code, Endpoint, Response};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
    static FAIL_RANDOM: Cell<bool> = const { Cell::new(false) };
}
fn random_for_refusal(bytes: &mut [u8]) -> bool {
    bytes.fill(0x42);
    !FAIL_RANDOM.with(Cell::get)
}
struct TrackingAllocator;
// Test instrumentation counts only this thread and delegates to the system allocator.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;
fn without_allocating<R>(work: impl FnOnce() -> R) -> R {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ALLOCATIONS.with(|c| c.set(None));
        }
    }
    ALLOCATIONS.with(|c| c.set(Some(0)));
    let guard = Guard;
    let result = work();
    let allocations = ALLOCATIONS.with(|c| c.get().unwrap());
    drop(guard);
    assert_eq!(
        allocations, 0,
        "poll/request work must not allocate or grow"
    );
    result
}

coaptic::memory_profile! {
    Buffers {
        rx_datagram: (4, 1472), tx_datagram: (4, 1472),
        rx_body: (2, 12288), tx_body: (2, 12288),
        dedup: 16, observe: 1,
    }
}
const PEER: Endpoint = Endpoint::v4([192, 0, 2, 2], 5683);
const BODY: [u8; 11264] = {
    let mut bytes = [0; 11264];
    let mut index = 0;
    while index < bytes.len() {
        bytes[index] = (index * 31 + index / 512) as u8;
        index += 1;
    }
    bytes
};
#[derive(Clone, Copy)]
struct Frame {
    bytes: [u8; 1472],
    len: usize,
    peer: Endpoint,
}
impl Default for Frame {
    fn default() -> Self {
        Self {
            bytes: [0; 1472],
            len: 0,
            peer: PEER,
        }
    }
}
#[derive(Default)]
struct Io {
    incoming: Option<Frame>,
    output: [Frame; 16],
    len: usize,
    fail_at: Option<usize>,
    sends: usize,
}
impl Io {
    fn take(&mut self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        let frame = self.output[0];
        self.output.copy_within(1..self.len, 0);
        self.len -= 1;
        Some(frame)
    }
}
impl coaptic::storage::DatagramTransport for Io {
    type Error = &'static str;
}

impl DatagramIo for Io {
    fn recv(&mut self, out: &mut [u8]) -> Result<Option<(usize, Endpoint)>, Self::Error> {
        let Some(frame) = self.incoming.take() else {
            return Ok(None);
        };
        out[..frame.len].copy_from_slice(&frame.bytes[..frame.len]);
        Ok(Some((frame.len, frame.peer)))
    }
    fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.sends += 1;
        if self.fail_at == Some(self.sends) {
            return Err("injected send failure");
        }
        assert!(self.len < self.output.len());
        let frame = &mut self.output[self.len];
        frame.bytes[..bytes.len()].copy_from_slice(bytes);
        frame.len = bytes.len();
        frame.peer = peer;
        self.len += 1;
        Ok(bytes.len())
    }
}

type Server<S = coaptic::storage::Memory<Buffers, coaptic::storage::WithBodies<Buffers>>> =
    App<Buffers, Io, 1, true, S, 2>;
fn fixed() -> Server {
    App::with_resources(
        Resources::<Buffers>::new()
            .routes::<1>()
            .block_wise::<true>()
            .deferred::<2>(),
    )
    .allow_unprotected()
    .deterministic_for_tests()
    .deferred_lifetime(40)
    .bind(Io::default())
    .unwrap()
}

struct Peer {
    #[cfg(feature = "oscore")]
    context: Option<coaptic::oscore::SecurityContext>,
}
impl Peer {
    fn new<S: AppStorage<Token = coaptic::message::Token>>(
        server: &mut Server<S>,
        protected: bool,
    ) -> Self {
        #[cfg(feature = "oscore")]
        {
            let make = |sender, recipient| {
                coaptic::oscore::SecurityContext::derive(coaptic::oscore::DeriveParams {
                    master_secret: &[0x42; 16],
                    master_salt: &[],
                    sender_id: sender,
                    recipient_id: recipient,
                    id_context: &[],
                })
                .unwrap()
            };
            if protected {
                server.set_oscore(&mut Some(make(&[2], &[1]))).unwrap();
            }
            Self {
                context: protected.then(|| make(&[1], &[2])),
            }
        }
        #[cfg(not(feature = "oscore"))]
        {
            let _ = server;
            assert!(!protected);
            Self {}
        }
    }
    fn request(&mut self, mid: u16, num: u32, more: bool, szx: u8) -> Frame {
        self.custom(
            mid,
            Code::GET,
            "snapshot",
            &[BlockValue::new(num, more, szx).unwrap()],
            false,
            None,
            b"",
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn custom(
        &mut self,
        mid: u16,
        code: Code,
        path: &str,
        blocks: &[BlockValue],
        observe: bool,
        etag: Option<&[u8]>,
        body: &[u8],
    ) -> Frame {
        let mut options = coaptic::message::OptionsBuilder::<16>::new();
        if let Some(tag) = etag {
            options.push(Opt::etag(tag)).unwrap();
        }
        if observe {
            options
                .push(Opt::new(coaptic::message::OptionNumber::OBSERVE, &[]))
                .unwrap();
        }
        options.push(Opt::uri_path(path)).unwrap();
        let cf = ContentFormat::CBOR.encode();
        if code == Code::FETCH {
            options.push(Opt::content_format(&cf)).unwrap();
        }
        let values: [_; 11] = core::array::from_fn(|index| {
            blocks
                .get(index)
                .copied()
                .unwrap_or(BlockValue::new(0, false, 6).unwrap())
                .encode()
        });
        for value in &values[..blocks.len()] {
            options.push(Opt::q_block2(value)).unwrap();
        }
        let message = Message::new(Type::Confirmable, code, MessageId::new(mid))
            .with_token(Token::new(b"owner").unwrap())
            .with_options(options.as_slice())
            .with_payload(body);
        self.encode(&message)
    }
    fn encode(&mut self, message: &Message<'_>) -> Frame {
        let mut frame = Frame::default();
        #[cfg(feature = "oscore")]
        if let Some(context) = self.context.as_mut() {
            frame.len = context.protect_request(message, &mut frame.bytes).unwrap();
            return frame;
        }
        frame.len = encode(message, &mut frame.bytes).unwrap();
        frame
    }
    fn invalid_fetch(&mut self, mid: u16, tags: &[&[u8]], q: &[u8]) -> Frame {
        let mut options = coaptic::message::OptionsBuilder::<16>::new();
        for tag in tags {
            options.push(Opt::etag(tag)).unwrap();
        }
        options.push(Opt::uri_path("snapshot")).unwrap();
        let format = ContentFormat::CBOR.encode();
        options.push(Opt::content_format(&format)).unwrap();
        options
            .push(Opt::new(coaptic::message::OptionNumber::Q_BLOCK2, q))
            .unwrap();
        self.encode(
            &Message::new(Type::Confirmable, Code::FETCH, MessageId::new(mid))
                .with_token(Token::new(b"owner").unwrap())
                .with_options(options.as_slice())
                .with_payload(b"query"),
        )
    }
    fn open(&self, frame: Frame) -> Frame {
        #[cfg(feature = "oscore")]
        if let Some(context) = self.context.as_ref() {
            let protected = decode(&frame.bytes[..frame.len]).unwrap();
            assert!(protected.oscore().is_some());
            let mut opened = Frame::default();
            let request = context.lookup(protected.token()).unwrap();
            let parsed = context
                .unprotect_response(&protected, request, &mut opened.bytes)
                .unwrap();
            // The parsed inner datagram occupies exactly this bounded prefix.
            let mut opts = coaptic::message::OptionsBuilder::<24>::new();
            for opt in parsed.options() {
                opts.push(Opt::new(opt.number(), opt.value())).unwrap();
            }
            let message = Message::new(parsed.ty(), parsed.code(), parsed.message_id())
                .with_token(parsed.token())
                .with_options(opts.as_slice())
                .with_payload(parsed.payload());
            let mut canonical = Frame::default();
            canonical.len = encode(&message, &mut canonical.bytes).unwrap();
            return canonical;
        }
        frame
    }
}
fn packets<S: AppStorage<Token = coaptic::message::Token>>(
    server: &mut Server<S>,
    peer: &Peer,
    start: u32,
    end: u32,
    szx: u8,
) {
    for num in start..end {
        let frame = peer.open(server.transport_mut().take().expect("selected payload"));
        let p = decode(&frame.bytes[..frame.len]).unwrap();
        let q = p.q_block2().next().unwrap().unwrap();
        assert_eq!(p.ty(), Type::NonConfirmable);
        assert_eq!(p.code(), Code::CONTENT);
        assert_eq!(q.num(), num);
        assert_eq!(q.szx(), szx);
        let size = 1usize << (szx + 4);
        let offset = num as usize * size;
        let stop = (offset + size).min(BODY.len());
        assert_eq!(p.payload(), &BODY[offset..stop]);
        assert_eq!(q.more(), stop < BODY.len());
        assert_eq!(p.etag().next(), Some(&b"snapshot"[..]));
        assert_eq!(p.content_format(), Some(Ok(ContentFormat::OCTET_STREAM)));
        assert_eq!(p.size2(), Some(Ok(BODY.len() as u32)));
    }
    assert!(server.transport_mut().take().is_none());
}
fn ack<S: AppStorage<Token = coaptic::message::Token>>(server: &mut Server<S>, mid: u16) {
    let f = server.transport_mut().take().unwrap();
    let p = decode(&f.bytes[..f.len]).unwrap();
    assert_eq!(p.code(), Code::EMPTY);
    assert_eq!(p.ty(), Type::Acknowledgement);
    assert_eq!(p.message_id(), MessageId::new(mid));
}

use core::future::{Future, pending};
use core::task::{Context, Poll, Waker};
use std::hint::black_box;
struct Timer;
impl coaptic::platform::AsyncTimer for Timer {
    async fn wait_until(&mut self, _: u64) { pending().await }
}
impl coaptic::storage::AsyncDatagramIo for Io {
    async fn recv(&mut self, out: &mut [u8]) -> Result<(usize, Endpoint), Self::Error> {
        match DatagramIo::recv(self, out)? { Some(value) => Ok(value), None => pending().await }
    }
    async fn send(&mut self, peer: Endpoint, bytes: &[u8]) -> Result<usize, Self::Error> {
        DatagramIo::send(self, peer, bytes)
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future=core::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value)=>value,
        Poll::Pending=>panic!("immediate fixture unexpectedly suspended"),
    }
}
fn response(_: coaptic::Request<'_>, _: Option<coaptic::DeferredReply>) -> Response<'static> {
    Response::content(&BODY).etag(b"snapshot").content_format(ContentFormat::OCTET_STREAM)
}
fn drive<S: AppStorage<Token=Token>>(app: &mut Server<S>, now: u64, asynchronous: bool) {
    if asynchronous {
        let mut timer=Timer;
        ready(async {
            assert_eq!(app.wait_async(now,&mut timer,pending::<()>()).await.unwrap(),coaptic::app::AppWake::Ingress);
            app.progress_with_async(now,&mut || Ok::<_, ()>(now),&mut timer,now+1000,response).await.unwrap();
        });
    } else { app.poll_with(now,response).unwrap(); }
}
#[link(name="kernel32")]
unsafe extern "system" {
    fn GetCurrentThread() -> *mut core::ffi::c_void;
    fn QueryThreadCycleTime(thread: *mut core::ffi::c_void, cycles: *mut u64) -> i32;
}
fn cycles()->u64 {
    let mut value=0;
    // Windows pseudo-handle is valid in the current thread; output is one u64.
    assert_ne!(unsafe{QueryThreadCycleTime(GetCurrentThread(),&mut value)},0);
    value
}
fn run<S: AppStorage<Token=Token>>(mut server: Server<S>, count: usize, protected: bool, asynchronous: bool, allocated: bool) {
    let mut peer=Peer::new(&mut server,protected);
    let mut samples=Vec::with_capacity(count);
    #[cfg(feature="diagnostics")]
    server.reset_work_metrics();
    for operation in 0..count+128 {
        let base=(operation*2+1) as u16;
        let mut elapsed=0;
        without_allocating(|| {
            for (part,num,start,end) in [(0,0,0,10),(1,10,10,11)] {
                server.transport_mut().incoming=Some(peer.request(base+part,num,true,6));
                let before=cycles();
                drive(black_box(&mut server),black_box(u64::from(base+part)),asynchronous);
                elapsed+=cycles().checked_sub(before).unwrap();
                ack(&mut server,base+part);
                packets(&mut server,&peer,start,end,6);
            }
            assert_eq!(server.engine_mut().storage_mut().tx_body().unwrap().occupied_count(),0);
            assert_eq!(server.engine_mut().rx_occupied(),0);
        });
        if operation>=128 { samples.push(elapsed); }
    }
    let mode=if asynchronous {"async"}else{"sync"};
    let security=if protected {"oscore"}else{"unprotected"};
    let storage=if allocated {"allocated"}else{"fixed"};
    println!("{{\"operations\":{count},\"warmup\":128,\"verified\":{},\"mode\":\"{mode}\",\"security\":\"{security}\",\"storage\":\"{storage}\",\"payload_bytes\":{},\"requests_per_operation\":2,\"data_packets_per_operation\":11,\"app_inline_bytes\":{},\"cycles\":{:?}}}",count+128,BODY.len(),core::mem::size_of_val(&server),samples);
    #[cfg(feature="diagnostics")]
    eprintln!("work_metrics {:?}",server.work_metrics());
}
fn main() {
    let args:Vec<_>=std::env::args().collect();
    assert_eq!(args.len(),5);
    let count:usize=args[1].parse().unwrap();
    assert!((1..=4096).contains(&count));
    let protected=match args[2].as_str(){"oscore"=>true,"unprotected"=>false,_=>panic!("security")};
    let asynchronous=match args[3].as_str(){"async"=>true,"sync"=>false,_=>panic!("mode")};
    match args[4].as_str() {
        "fixed"=>run(fixed(),count,protected,asynchronous,false),
        "allocated"=>{
            let resources=|| Resources::<Buffers>::new().routes::<1>().block_wise::<true>().deferred::<2>();
            let bytes=resources().allocated(usize::MAX).required_heap_bytes().unwrap();
            let app=App::with_resources(resources().allocated(bytes)).allow_unprotected().deterministic_for_tests().deferred_lifetime(40).bind(Io::default()).unwrap();
            run(app,count,protected,asynchronous,true);
        }
        _=>panic!("storage"),
    }
}

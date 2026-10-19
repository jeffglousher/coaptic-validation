use super::*;

enum Input {
    Packet(Vec<u8>),
    Idle,
    Fault,
}

struct Burst {
    input: VecDeque<Input>,
    output: Rc<RefCell<Vec<Vec<u8>>>>,
    reads: Rc<Cell<usize>>,
}
impl coaptic::storage::DatagramTransport for Burst {
    type Error = ();
}
impl DatagramIo for Burst {
    fn recv(&mut self, scratch: &mut [u8]) -> Result<Option<(usize, Endpoint)>, ()> {
        self.reads.set(self.reads.get() + 1);
        match self.input.pop_front().expect("bounded scripted receive") {
            Input::Idle => Ok(None),
            Input::Fault => Err(()),
            Input::Packet(packet) => {
                assert!(packet.len() <= scratch.len());
                scratch[..packet.len()].copy_from_slice(&packet);
                Ok(Some((packet.len(), Endpoint::v4([192, 0, 2, 1], 5683))))
            }
        }
    }
    fn send(&mut self, _: Endpoint, bytes: &[u8]) -> Result<usize, ()> {
        self.output.borrow_mut().push(bytes.to_vec());
        Ok(bytes.len())
    }
}

fn burst(memory: Memory, input: Vec<Input>) -> (Result<(), &'static str>, Vec<Vec<u8>>, usize) {
    let polls = input.len();
    let output = Rc::new(RefCell::new(Vec::new()));
    let reads = Rc::new(Cell::new(0));
    let io = Burst {
        input: input.into(),
        output: output.clone(),
        reads: reads.clone(),
    };
    let mut times = 0..polls as u64;
    let result = run_protected(
        io,
        |b| {
            b.fill(42);
            true
        },
        || times.next(),
        &[b'a'; 32],
        &credentials(),
        memory,
    );
    let packets = output.borrow().clone();
    (result, packets, reads.get())
}

fn authenticated_response(
    peer: &mut SecurityContext,
    request: &[u8],
    response: &[u8],
    code: coaptic::Code,
    body: &[u8],
) {
    let mut verifier = SecurityContext::derive(credentials().parameters()).unwrap();
    let mut scratch = [0; 1152];
    let (_, reference) = verifier
        .unprotect_request(&decode(request).unwrap(), &mut scratch)
        .unwrap();
    let request = decode(request).unwrap();
    let response = decode(response).unwrap();
    assert_eq!(response.message_id(), request.message_id());
    assert_eq!(response.token(), request.token());
    assert_eq!(response.ty(), Type::Acknowledgement);
    assert!(response.oscore().is_some());
    let opened = peer
        .unprotect_response(&response, reference, &mut scratch)
        .unwrap();
    assert_eq!(opened.code(), code);
    assert_eq!(opened.payload(), body);
}

#[test]
fn rejected_bursts_do_not_dispatch_or_consume_the_transport_failure_budget() {
    let _test = TEST_LOCK.lock().unwrap();
    for kind in 0..4 {
        let mut memory = Memory::default();
        provision(&mut memory, &credentials()).unwrap();
        let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
        let bad = match kind {
            0 => vec![0xff],
            1 => {
                let mut c = peer_credentials();
                c.secret[0] ^= 1;
                let mut wrong = SecurityContext::derive(c.parameters()).unwrap();
                protected_request(&mut wrong, 1, coaptic::Code::POST, "echo", b"unauthorized")
            }
            2 => {
                let mut packet =
                    protected_request(&mut peer, 1, coaptic::Code::POST, "echo", b"unauthorized");
                *packet.last_mut().unwrap() ^= 1;
                peer.take(Token::new(&[1]).unwrap());
                packet
            }
            3 => {
                let packet =
                    protected_request(&mut peer, 1, coaptic::Code::POST, "echo", b"accepted once");
                let (result, output, reads) =
                    burst(memory.clone(), vec![Input::Packet(packet.clone())]);
                assert_eq!((result, reads), (Ok(()), 1));
                assert_eq!(output.len(), 1);
                authenticated_response(
                    &mut peer,
                    &packet,
                    &output[0],
                    coaptic::Code::CONTENT,
                    b"accepted once",
                );
                packet
            }
            _ => unreachable!(),
        };
        let before = ECHO_CALLS.load(Ordering::Relaxed);
        let commits = memory.0.borrow().commits;
        let fresh = protected_request(&mut peer, 200, coaptic::Code::POST, "echo", &[0x5a; 128]);
        let mut input: Vec<_> = (0..64).map(|_| Input::Packet(bad.clone())).collect();
        input.push(Input::Packet(fresh.clone()));
        let (result, output, reads) = burst(memory.clone(), input);
        assert_eq!((result, reads), (Ok(()), 65), "rejection class {kind}");
        assert_eq!(output.len(), 1, "rejection class {kind}");
        assert_eq!(ECHO_CALLS.load(Ordering::Relaxed), before + 1);
        // Only recovery reservation and the fresh authenticated checkpoint write.
        assert_eq!(memory.0.borrow().commits, commits + 2);
        authenticated_response(
            &mut peer,
            &fresh,
            &output[0],
            coaptic::Code::CONTENT,
            &[0x5a; 128],
        );
    }
}

#[test]
fn authenticated_oversize_burst_refuses_complete_bodies_then_recovers() {
    let _test = TEST_LOCK.lock().unwrap();
    let mut memory = Memory::default();
    provision(&mut memory, &credentials()).unwrap();
    let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
    let requests: Vec<_> = (1..=65)
        .map(|mid| {
            let payload: &[u8] = if mid == 65 {
                &[0x5a; 128]
            } else {
                &[0x6b; 129]
            };
            let packet = protected_request(&mut peer, mid, coaptic::Code::POST, "echo", payload);
            peer.take(Token::new(&[mid as u8]).unwrap());
            packet
        })
        .collect();
    let before = ECHO_CALLS.load(Ordering::Relaxed);
    let (result, output, reads) = burst(
        memory,
        requests.iter().cloned().map(Input::Packet).collect(),
    );
    assert_eq!((result, reads), (Ok(()), 65));
    assert_eq!(output.len(), 65);
    // Oversized requests are authenticated and deliberately enter the bounded handler.
    assert_eq!(ECHO_CALLS.load(Ordering::Relaxed), before + 65);
    for (index, (request, response)) in requests.iter().zip(&output).enumerate() {
        let (code, body): (_, &[u8]) = if index == 64 {
            (coaptic::Code::CONTENT, &[0x5a; 128])
        } else {
            (coaptic::Code::REQUEST_ENTITY_TOO_LARGE, &[])
        };
        authenticated_response(&mut peer, request, response, code, body);
    }
}

#[test]
fn persistent_transport_stops_at_32_but_idle_and_refusal_reset_at_31() {
    let _test = TEST_LOCK.lock().unwrap();
    for reset in 0..3 {
        let mut memory = Memory::default();
        provision(&mut memory, &credentials()).unwrap();
        let mut input: Vec<_> = (0..31).map(|_| Input::Fault).collect();
        if reset == 0 {
            input.push(Input::Fault);
        } else {
            input.push(if reset == 1 {
                Input::Idle
            } else {
                Input::Packet(vec![0xff])
            });
            input.extend((0..31).map(|_| Input::Fault));
        }
        let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
        let fresh = protected_request(&mut peer, 200, coaptic::Code::POST, "echo", b"recovered");
        input.push(Input::Packet(fresh.clone()));
        let before = ECHO_CALLS.load(Ordering::Relaxed);
        let (result, output, reads) = burst(memory, input);
        if reset == 0 {
            assert_eq!((result, reads), (Err("poll failures"), 32));
            assert!(output.is_empty());
            assert_eq!(ECHO_CALLS.load(Ordering::Relaxed), before);
        } else {
            assert_eq!((result, reads), (Ok(()), 64));
            assert_eq!(output.len(), 1);
            assert_eq!(ECHO_CALLS.load(Ordering::Relaxed), before + 1);
            authenticated_response(
                &mut peer,
                &fresh,
                &output[0],
                coaptic::Code::CONTENT,
                b"recovered",
            );
        }
    }
}

#[test]
fn uncertain_initial_sender_reservation_stops_before_receive_and_recovers() {
    let _test = TEST_LOCK.lock().unwrap();
    let mut memory = Memory::default();
    provision(&mut memory, &credentials()).unwrap();
    memory.0.borrow_mut().lose_ack_at = Some(2);
    let mut peer = SecurityContext::derive(peer_credentials().parameters()).unwrap();
    let fresh = protected_request(&mut peer, 1, coaptic::Code::POST, "echo", b"retained");
    let before = ECHO_CALLS.load(Ordering::Relaxed);
    let (result, output, reads) = burst(memory.clone(), vec![Input::Packet(fresh.clone())]);
    assert_eq!((result, reads), (Err("security recovery"), 0));
    assert!(output.is_empty());
    assert_eq!(ECHO_CALLS.load(Ordering::Relaxed), before);
    assert_eq!(memory.0.borrow().commits, 2);
    memory.0.borrow_mut().lose_ack_at = None;
    let (result, output, reads) = burst(memory.clone(), vec![Input::Packet(fresh.clone())]);
    assert_eq!((result, reads), (Ok(()), 1));
    assert_eq!(output.len(), 1);
    authenticated_response(
        &mut peer,
        &fresh,
        &output[0],
        coaptic::Code::CONTENT,
        b"retained",
    );
    assert_eq!(memory.0.borrow().commits, 4);
}

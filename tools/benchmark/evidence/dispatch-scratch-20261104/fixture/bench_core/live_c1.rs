//! Fresh-request, capacity-one fixture, separate from the historical batch.
//!
//! NEW virtual-time semantics: global index i (including warmup) advances the
//! App clock to i * 8 milliseconds. A MID cycle is 524,288 ms, beyond the
//! 247,000 ms exchange lifetime. This is socket-free protocol progress, not
//! elapsed time, traffic rate or RTT. The old batch still uses real elapsed time.
//! The helper prepares AND authenticates each exchange; only main polls App.
use super::*;
use coaptic::oscore::{RequestRef, SecurityContext};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

pub(super) const OPERATIONS: usize = 1_000_000;
const WARMUP: usize = 128;
const WORK_TIMEOUT: Duration = Duration::from_secs(90);
const GATE_TIMEOUT: Duration = Duration::from_secs(120);
const HELPER_STACK: usize = 2 * 1024 * 1024;
const MODE: &str = "server-app-live-c1/1";

// Cross-thread failures have fixed size and never allocate per-operation text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Timeout,
    Cancelled,
    Panic,
    Poison,
    Eof,
    Io,
    Command,
    Spawn,
    Unsupported,
    ThreadIdentity,
    State,
    Bounds,
    Encode,
    Binding,
    Poll,
    Response,
    Authentication,
    Incomplete,
}
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Fault {}
type Result<T> = std::result::Result<T, Fault>;

#[derive(Clone, Copy)]
struct Schedule {
    warmup: usize,
    work: usize,
}
impl Schedule {
    const FIXED: Self = Self {
        warmup: WARMUP,
        work: OPERATIONS,
    };
    fn validate(self) -> Result<()> {
        if self.warmup == 0 || self.warmup > WARMUP || self.work == 0 || self.work > OPERATIONS {
            return Err(Fault::Bounds);
        }
        virtual_ms(self.warmup + self.work - 1)?;
        Ok(())
    }
}

fn virtual_ms(index: usize) -> Result<u64> {
    if index >= WARMUP + OPERATIONS {
        return Err(Fault::Bounds);
    }
    u64::try_from(index)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or(Fault::Bounds)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Empty,
    Request,
    Server,
    Response,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Starting,
    Warmup,
    Warmed,
    Work,
    Measured,
    Finalize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    prepared: usize,
    polled: usize,
    responded: usize,
    verified: usize,
}
impl Counts {
    fn complete(self, n: usize) -> bool {
        self == Self {
            prepared: n,
            polled: n,
            responded: n,
            verified: n,
        }
    }
}

struct State {
    bytes: [u8; WIRE],
    len: usize,
    index: usize,
    slot: Slot,
    phase: Phase,
    deadline: Instant,
    terminal: Option<Fault>,
    warmup: Counts,
    work: Counts,
    max_outstanding: usize,
    pending_binding: bool,
    io_pending: bool,
    helper_settled: bool,
    client_tid: u32,
    #[cfg(test)]
    client_allocations: Option<usize>,
}
impl State {
    fn counts(&mut self) -> &mut Counts {
        if self.phase == Phase::Warmup {
            &mut self.warmup
        } else {
            &mut self.work
        }
    }
    fn check(&self, deadline: Instant) -> Result<()> {
        if let Some(fault) = self.terminal {
            Err(fault)
        } else if Instant::now() >= deadline {
            Err(Fault::Timeout)
        } else {
            Ok(())
        }
    }
    fn complete(&self, schedule: Schedule) -> Result<()> {
        if let Some(fault) = self.terminal {
            return Err(fault);
        }
        if !self.warmup.complete(schedule.warmup)
            || !self.work.complete(schedule.work)
            || self.slot != Slot::Empty
            || self.len != 0
            || self.pending_binding
            || self.io_pending
            || self.max_outstanding != 1
        {
            return Err(Fault::Incomplete);
        }
        Ok(())
    }
}

// Exactly one reusable packet owner. Mutex, Condvar, counters, metadata and
// enclosing padding are included in the emitted shared_slot layout category.
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}
impl Shared {
    fn new() -> Self {
        Self {
            state: Mutex::new(State {
                bytes: [0; WIRE],
                len: 0,
                index: 0,
                slot: Slot::Empty,
                phase: Phase::Starting,
                deadline: Instant::now() + GATE_TIMEOUT,
                terminal: None,
                warmup: Counts::default(),
                work: Counts::default(),
                max_outstanding: 0,
                pending_binding: false,
                io_pending: false,
                helper_settled: false,
                client_tid: 0,
                #[cfg(test)]
                client_allocations: None,
            }),
            changed: Condvar::new(),
        }
    }
    // Recover only to record failure/settlement, never to resume a poisoned run.
    fn lock(&self) -> MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poison) => {
                let mut state = poison.into_inner();
                state.terminal.get_or_insert(Fault::Poison);
                self.changed.notify_all();
                state
            }
        }
    }
    fn fail(&self, fault: Fault) {
        self.lock().terminal.get_or_insert(fault);
        self.changed.notify_all();
    }
    fn wait(
        &self,
        deadline: Instant,
        ready: impl Fn(&State) -> bool,
    ) -> Result<MutexGuard<'_, State>> {
        let mut state = self.lock();
        loop {
            state.check(deadline)?;
            if ready(&state) {
                return Ok(state);
            }
            // Absolute phase/work deadline: spurious wakes cannot extend it.
            let remaining = deadline.saturating_duration_since(Instant::now());
            state = match self.changed.wait_timeout(state, remaining) {
                Ok((state, _)) => state,
                Err(poison) => {
                    let (mut state, _) = poison.into_inner();
                    state.terminal.get_or_insert(Fault::Poison);
                    self.changed.notify_all();
                    return Err(Fault::Poison);
                }
            };
        }
    }
    fn begin(&self, phase: Phase) -> Result<Instant> {
        let mut state = self.lock();
        state.check(state.deadline)?;
        let expected = match phase {
            Phase::Warmup => Phase::Starting,
            Phase::Work => Phase::Warmed,
            Phase::Finalize => Phase::Measured,
            _ => return Err(Fault::State),
        };
        if state.phase != expected || state.slot != Slot::Empty || state.len != 0 {
            return Err(Fault::State);
        }
        state.phase = phase;
        state.deadline = Instant::now()
            + if phase == Phase::Work {
                WORK_TIMEOUT
            } else {
                GATE_TIMEOUT
            };
        self.changed.notify_all();
        Ok(state.deadline)
    }
}

struct Client {
    context: Option<SecurityContext>,
    binding: Option<RequestRef>,
    opened: [u8; WIRE],
    operation: Option<usize>,
}
impl Client {
    fn new(context: Option<SecurityContext>) -> Self {
        Self {
            context,
            binding: None,
            opened: [0; WIRE],
            operation: None,
        }
    }
    fn token(index: usize) -> Result<Token> {
        virtual_ms(index)?;
        // Never truncate the token when MID wraps or the PIV grows.
        Token::new(&(index as u64).to_be_bytes()).ok_or(Fault::Encode)
    }
    fn prepare(&mut self, index: usize, out: &mut [u8; WIRE]) -> Result<usize> {
        if self.operation.is_some() || self.binding.is_some() {
            return Err(Fault::State);
        }
        let token = Self::token(index)?;
        self.operation = Some(index);
        let options = [Opt::uri_path("bench")];
        let request =
            Message::con(Code::GET, MessageId::new(index as u16), token).with_options(&options);
        match self.context.as_mut() {
            Some(context) => {
                let n = context
                    .protect_request(&request, out)
                    .map_err(|_| Fault::Encode)?;
                self.binding = Some(context.take(token).ok_or(Fault::Binding)?);
                Ok(n)
            }
            None => request.encode(out).map_err(|_| Fault::Encode),
        }
    }
    fn verify(&mut self, bytes: &[u8]) -> Result<()> {
        let index = self.operation.ok_or(Fault::State)?;
        let token = Self::token(index)?;
        let mid = MessageId::new(index as u16);
        let wire = decode(black_box(bytes)).map_err(|_| Fault::Response)?;
        // Outer MID/Token/type are not authenticated by OSCORE. Validate all
        // eight token bytes explicitly before opening the authenticated inner.
        if wire.message_id() != mid || wire.token() != token || wire.ty() != Type::Acknowledgement {
            return Err(Fault::Response);
        }
        let reply = match self.context.as_ref() {
            Some(context) => {
                if wire.code() != Code::CHANGED || wire.oscore().is_none() {
                    return Err(Fault::Response);
                }
                context
                    .unprotect_response(
                        &wire,
                        self.binding.take().ok_or(Fault::Binding)?,
                        &mut self.opened,
                    )
                    .map_err(|_| Fault::Authentication)?
            }
            None => {
                if self.binding.is_some() || wire.oscore().is_some() {
                    return Err(Fault::Binding);
                }
                wire
            }
        };
        // Exact fixture semantics, including no extra options; errors remain a
        // small enum even under corrupt traffic. The legacy oracle is unchanged.
        let mut etags = reply.etag();
        if reply.message_id() != mid
            || reply.token() != token
            || reply.ty() != Type::Acknowledgement
            || reply.code() != Code::CONTENT
            || reply.payload() != BODY
            || reply.content_format().and_then(std::result::Result::ok)
                != Some(ContentFormat::OCTET_STREAM)
            || etags.next() != Some(&b"fixture"[..])
            || etags.next().is_some()
            || reply.options().count() != 2
        {
            return Err(Fault::Response);
        }
        self.operation = None;
        Ok(())
    }
    fn cancel(&mut self) {
        if let (Some(context), Some(index)) = (&mut self.context, self.operation)
            && let Ok(token) = Self::token(index)
        {
            let _ = context.take(token);
        }
        self.binding = None;
        self.operation = None;
    }
}

fn helper_exchanges(
    shared: &Shared,
    client: &mut Client,
    first: usize,
    count: usize,
    deadline: Instant,
) -> Result<()> {
    for index in first..first + count {
        let mut state = shared.wait(deadline, |s| s.slot == Slot::Empty)?;
        if state.len != 0 {
            return Err(Fault::State);
        }
        state.len = client.prepare(index, &mut state.bytes)?;
        state.index = index;
        state.pending_binding = client.binding.is_some();
        state.counts().prepared += 1;
        state.max_outstanding = 1;
        state.slot = Slot::Request;
        shared.changed.notify_all();
        drop(state);
        let mut state = shared.wait(deadline, |s| s.slot == Slot::Response)?;
        if state.index != index || !(1..=WIRE).contains(&state.len) {
            return Err(Fault::State);
        }
        client.verify(&state.bytes[..state.len])?;
        state.pending_binding = client.binding.is_some();
        state.counts().verified += 1;
        state.slot = Slot::Empty;
        state.len = 0;
        // Count an actually verified response even if it just crossed the
        // deadline, but never promote that incomplete/timed-out cohort.
        state.check(deadline)?;
        shared.changed.notify_all();
    }
    Ok(())
}

fn helper(shared: &Shared, client: &mut Client, schedule: Schedule) -> Result<()> {
    {
        let mut state = shared.lock();
        #[cfg(windows)]
        {
            state.client_tid = current_windows_thread_id();
        }
        // Non-Windows is testable, but the public runtime refuses it; no fake
        // OS thread identity is emitted as Windows evidence.
        #[cfg(not(windows))]
        {
            state.client_tid = 0;
        }
        shared.changed.notify_all();
    }
    let start_deadline = shared.lock().deadline;
    let warm_deadline = shared
        .wait(start_deadline, |s| s.phase == Phase::Warmup)?
        .deadline;
    helper_exchanges(shared, client, 0, schedule.warmup, warm_deadline)?;
    let run_deadline = {
        let mut state = shared.lock();
        state.check(warm_deadline)?;
        state.phase = Phase::Warmed;
        state.deadline = Instant::now() + GATE_TIMEOUT;
        shared.changed.notify_all();
        state.deadline
    };
    let work_deadline = shared
        .wait(run_deadline, |s| s.phase == Phase::Work)?
        .deadline;
    #[cfg(not(test))]
    helper_exchanges(
        shared,
        client,
        schedule.warmup,
        schedule.work,
        work_deadline,
    )?;
    #[cfg(test)]
    {
        let (result, allocations) = super::batch_tests::observe_allocations(|| {
            helper_exchanges(
                shared,
                client,
                schedule.warmup,
                schedule.work,
                work_deadline,
            )
        });
        shared.lock().client_allocations = Some(allocations);
        result?;
    }
    let finalize_deadline = {
        let mut state = shared.lock();
        state.check(work_deadline)?;
        state.complete(schedule)?;
        state.phase = Phase::Measured;
        state.deadline = Instant::now() + GATE_TIMEOUT;
        shared.changed.notify_all();
        state.deadline
    };
    // Still alive while main emits measured and the parent stops/flushed ETW.
    shared
        .wait(finalize_deadline, |s| s.phase == Phase::Finalize)?
        .complete(schedule)?;
    Ok(())
}

fn helper_guard(
    shared: &Shared,
    context: Option<SecurityContext>,
    action: impl FnOnce(&mut Client) -> Result<()>,
) -> Result<()> {
    let mut client = Client::new(context);
    let outcome =
        catch_unwind(AssertUnwindSafe(|| action(&mut client))).unwrap_or(Err(Fault::Panic));
    client.cancel();
    let mut state = shared.lock();
    if let Err(fault) = outcome {
        state.terminal.get_or_insert(fault);
    }
    state.pending_binding = false;
    state.helper_settled = true;
    shared.changed.notify_all();
    outcome
}

fn serve_one(shared: &Shared, app: &mut CoreApp, index: usize, deadline: Instant) -> Result<()> {
    let now = virtual_ms(index)?;
    let mut state = shared.wait(deadline, |s| s.slot == Slot::Request)?;
    let io = app.transport_mut();
    if state.index != index
        || !(1..=WIRE).contains(&state.len)
        || io.input_len.is_some()
        || io.output_len.is_some()
    {
        return Err(Fault::State);
    }
    io.input[..state.len].copy_from_slice(black_box(&state.bytes[..state.len]));
    io.input_len = Some(state.len);
    state.io_pending = true;
    state.slot = Slot::Server;
    drop(state);
    // Main is the sole App owner. The mutex is not held through App::poll, so
    // a failed/expired helper can publish its terminal reason and wake main.
    let outcome = black_box(black_box(&mut *app).poll(black_box(now)));
    let io = app.transport_mut();
    let mut state = shared.lock();
    state.io_pending = io.input_len.is_some() || io.output_len.is_some();
    outcome.map_err(|_| Fault::Poll)?;
    state.counts().polled += 1; // Completed successful complete-App polls.
    if io.input_len.is_some() {
        return Err(Fault::Response);
    }
    let n = io.output_len.ok_or(Fault::Response)?;
    if !(1..=WIRE).contains(&n) {
        return Err(Fault::Response);
    }
    state.bytes[..n].copy_from_slice(black_box(&io.output[..n]));
    io.output_len = None;
    state.io_pending = false;
    state.len = n;
    state.slot = Slot::Response;
    state.counts().responded += 1;
    shared.changed.notify_all();
    state.check(deadline)
}

fn drive(
    shared: &Shared,
    app: &mut CoreApp,
    first: usize,
    count: usize,
    deadline: Instant,
    done: Phase,
) -> Result<()> {
    for index in first..first + count {
        serve_one(shared, app, index, deadline)?;
    }
    // Includes the final helper authentication, never just response production.
    drop(shared.wait(deadline, |s| s.phase == done)?);
    Ok(())
}

struct CancelOnDrop<'a>(&'a Shared);
impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        if !self.0.lock().helper_settled {
            self.0.fail(Fault::Cancelled);
        }
    }
}

fn scoped(
    shared: &Shared,
    app: &mut CoreApp,
    context: Option<SecurityContext>,
    schedule: Schedule,
    owner: impl FnOnce(&Shared, &mut CoreApp) -> Result<()>,
) -> Result<()> {
    schedule.validate()?;
    std::thread::scope(|scope| {
        // Inside the scope: on owner unwind this drops BEFORE scope's implicit
        // join. A guard outside scope would leave the helper asleep until timeout.
        let _cancel = CancelOnDrop(shared);
        let helper = match std::thread::Builder::new()
            .stack_size(HELPER_STACK)
            .spawn_scoped(scope, || {
                helper_guard(shared, context, |client| helper(shared, client, schedule))
            }) {
            Ok(helper) => helper,
            Err(_) => {
                shared.lock().helper_settled = true; // No helper was created.
                shared.fail(Fault::Spawn);
                return Err(Fault::Spawn);
            }
        };
        let result =
            catch_unwind(AssertUnwindSafe(|| owner(shared, app))).unwrap_or(Err(Fault::Panic));
        if let Err(fault) = result {
            shared.fail(fault);
        }
        let joined = helper.join().unwrap_or(Err(Fault::Panic));
        if let Err(fault) = joined {
            shared.fail(fault);
        }
        let mut state = shared.lock();
        state.helper_settled = true; // Join also proves settlement after a panic.
        state.io_pending =
            app.transport().input_len.is_some() || app.transport().output_len.is_some();
        if let Some(fault) = state.terminal {
            return Err(fault);
        }
        result.and(joined)
    })
}

fn gate(input: &mut impl Read, expected: &[u8]) -> Result<()> {
    let mut bytes = [0; 7];
    if expected.len() > bytes.len() {
        return Err(Fault::Bounds);
    }
    input
        .read_exact(&mut bytes[..expected.len()])
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                Fault::Eof
            } else {
                Fault::Io
            }
        })?;
    if &bytes[..expected.len()] != expected {
        return Err(Fault::Command);
    }
    Ok(())
}
fn flush(output: &mut impl Write) -> Result<()> {
    output.flush().map_err(|_| Fault::Io)
}

fn fixture(output: &mut impl Write, shared: &Shared, app: &CoreApp, security: &str) -> Result<()> {
    #[cfg(windows)]
    let tid = current_windows_thread_id();
    #[cfg(not(windows))]
    let tid = 0;
    let deadline = shared.lock().deadline;
    let state = shared.wait(deadline, |s| s.client_tid != 0)?;
    if tid == 0 || state.client_tid == tid {
        return Err(Fault::ThreadIdentity);
    }
    let heap =
        coaptic::storage::AllocMemory::<Token>::required_heap_bytes(app.engine().capacities())
            .map_err(|_| Fault::Bounds)?;
    writeln!(output,
        "{{\"event\":\"fixture\",\"mode\":\"{MODE}\",\"security\":\"{security}\",\"operations\":1000000,\"warmup\":128,\"workload_thread_id\":{tid},\"client_thread_id\":{},\"deadline_seconds\":90,\"virtual_tick_ms\":8,\"virtual_first_ms\":0,\"virtual_last_ms\":8001016,\"capacities\":{{\"routes\":1,\"calls\":4,\"deferred\":0,\"security_bindings\":4,\"associations\":1,\"rx_datagram_slots\":4,\"rx_datagram_bytes\":1472,\"tx_datagram_slots\":4,\"tx_datagram_bytes\":1472,\"dedup_entries\":8,\"observe_entries\":4,\"rx_body_slots\":1,\"rx_body_bytes\":1024,\"tx_body_slots\":2,\"tx_body_bytes\":1024,\"blockwise\":true}},\"layout\":{{\"shared_slot\":{},\"client_context\":{},\"client_request_ref\":{},\"client_decrypt_scratch\":1472,\"server_app_inline\":{},\"server_requested_heap\":{heap},\"helper_stack_requested\":2097152}}}}",
        state.client_tid, std::mem::size_of::<Shared>(), std::mem::size_of::<Option<SecurityContext>>(),
        std::mem::size_of::<Option<RequestRef>>(), std::mem::size_of_val(app),
    ).map_err(|_| Fault::Io)?;
    drop(state);
    flush(output)
}

fn counters(
    output: &mut impl Write,
    state: &State,
    security: &str,
    event: &str,
    settled: bool,
) -> Result<()> {
    write!(output,
        "{{\"event\":\"{event}\",\"mode\":\"{MODE}\",\"security\":\"{security}\",\"prepared\":{},\"polled\":{},\"responded\":{},\"verified\":{},\"warmup_verified\":{},\"total_verified\":{},\"internal_datagrams\":{},\"udp_datagrams\":0,\"max_outstanding\":{},\"slot_empty\":{},\"pending_binding\":{},\"io_pending\":{}",
        state.work.prepared, state.work.polled, state.work.responded, state.work.verified,
        state.warmup.verified, state.warmup.verified + state.work.verified,
        state.warmup.prepared + state.warmup.responded + state.work.prepared + state.work.responded,
        state.max_outstanding, state.slot == Slot::Empty && state.len == 0, state.pending_binding, state.io_pending,
    ).map_err(|_| Fault::Io)?;
    if let Some(fault) = state.terminal {
        write!(output, ",\"terminal\":true,\"reason\":\"{fault}\"").map_err(|_| Fault::Io)?;
    }
    if settled {
        write!(output, ",\"helper_settled\":{}", state.helper_settled).map_err(|_| Fault::Io)?;
    }
    writeln!(output, "}}").map_err(|_| Fault::Io)?;
    flush(output)
}

pub(super) fn run(
    app: &mut CoreApp,
    context: Option<SecurityContext>,
    security: &str,
) -> std::result::Result<(), Failure> {
    let shared = Shared::new();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let result = if !cfg!(windows) {
        shared.lock().helper_settled = true;
        Err(Fault::Unsupported)
    } else {
        scoped(&shared, app, context, Schedule::FIXED, |shared, app| {
            gate(&mut input, b"start\n")?;
            fixture(&mut output, shared, app, security)?;
            let deadline = shared.begin(Phase::Warmup)?;
            drive(shared, app, 0, WARMUP, deadline, Phase::Warmed)?;
            writeln!(output, "{{\"event\":\"warmup\",\"mode\":\"{MODE}\",\"security\":\"{security}\",\"warmup_verified\":128}}").map_err(|_| Fault::Io)?;
            writeln!(output, "{{\"event\":\"ready\",\"mode\":\"{MODE}\",\"security\":\"{security}\",\"kind\":\"work\"}}").map_err(|_| Fault::Io)?;
            flush(&mut output)?;
            gate(&mut input, b"run\n")?;
            let deadline = shared.begin(Phase::Work)?;
            drive(shared, app, WARMUP, OPERATIONS, deadline, Phase::Measured)?;
            {
                let state = shared.lock();
                state.complete(Schedule::FIXED)?;
                counters(&mut output, &state, security, "measured", false)?;
            }
            // Parent must stop and flush its collector before sending verify.
            // Blocking stdin has external containment; no third reader thread.
            gate(&mut input, b"verify\n")?;
            shared.begin(Phase::Finalize)?;
            Ok(())
        }).and_then(|()| {
            {
                let state = shared.lock();
                state.complete(Schedule::FIXED)?;
                if !state.helper_settled { return Err(Fault::Incomplete); }
                counters(&mut output, &state, security, "verified", true)?;
                counters(&mut output, &state, security, "complete", true)?;
            }
            gate(&mut input, b"exit\n")
        })
    };
    if let Err(fault) = result {
        shared.fail(fault);
        // If stdout itself failed, preserve the original failure on process
        // stderr/exit; a failed diagnostic write never becomes a success row.
        let _ = counters(&mut output, &shared.lock(), security, "failed", true);
        return Err(fault.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::batch_tests::{fixture as app_fixture, observe_allocations};
    use super::*;
    use coaptic::message::OptionNumber;

    fn response(app: &mut CoreApp, client: &mut Client, index: usize) -> usize {
        let io = app.transport_mut();
        assert!(io.input_len.is_none() && io.output_len.is_none());
        io.input_len = Some(client.prepare(index, &mut io.input).unwrap());
        app.poll(virtual_ms(index).unwrap()).unwrap();
        assert!(app.transport().input_len.is_none());
        app.transport().output_len.unwrap()
    }

    fn short_schedule() -> Schedule {
        Schedule { warmup: 2, work: 3 }
    }

    fn warm(shared: &Shared, app: &mut CoreApp, schedule: Schedule) -> Result<()> {
        let deadline = shared.begin(Phase::Warmup)?;
        drive(shared, app, 0, schedule.warmup, deadline, Phase::Warmed)
    }

    fn finish_work(shared: &Shared, app: &mut CoreApp, schedule: Schedule) -> Result<()> {
        let deadline = shared.begin(Phase::Work)?;
        drive(
            shared,
            app,
            schedule.warmup,
            schedule.work,
            deadline,
            Phase::Measured,
        )
    }

    #[test]
    fn live_admission_is_separate_and_exact() {
        for security in ["unprotected", "oscore"] {
            let args = ["bench-core", "1000000", security, "--live-c1"].map(String::from);
            assert_eq!(parse_args(&args).unwrap().mode, ProbeMode::LiveC1);
        }
        for raw in [
            "999999 oscore --live-c1",
            "1000001 oscore --live-c1",
            "50000 oscore --live-c1",
            "1000000 bogus --live-c1",
            "1000000 --live-c1",
            "1000000 oscore --live-c1 extra",
            "1000000 oscore",
            "1000000 oscore --batch-cpu",
            "60001 unprotected",
            "1000000 oscore --service-allocated 64",
        ] {
            let args: Vec<_> = std::iter::once("bench-core")
                .chain(raw.split_whitespace())
                .map(String::from)
                .collect();
            assert!(parse_args(&args).is_err(), "{raw}");
        }
        assert_eq!(OPERATIONS, 1_000_000);
        assert_eq!(WARMUP, 128);
        assert_eq!(WORK_TIMEOUT, Duration::from_secs(90));
        assert_eq!(GATE_TIMEOUT, Duration::from_secs(120));
        assert_eq!(HELPER_STACK, 2097152);
        assert_eq!(virtual_ms(0), Ok(0));
        assert_eq!(virtual_ms(65536), Ok(524288));
        assert_eq!(virtual_ms(WARMUP + OPERATIONS - 1), Ok(8001016));
        assert_eq!(virtual_ms(WARMUP + OPERATIONS), Err(Fault::Bounds));
        assert_eq!(virtual_ms(usize::MAX), Err(Fault::Bounds));
        assert!(Schedule { warmup: 0, work: 1 }.validate().is_err());
        assert!(
            Schedule {
                warmup: 128,
                work: OPERATIONS + 1
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn live_both_modes_cross_mid_wrap_and_piv_widths_with_no_thread_allocations() {
        // Includes 255->256 and 65535->65536 sequence/PIV widths, a complete
        // MID cycle, warmup/work transition, and a second use of low MIDs.
        let schedule = Schedule {
            warmup: WARMUP,
            work: 65_540,
        };
        for protected in [false, true] {
            let (mut app, context) = app_fixture(protected);
            let shared = Shared::new();
            scoped(&shared, &mut app, context, schedule, |shared, app| {
                warm(shared, app, schedule)?;
                let (result, allocations) =
                    observe_allocations(|| finish_work(shared, app, schedule));
                result?;
                assert_eq!(allocations, 0, "server thread, protected={protected}");
                {
                    let state = shared.lock();
                    state.complete(schedule)?;
                    assert_eq!(
                        state.client_allocations,
                        Some(0),
                        "client thread, protected={protected}"
                    );
                    assert!(!state.helper_settled); // Still alive through measured/collector stop.
                    assert_eq!(state.phase, Phase::Measured);
                    assert_eq!(state.max_outstanding, 1);
                    #[cfg(windows)]
                    {
                        assert!(state.client_tid > 0);
                        assert_ne!(state.client_tid, current_windows_thread_id());
                    }
                }
                if protected {
                    assert!(
                        !app.oscore()
                            .unwrap()
                            .replay_fresh((schedule.warmup + schedule.work - 1) as u64)
                    );
                }
                shared.begin(Phase::Finalize)?;
                Ok(())
            })
            .unwrap();
            let state = shared.lock();
            state.complete(schedule).unwrap();
            assert!(state.helper_settled);
            assert!(!state.pending_binding && !state.io_pending);
        }
    }

    #[test]
    fn live_full_tokens_piv_bindings_and_consumed_reply_refusal() {
        for protected in [false, true] {
            let (mut app, context) = app_fixture(protected);
            let mut client = Client::new(context);
            for index in 0..=65_537 {
                let n = response(&mut app, &mut client, index);
                let reply = decode(&app.transport().output[..n]).unwrap();
                assert_eq!(reply.token(), Client::token(index).unwrap());
                assert_eq!(reply.message_id(), MessageId::new(index as u16));
                if let Some(context) = client.context.as_ref() {
                    let binding = client.binding.unwrap();
                    assert_eq!(binding.piv().seq(), index as u64);
                    assert_eq!(
                        binding.piv().as_bytes().len(),
                        if index <= 255 {
                            1
                        } else if index <= 65535 {
                            2
                        } else {
                            3
                        }
                    );
                    assert_eq!(context.sender_seq(), index as u64 + 1);
                    assert!(context.lookup(Client::token(index).unwrap()).is_none());
                }
                client.verify(&app.transport().output[..n]).unwrap();
                assert!(client.binding.is_none() && client.operation.is_none());
                assert_eq!(
                    client.verify(&app.transport().output[..n]),
                    Err(Fault::State)
                );
                app.transport_mut().output_len = None;
            }
        }
    }

    #[test]
    fn live_outer_and_ciphertext_corruption_and_binding_failures_refuse() {
        for protected in [false, true] {
            for fault in 0..14 {
                let (mut app, context) = app_fixture(protected);
                let mut client = Client::new(context);
                let n = response(&mut app, &mut client, 0);
                let io = app.transport_mut();
                let mut len = n;
                match fault {
                    0 => io.output[0] ^= 0x10,              // Outer ACK type.
                    1 => io.output[2] ^= 1,                 // Outer MID.
                    2..=9 => io.output[4 + fault - 2] ^= 1, // EACH of all eight token bytes.
                    10 => io.output[n - 1] ^= 1,            // Body or authenticated tag.
                    11 => len -= 1,
                    12 => {
                        client.binding = None;
                        if !protected {
                            len = 0;
                        }
                    }
                    13 => io.output[1] = Code::BAD_REQUEST.as_raw(),
                    _ => unreachable!(),
                }
                assert!(
                    client.verify(&io.output[..len]).is_err(),
                    "fault={fault}, protected={protected}"
                );
                client.cancel();
                assert!(client.operation.is_none() && client.binding.is_none());
            }
        }
        let (mut app, context) = app_fixture(true);
        let mut client = Client::new(context);
        let n = response(&mut app, &mut client, 0);
        let old_binding = client.binding;
        client.verify(&app.transport().output[..n]).unwrap();
        app.transport_mut().output_len = None;
        let n = response(&mut app, &mut client, 1);
        client.binding = old_binding; // Correct header, wrong request AEAD binding.
        assert_eq!(
            client.verify(&app.transport().output[..n]),
            Err(Fault::Authentication)
        );
    }

    #[test]
    fn live_authenticated_semantic_corruption_refuses_without_nonce_reuse() {
        for protected in [false, true] {
            for fault in 0..7 {
                let (mut app, context) = app_fixture(protected);
                let mut client = Client::new(context);
                let mut request_wire = [0; WIRE];
                let n = client.prepare(0, &mut request_wire).unwrap();
                let token = Client::token(0).unwrap();
                let options = [
                    Opt::etag(if fault == 1 { b"changed" } else { b"fixture" }),
                    Opt::new(
                        OptionNumber::CONTENT_FORMAT,
                        if fault == 2 { &[0] } else { &[42] },
                    ),
                    Opt::new(OptionNumber::BLOCK2, &[0]),
                ];
                let plain = Message::new(
                    Type::Acknowledgement,
                    if fault == 0 {
                        Code::CHANGED
                    } else {
                        Code::CONTENT
                    },
                    MessageId::new(0),
                )
                .with_token(token)
                .with_options(if fault == 3 {
                    &options
                } else if fault == 4 {
                    &options[..1]
                } else {
                    &options[..2]
                })
                .with_payload(if fault == 5 {
                    &BODY[..63]
                } else if fault == 6 {
                    b"wrong"
                } else {
                    &BODY
                });
                let mut bytes = [0; WIRE];
                let n = if protected {
                    // Do NOT first produce a legitimate response. Each fresh
                    // binding encrypts exactly one (malformed) plaintext here.
                    let mut opened = [0; WIRE];
                    let (_, binding) = app
                        .oscore_mut()
                        .unwrap()
                        .unprotect_request(&decode(&request_wire[..n]).unwrap(), &mut opened)
                        .unwrap();
                    app.oscore()
                        .unwrap()
                        .protect_response(&plain, binding, &mut bytes)
                        .unwrap()
                } else {
                    plain.encode(&mut bytes).unwrap()
                };
                assert_eq!(
                    client.verify(&bytes[..n]),
                    Err(Fault::Response),
                    "fault={fault}, protected={protected}"
                );
            }
        }
    }

    #[test]
    fn live_replayed_response_and_server_replayed_request_refuse() {
        for protected in [false, true] {
            let (mut app, context) = app_fixture(protected);
            let mut client = Client::new(context);
            let n = response(&mut app, &mut client, 0);
            let old = app.transport().output;
            client.verify(&old[..n]).unwrap();
            app.transport_mut().output_len = None;
            response(&mut app, &mut client, 1);
            assert_eq!(client.verify(&old[..n]), Err(Fault::Response));
        }
        let (mut app, context) = app_fixture(true);
        let mut client = Client::new(context);
        let io = app.transport_mut();
        let request_len = client.prepare(0, &mut io.input).unwrap();
        let original = io.input;
        io.input_len = Some(request_len);
        app.poll(0).unwrap();
        let n = app.transport().output_len.unwrap();
        client.verify(&app.transport().output[..n]).unwrap();
        app.transport_mut().output_len = None;
        let io = app.transport_mut();
        io.input = original;
        io.input[2..4].copy_from_slice(&1u16.to_be_bytes()); // Bypass ordinary dedup.
        io.input_len = Some(request_len);
        app.poll(8).unwrap();
        assert!(app.transport().output_len.is_none());
        assert!(!app.oscore().unwrap().replay_fresh(0));
        let n = response(&mut app, &mut client, 2);
        client.verify(&app.transport().output[..n]).unwrap(); // Fresh sequence recovers.
    }

    #[test]
    fn live_slot_ownership_and_phase_order_refuse_overwrite() {
        for protected in [false, true] {
            let (mut app, context) = app_fixture(protected);
            let shared = Shared::new();
            let mut client = Client::new(context);
            assert_eq!(shared.begin(Phase::Work), Err(Fault::State));
            let deadline = shared.begin(Phase::Warmup).unwrap();
            {
                let mut state = shared.lock();
                state.len = client.prepare(0, &mut state.bytes).unwrap();
                state.index = 0;
                state.slot = Slot::Request;
                let original = state.bytes;
                assert_eq!(client.prepare(1, &mut state.bytes), Err(Fault::State));
                assert_eq!(state.bytes, original);
            }
            assert_eq!(serve_one(&shared, &mut app, 1, deadline), Err(Fault::State));
            assert_eq!(shared.lock().slot, Slot::Request);
            app.transport_mut().input_len = Some(1);
            assert_eq!(serve_one(&shared, &mut app, 0, deadline), Err(Fault::State));
            app.transport_mut().input_len = None;
            serve_one(&shared, &mut app, 0, deadline).unwrap();
            assert_eq!(shared.lock().slot, Slot::Response);
            assert!(shared.begin(Phase::Work).is_err());
            let deadline = Instant::now();
            assert!(matches!(
                shared.wait(deadline, |s| s.slot == Slot::Request),
                Err(Fault::Timeout)
            ));
            assert_eq!(shared.lock().slot, Slot::Response); // Still owns unread response.
        }
    }

    #[test]
    fn live_spurious_wakes_preserve_absolute_deadline_and_predicate() {
        let shared = Shared::new();
        let deadline = Instant::now() + Duration::from_millis(30);
        std::thread::scope(|scope| {
            let notifier = scope.spawn(|| {
                for _ in 0..5 {
                    shared.changed.notify_all();
                    std::thread::sleep(Duration::from_millis(2));
                }
            });
            assert!(matches!(
                shared.wait(deadline, |s| s.slot == Slot::Response),
                Err(Fault::Timeout)
            ));
            assert!(Instant::now() >= deadline);
            notifier.join().unwrap();
        });
        assert_eq!(shared.lock().slot, Slot::Empty);
        shared.fail(Fault::Cancelled);
        assert!(matches!(
            shared.wait(Instant::now() + GATE_TIMEOUT, |_| true),
            Err(Fault::Cancelled)
        ));
    }

    #[test]
    fn live_helper_own_deadlines_settle_with_actual_partial_counts() {
        for protected in [false, true] {
            for active in [false, true] {
                let (_, context) = app_fixture(protected);
                let shared = Shared::new();
                {
                    let mut state = shared.lock();
                    state.phase = if active { Phase::Work } else { Phase::Starting };
                    state.deadline = Instant::now();
                }
                std::thread::scope(|scope| {
                    let task = scope.spawn(|| {
                        helper_guard(&shared, context, |client| {
                            if active {
                                // A real prepared request remains unanswered. The
                                // helper's own fixed deadline must cancel its binding.
                                helper_exchanges(
                                    &shared,
                                    client,
                                    2,
                                    3,
                                    Instant::now() + Duration::from_millis(20),
                                )
                            } else {
                                helper(&shared, client, short_schedule())
                            }
                        })
                    });
                    assert_eq!(task.join().unwrap(), Err(Fault::Timeout));
                });
                let state = shared.lock();
                assert!(state.helper_settled);
                assert_eq!(state.terminal, Some(Fault::Timeout));
                assert!(!state.pending_binding);
                assert!(state.work.prepared <= usize::from(active));
                assert_eq!(state.work.polled, 0);
                assert_eq!(state.work.responded, 0);
                assert_eq!(state.work.verified, 0);
            }
        }
    }

    #[test]
    fn live_main_eof_error_panic_cancel_timeout_always_settle_helper() {
        for protected in [false, true] {
            for fault in 0..6 {
                let (mut app, context) = app_fixture(protected);
                let shared = Shared::new();
                let schedule = short_schedule();
                let result = scoped(&shared, &mut app, context, schedule, |shared, app| {
                    if fault != 0 {
                        warm(shared, app, schedule)?;
                    }
                    match fault {
                        0 | 1 => gate(&mut &b""[..], b"run\n"),
                        2 => Err(Fault::Io),
                        3 => panic!("injected main failure"),
                        4 => Err(Fault::Cancelled),
                        5 => {
                            let deadline = shared.begin(Phase::Work)?;
                            // The fixed deadline, not per-operation progress,
                            // controls refusal; no 90-second test sleep needed.
                            assert!(deadline > Instant::now());
                            drive(
                                shared,
                                app,
                                schedule.warmup,
                                schedule.work,
                                Instant::now(),
                                Phase::Measured,
                            )
                        }
                        _ => unreachable!(),
                    }
                });
                assert!(result.is_err());
                let state = shared.lock();
                assert!(state.helper_settled && state.terminal.is_some());
                assert!(!state.pending_binding);
                assert!(!state.work.complete(schedule.work));
                assert!(state.work.prepared <= schedule.work);
                assert!(state.work.verified <= state.work.responded);
            }
        }
    }

    #[test]
    fn live_helper_panic_poison_and_verification_failure_wake_owner() {
        for protected in [false, true] {
            for poison in [false, true] {
                let (_, context) = app_fixture(protected);
                let shared = Shared::new();
                std::thread::scope(|scope| {
                    let task = scope.spawn(|| {
                        helper_guard(&shared, context, |client| {
                            let mut state = shared.lock();
                            state.len = client.prepare(0, &mut state.bytes)?;
                            state.pending_binding = client.binding.is_some();
                            if !poison {
                                drop(state);
                            }
                            panic!("injected helper panic");
                        })
                    });
                    assert!(matches!(
                        shared.wait(Instant::now() + GATE_TIMEOUT, |s| s.helper_settled),
                        Err(Fault::Panic | Fault::Poison)
                    ));
                    assert!(task.join().unwrap().is_err());
                });
                assert!(shared.lock().helper_settled);
                assert!(!shared.lock().pending_binding);
            }
            let (mut app, context) = app_fixture(protected);
            let shared = Shared::new();
            let schedule = short_schedule();
            let result = scoped(&shared, &mut app, context, schedule, |shared, app| {
                warm(shared, app, schedule)?;
                let deadline = shared.begin(Phase::Work)?;
                // Replace the first work response before publishing it. The
                // helper is waiting for Response and must fail/wake main.
                let mut state = shared.wait(deadline, |s| s.slot == Slot::Request)?;
                state.bytes[0] = 0;
                state.len = 1;
                state.slot = Slot::Response;
                shared.changed.notify_all();
                drop(state);
                drop(shared.wait(deadline, |s| s.phase == Phase::Measured)?);
                Ok(())
            });
            assert_eq!(result, Err(Fault::Response));
            assert!(shared.lock().helper_settled);
            assert_eq!(shared.lock().work.verified, 0);
            assert_eq!(shared.lock().work.polled, 0);
        }
    }

    #[test]
    fn live_finalize_gate_eof_preserves_actual_counts_and_failure_row() {
        for protected in [false, true] {
            let (mut app, context) = app_fixture(protected);
            let shared = Shared::new();
            let schedule = short_schedule();
            let result = scoped(&shared, &mut app, context, schedule, |shared, app| {
                warm(shared, app, schedule)?;
                finish_work(shared, app, schedule)?;
                assert!(!shared.lock().helper_settled);
                gate(&mut &b"ver"[..], b"verify\n")
            });
            assert_eq!(result, Err(Fault::Eof));
            let state = shared.lock();
            assert!(state.helper_settled);
            assert!(state.work.complete(3));
            assert!(state.warmup.complete(2));
            let mut output = Vec::new();
            counters(
                &mut output,
                &state,
                if protected { "oscore" } else { "unprotected" },
                "failed",
                true,
            )
            .unwrap();
            let row = String::from_utf8(output).unwrap();
            for field in [
                "\"event\":\"failed\"",
                "\"terminal\":true",
                "\"reason\":\"Eof\"",
                "\"prepared\":3",
                "\"polled\":3",
                "\"responded\":3",
                "\"verified\":3",
                "\"warmup_verified\":2",
                "\"total_verified\":5",
                "\"internal_datagrams\":10",
                "\"helper_settled\":true",
                "\"slot_empty\":true",
                "\"pending_binding\":false",
                "\"io_pending\":false",
            ] {
                assert!(row.contains(field), "missing {field} in {row}");
            }
            assert!(!row.contains("1000000"));
        }
        for mut raw in [&b""[..], &b"run"[..], &b"bad\n"[..]] {
            assert!(gate(&mut raw, b"run\n").is_err());
        }
        assert_eq!(gate(&mut &b"run\n"[..], b"run\n"), Ok(()));
        assert_eq!(gate(&mut &b""[..], b"oversize"), Err(Fault::Bounds));
    }
}

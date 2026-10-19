//! Shared host diagnostics for one explicitly identified App source.
//!
//! Mutex acquisition linearizes record/sample/reset operations. A delayed sample
//! joins the window in which it is recorded, even if captured before reset.
//! Keep one adapter per App/clock domain; source IDs are local configuration,
//! never peer-supplied labels. Capture App snapshots under the App owner's normal
//! exclusive access, then publish them here. No App reference or event queue is kept.
//! Poison is reported; it is not silently recovered. Export copies state before
//! formatting or I/O, so a slow writer cannot hold the diagnostics mutex.
//! Scheduling, lock-wait and writer latency remain host responsibilities;
//! bounded storage and encoded size do not imply a wall-clock execution bound.

#![forbid(unsafe_code)]

use coaptic::app::AppUsage;
use coaptic::app::diagnostics::{Reason, Recorder, Snapshot};
use coaptic::storage::PoolUsage;
use std::{io, sync::Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Poisoned,
    WrongSource,
    StaleSample,
}

#[derive(Clone, Copy, Debug, Default)]
struct State {
    recorder: Recorder,
    latest: Option<Snapshot>,
}

/// Caller-owned synchronization wrapper; sharing via Arc is optional.
pub struct Diagnostics {
    source: u32,
    state: Mutex<State>,
}

impl Diagnostics {
    pub fn new(source: u32) -> Self {
        Self {
            source,
            state: Mutex::new(State::default()),
        }
    }

    pub fn record(&self, source: u32, reason: Reason) -> Result<(), Error> {
        self.check_source(source)?;
        self.state
            .lock()
            .map_err(|_| Error::Poisoned)?
            .recorder
            .record(reason);
        Ok(())
    }

    /// Publish a bounded snapshot. Equal timestamps are ordered by the mutex;
    /// decreasing timestamps are refused without changing the current window.
    pub fn sample(&self, source: u32, snapshot: Snapshot) -> Result<(), Error> {
        self.check_source(source)?;
        let mut state = self.state.lock().map_err(|_| Error::Poisoned)?;
        if state.latest.is_some_and(|last| last.at_ms > snapshot.at_ms) {
            return Err(Error::StaleSample);
        }
        state.recorder.sample(&snapshot);
        state.latest = Some(snapshot);
        Ok(())
    }

    /// Reset only host observations. Core counters and protocol state are untouched.
    /// Dropping the adapter similarly has no effects on its App.
    pub fn reset(&self) -> Result<(), Error> {
        *self.state.lock().map_err(|_| Error::Poisoned)? = State::default();
        Ok(())
    }

    pub fn report(&self) -> Result<Report, Error> {
        let state = self.state.lock().map_err(|_| Error::Poisoned)?;
        Ok(Report {
            source: self.source,
            recorder: state.recorder,
            latest: state.latest,
        })
    }

    fn check_source(&self, source: u32) -> Result<(), Error> {
        if source == self.source {
            Ok(())
        } else {
            Err(Error::WrongSource)
        }
    }
}

/// Immutable export copy; counters and maxima have the core Recorder semantics.
#[derive(Clone, Copy, Debug)]
pub struct Report {
    pub source: u32,
    pub recorder: Recorder,
    pub latest: Option<Snapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    TooSmall { required: usize, available: usize },
    LengthOverflow,
}
#[derive(Debug)]
pub enum WriteError {
    Encode(EncodeError),
    Io(io::Error),
}

impl Report {
    /// Encode the fixed-shape CBOR v1 contract in diagnostics.cddl.
    /// Short output remains unchanged; no text labels, peer IDs or payloads exist.
    /// The optional core WorkMetrics feature is not included in this host contract.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let mut count = Sink {
            output: None,
            position: 0,
        };
        self.encode_into(&mut count)?;
        let required = count.position;
        if required > output.len() {
            return Err(EncodeError::TooSmall {
                required,
                available: output.len(),
            });
        }
        self.encode_into(&mut Sink {
            output: Some(output),
            position: 0,
        })?;
        Ok(required)
    }

    /// Encode before writing; the byte slice supplies the explicit export bound.
    /// Writer failure may leave a partial record. The caller owns framing/retry
    /// and writer latency. No lock is held and no report is consumed or reset.
    pub fn write_to(
        &self,
        output: &mut [u8],
        writer: &mut impl io::Write,
    ) -> Result<usize, WriteError> {
        let n = self.encode(output).map_err(WriteError::Encode)?;
        writer.write_all(&output[..n]).map_err(WriteError::Io)?;
        Ok(n)
    }

    fn encode_into(&self, sink: &mut Sink<'_>) -> Result<(), EncodeError> {
        sink.array(6)?;
        sink.uint(1)?;
        sink.uint(u64::from(self.source))?;
        sink.array(Reason::ALL.len())?;
        for reason in Reason::ALL {
            sink.uint(u64::from(self.recorder.count(reason)))?;
        }
        sink.uint(self.recorder.samples())?;
        if let Some(snapshot) = self.latest {
            sink.array(5)?;
            sink.uint(snapshot.at_ms)?;
            metrics(sink, snapshot.metrics)?;
            usage(sink, snapshot.usage)?;
            optional_uint(sink, snapshot.next_timeout_ms)?;
            optional_uint(sink, snapshot.next_poll_ms)?;
        } else {
            sink.null()?;
        }
        if let Some(maxima) = self.recorder.sampled_maxima() {
            usage(sink, maxima)?;
        } else {
            sink.null()?;
        }
        Ok(())
    }
}

struct Sink<'a> {
    output: Option<&'a mut [u8]>,
    position: usize,
}
impl Sink<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(EncodeError::LengthOverflow)?;
        if let Some(output) = self.output.as_deref_mut() {
            let available = output.len();
            output
                .get_mut(self.position..end)
                .ok_or(EncodeError::TooSmall {
                    required: end,
                    available,
                })?
                .copy_from_slice(bytes);
        }
        self.position = end;
        Ok(())
    }
    fn head(&mut self, major: u8, value: u64) -> Result<(), EncodeError> {
        if value < 24 {
            self.bytes(&[(major << 5) | value as u8])
        } else if let Ok(value) = u8::try_from(value) {
            self.bytes(&[(major << 5) | 24, value])
        } else {
            let bytes = value.to_be_bytes();
            let (additional, start) = if u16::try_from(value).is_ok() {
                (25, 6)
            } else if u32::try_from(value).is_ok() {
                (26, 4)
            } else {
                (27, 0)
            };
            self.bytes(&[(major << 5) | additional])?;
            self.bytes(&bytes[start..])
        }
    }
    fn uint(&mut self, value: u64) -> Result<(), EncodeError> {
        self.head(0, value)
    }
    fn array(&mut self, len: usize) -> Result<(), EncodeError> {
        self.head(4, len as u64)
    }
    fn null(&mut self) -> Result<(), EncodeError> {
        self.bytes(&[0xf6])
    }
}
fn optional_uint(sink: &mut Sink<'_>, value: Option<u64>) -> Result<(), EncodeError> {
    if let Some(value) = value {
        sink.uint(value)
    } else {
        sink.null()
    }
}
fn pool(sink: &mut Sink<'_>, value: PoolUsage) -> Result<(), EncodeError> {
    sink.array(2)?;
    sink.uint(value.occupied as u64)?;
    sink.uint(value.capacity as u64)
}
fn optional_pool(sink: &mut Sink<'_>, value: Option<PoolUsage>) -> Result<(), EncodeError> {
    if let Some(value) = value {
        pool(sink, value)
    } else {
        sink.null()
    }
}
fn usage(sink: &mut Sink<'_>, value: AppUsage) -> Result<(), EncodeError> {
    sink.array(16)?;
    pool(sink, value.storage.rx_datagram)?;
    pool(sink, value.storage.tx_datagram)?;
    pool(sink, value.storage.dedup)?;
    pool(sink, value.storage.observe)?;
    optional_pool(sink, value.storage.rx_body)?;
    optional_pool(sink, value.storage.tx_body)?;
    sink.uint(value.ordinary_tx_capacity as u64)?;
    sink.uint(value.full_response_capacity as u64)?;
    pool(sink, value.routes)?;
    pool(sink, value.client_requests)?;
    sink.uint(value.client_cooldowns as u64)?;
    pool(sink, value.client_replies)?;
    sink.uint(value.completed_replies as u64)?;
    pool(sink, value.deferred)?;
    optional_pool(sink, value.security)?;
    sink.uint(value.revoked_associations as u64)
}
fn metrics(sink: &mut Sink<'_>, value: coaptic::Metrics) -> Result<(), EncodeError> {
    let counters = [
        value.token_capacity_refused,
        value.admission_rx_refused,
        value.admission_tx_refused,
        value.admission_refusal_sent,
        value.admission_refusal_unsent,
        value.hard_rx_exhausted,
        value.hard_tx_exhausted,
        value.rx_accepted,
        value.rx_error,
        value.tx_ok,
        value.tx_fail,
        value.con_retransmit,
        value.give_up,
        value.observe_notify,
        value.observe_register,
        value.observe_cancel,
        value.block1_assemble,
        value.block2_assemble,
        value.progress,
        value.saturated,
        value.nstart_reject,
        value.empty_ack,
        value.empty_rst,
    ];
    sink.array(counters.len())?;
    for value in counters {
        sink.uint(u64::from(value))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poisoned_owner_is_explicit() {
        let diagnostics = Diagnostics::new(1);
        std::thread::scope(|scope| {
            assert!(
                scope
                    .spawn(|| {
                        let _guard = diagnostics.state.lock().unwrap();
                        panic!("injected owner failure");
                    })
                    .join()
                    .is_err()
            );
        });
        assert_eq!(
            diagnostics.record(1, Reason::Capacity),
            Err(Error::Poisoned)
        );
        assert_eq!(diagnostics.reset(), Err(Error::Poisoned));
        assert!(matches!(diagnostics.report(), Err(Error::Poisoned)));
    }
}

//! Finite separate-CON state for the standalone peer fixture, not upstream coap-rs.
use super::{MAX_DATAGRAM, MAX_PENDING};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

const BACKEND_WAIT: Duration = Duration::from_secs(10);
const MAX_RETRANSMIT: u8 = 4;

struct Slot {
    id: u64,
    peer: SocketAddr,
    request: Vec<u8>,
    response: Option<Vec<u8>>,
    deadline: Instant,
    span_end: Instant,
    wait_end: Instant,
    interval: Duration,
    retries: u8,
}

#[derive(Debug, PartialEq)]
pub(super) enum Admission {
    Fresh(u64),
    Duplicate,
    Refused,
}

pub(super) struct Pending {
    slots: Vec<Slot>,
    next_id: u64,
}
impl Pending {
    pub(super) fn new() -> Self {
        Self {
            slots: Vec::with_capacity(MAX_PENDING),
            next_id: 0,
        }
    }
    pub(super) fn admit(&mut self, peer: SocketAddr, request: &[u8], now: Instant) -> Admission {
        if request.len() > MAX_DATAGRAM || request.len() < 4 {
            return Admission::Refused;
        }
        if let Some(slot) = self.slots.iter().find(|slot| slot.peer == peer) {
            return if slot.request == request {
                Admission::Duplicate
            } else {
                Admission::Refused
            };
        }
        if self.slots.len() == MAX_PENDING {
            return Admission::Refused;
        }
        let Some(id) = self.next_id.checked_add(1) else {
            return Admission::Refused;
        };
        self.next_id = id;
        self.slots.push(Slot {
            id,
            peer,
            request: request.to_vec(),
            response: None,
            deadline: now + BACKEND_WAIT,
            span_end: now,
            wait_end: now,
            interval: Duration::ZERO,
            retries: 0,
        });
        Admission::Fresh(id)
    }
    pub(super) fn complete(
        &mut self,
        id: u64,
        bytes: &[u8],
        now: Instant,
        interval: Duration,
    ) -> bool {
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.id == id) else {
            return false;
        };
        if slot.response.is_some()
            || now >= slot.deadline
            || bytes.len() > MAX_DATAGRAM
            || bytes.len() < 4
            || !(Duration::from_secs(2)..=Duration::from_secs(3)).contains(&interval)
        {
            return false;
        }
        // The backend must preserve the admitted token and supply a new CON MID.
        let token_len = usize::from(slot.request[0] & 15);
        if bytes[0] != (0x40 | token_len as u8)
            || !matches!(bytes[1] >> 5, 2 | 4 | 5)
            || coap_lite::Packet::from_bytes(bytes).is_err()
            || bytes[2..4] == slot.request[2..4]
            || bytes.get(4..4 + token_len) != slot.request.get(4..4 + token_len)
        {
            return false;
        }
        slot.response = Some(bytes.to_vec());
        slot.interval = interval;
        slot.deadline = now + interval;
        slot.span_end = now + interval * ((1 << MAX_RETRANSMIT) - 1);
        slot.wait_end = now + interval * ((1 << (MAX_RETRANSMIT + 1)) - 1);
        true
    }
    pub(super) fn control(&mut self, peer: SocketAddr, bytes: &[u8]) -> bool {
        if bytes.len() != 4 || !matches!(bytes[0], 0x60 | 0x70) || bytes[1] != 0 {
            return false;
        }
        let Some(index) = self.slots.iter().position(|slot| {
            slot.peer == peer
                && slot
                    .response
                    .as_ref()
                    .is_some_and(|response| response[2..4] == bytes[2..4])
        }) else {
            return false;
        };
        self.slots.swap_remove(index);
        true
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.slots.iter().map(|slot| slot.deadline).min()
    }
    pub(super) fn due(&mut self, now: Instant) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut sends = Vec::new();
        self.slots.retain_mut(|slot| {
            if now < slot.deadline {
                return true;
            }
            let Some(response) = &slot.response else {
                return false;
            };
            if slot.retries == MAX_RETRANSMIT || now >= slot.wait_end {
                return false;
            }
            if now > slot.span_end {
                slot.deadline = slot.wait_end;
                return true;
            }
            sends.push((response.clone(), slot.peer));
            slot.retries += 1;
            slot.interval *= 2;
            slot.deadline = (now + slot.interval).min(slot.wait_end);
            true
        });
        sends
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(n: u16) -> SocketAddr {
        ([127, 0, 0, 1], 1000 + n).into()
    }
    const REQUEST: &[u8] = &[0x41, 1, 0, 3, 9];
    const RESPONSE: &[u8] = &[0x41, 69, 0, 4, 9, 0xff, 77];
    fn reserve(p: &mut Pending, n: u16, now: Instant) -> u64 {
        let Admission::Fresh(id) = p.admit(peer(n), REQUEST, now) else {
            panic!("not admitted")
        };
        id
    }
    #[test]
    fn bounded_admission_stale_backend_and_control_ownership() {
        let now = Instant::now();
        let mut pending = Pending::new();
        let id = reserve(&mut pending, 0, now);
        assert_eq!(pending.admit(peer(0), REQUEST, now), Admission::Duplicate);
        assert_eq!(
            pending.admit(peer(0), &[0x41, 1, 0, 5, 9], now),
            Admission::Refused
        );
        for n in 1..MAX_PENDING {
            reserve(&mut pending, n as u16, now);
        }
        assert_eq!(pending.admit(peer(9), REQUEST, now), Admission::Refused);
        assert!(!pending.control(peer(0), &[0x60, 0, 0, 4])); // not sent yet
        assert!(pending.complete(id, RESPONSE, now, Duration::from_secs(2)));
        assert!(!pending.complete(id, RESPONSE, now, Duration::from_secs(2)));
        for bad in [
            &[0x60, 0, 0, 5][..],
            &[0x61, 0, 0, 4, 9],
            &[0x70, 1, 0, 4],
            &[0x60, 0, 0, 4, 0xff, 1],
        ] {
            assert!(!pending.control(peer(0), bad));
        }
        assert!(!pending.control(peer(1), &[0x60, 0, 0, 4]));
        assert!(pending.control(peer(0), &[0x60, 0, 0, 4]));
        let new_id = reserve(&mut pending, 0, now);
        assert_ne!(id, new_id);
        assert!(!pending.complete(id, RESPONSE, now, Duration::from_secs(2)));
        assert!(pending.complete(new_id, RESPONSE, now, Duration::from_secs(2)));
        assert!(pending.control(peer(0), &[0x70, 0, 0, 4]));
        assert!(!pending.control(peer(0), &[0x70, 0, 0, 4]));
        assert!(pending.due(now + BACKEND_WAIT).is_empty());
        assert_eq!(pending.deadline(), None);
        reserve(&mut pending, 0, now + BACKEND_WAIT);
    }
    #[test]
    fn invalid_backend_bytes_and_limits_refuse_before_valid_recovery() {
        let now = Instant::now();
        let mut pending = Pending::new();
        assert_eq!(
            pending.admit(peer(0), &vec![0; MAX_DATAGRAM + 1], now),
            Admission::Refused
        );
        let id = reserve(&mut pending, 0, now);
        let mut invalid = vec![vec![], vec![0; MAX_DATAGRAM + 1]];
        for (index, value) in [(0, 0x61), (1, 0), (1, 0x61), (2, 0), (4, 10)] {
            let mut bytes = RESPONSE.to_vec();
            bytes[index] = value;
            if index == 2 {
                bytes[3] = 3;
            }
            invalid.push(bytes);
        }
        for bytes in invalid {
            assert!(!pending.complete(id, &bytes, now, Duration::from_secs(2)));
        }
        for millis in [1999, 3001] {
            assert!(!pending.complete(id, RESPONSE, now, Duration::from_millis(millis)));
        }
        assert!(pending.complete(id, RESPONSE, now, Duration::from_secs(2)));
        assert!(pending.control(peer(0), &[0x60, 0, 0, 4]));
        pending.next_id = u64::MAX;
        assert_eq!(pending.admit(peer(0), REQUEST, now), Admission::Refused);
    }
    #[test]
    fn complete_retransmissions_backoff_expiry_and_late_poll_bound() {
        let now = Instant::now();
        let mut pending = Pending::new();
        let id = reserve(&mut pending, 0, now);
        assert!(pending.complete(id, RESPONSE, now, Duration::from_secs(2)));
        for second in [2, 6, 14, 30] {
            assert!(
                pending
                    .due(now + Duration::from_secs(second) - Duration::from_millis(1))
                    .is_empty()
            );
            assert_eq!(
                pending.due(now + Duration::from_secs(second)),
                vec![(RESPONSE.to_vec(), peer(0))]
            );
            assert!(pending.due(now + Duration::from_secs(second)).is_empty());
        }
        assert!(pending.due(now + Duration::from_secs(62)).is_empty());
        assert_eq!(pending.deadline(), None);
        let id = reserve(&mut pending, 0, now);
        assert!(pending.complete(id, RESPONSE, now, Duration::from_secs(3)));
        assert!(pending.due(now + Duration::from_secs(46)).is_empty());
        assert_eq!(pending.deadline(), Some(now + Duration::from_secs(93)));
        pending.due(now + Duration::from_secs(93));
        assert_eq!(pending.deadline(), None);
        let old = reserve(&mut pending, 0, now);
        pending.due(now + BACKEND_WAIT);
        let fresh = reserve(&mut pending, 0, now + BACKEND_WAIT);
        assert!(!pending.complete(old, RESPONSE, now + BACKEND_WAIT, Duration::from_secs(2)));
        assert!(pending.complete(fresh, RESPONSE, now + BACKEND_WAIT, Duration::from_secs(2)));
    }
}

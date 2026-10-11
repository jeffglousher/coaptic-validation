//! Bounded one-shot receive loss owned by one qualification transport.
use coaptic::message::{Code, MessageId, Type, decode};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct ObserveLoss(Arc<Mutex<State>>);
#[derive(Default)]
struct State {
    rule: Option<Rule>,
    consumed: usize,
}
struct Rule {
    peer: SocketAddr,
    token: [u8; 8],
    len: usize,
    ack: bool,
    mid: Option<MessageId>,
}
impl ObserveLoss {
    pub(crate) fn arm(
        &self,
        peer: SocketAddr,
        token: &[u8],
        ack: bool,
    ) -> Result<(), &'static str> {
        if token.is_empty() || token.len() > 8 {
            return Err("invalid loss token");
        }
        let mut state = self.0.lock().expect("loss");
        if state.rule.is_some() {
            return Err("loss rule occupied");
        }
        let mut bytes = [0; 8];
        bytes[..token.len()].copy_from_slice(token);
        state.rule = Some(Rule {
            peer,
            token: bytes,
            len: token.len(),
            ack,
            mid: None,
        });
        Ok(())
    }
    pub(crate) fn sent(&self, peer: SocketAddr, bytes: &[u8]) {
        let Ok(p) = decode(bytes) else {
            return;
        };
        let mut state = self.0.lock().expect("loss");
        if let Some(rule) = &mut state.rule {
            if rule.ack
                && rule.mid.is_none()
                && peer == rule.peer
                && p.ty() == Type::Confirmable
                && p.code() == Code::CONTENT
                && p.observe().is_some()
                && p.token().as_bytes() == &rule.token[..rule.len]
            {
                rule.mid = Some(p.message_id());
            }
        }
    }
    pub(crate) fn received(&self, peer: SocketAddr, bytes: &[u8]) -> bool {
        let Ok(p) = decode(bytes) else {
            return false;
        };
        let mut state = self.0.lock().expect("loss");
        let Some(rule) = &state.rule else {
            return false;
        };
        let matches = peer == rule.peer
            && if rule.ack {
                bytes.len() == 4
                    && p.ty() == Type::Acknowledgement
                    && p.code().is_empty()
                    && rule.mid == Some(p.message_id())
            } else {
                p.ty() == Type::Confirmable
                    && p.code() == Code::CONTENT
                    && p.observe().is_some()
                    && p.token().as_bytes() == &rule.token[..rule.len]
            };
        if matches {
            state.rule = None;
            state.consumed += 1;
        }
        matches
    }
    pub(crate) fn consumed(&self) -> usize {
        self.0.lock().expect("loss").consumed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coaptic::message::{Message, Opt, Token, encode};
    fn note(mid: u16, token: &[u8]) -> Vec<u8> {
        let sequence = coaptic::message::encode_uint(1);
        let options = [Opt::observe(&sequence)];
        let message = Message::new(Type::Confirmable, Code::CONTENT, MessageId::new(mid))
            .with_token(Token::new(token).unwrap())
            .with_options(&options)
            .with_payload(b"body");
        let mut bytes = [0; 128];
        let n = encode(&message, &mut bytes).unwrap();
        bytes[..n].to_vec()
    }
    #[test]
    fn notification_loss_is_owned_bounded_and_one_shot() {
        let loss = ObserveLoss::default();
        let owner = "127.0.0.1:5683".parse().unwrap();
        let other = "127.0.0.1:5684".parse().unwrap();
        assert!(loss.arm(owner, &[], false).is_err());
        assert!(loss.arm(owner, &[1; 9], false).is_err());
        loss.arm(owner, &[1], false).unwrap();
        assert!(loss.arm(other, &[2], false).is_err());
        assert!(!loss.received(other, &note(1, &[1])));
        assert!(!loss.received(owner, &note(1, &[2])));
        assert!(!loss.received(owner, &[0x60, 0, 0, 1]));
        assert!(!loss.received(owner, &[0]));
        assert_eq!(loss.consumed(), 0);
        assert!(loss.received(owner, &note(1, &[1])));
        assert!(!loss.received(owner, &note(1, &[1])));
        assert_eq!(loss.consumed(), 1);
        loss.arm(other, &[2], false).unwrap();
        assert!(loss.received(other, &note(2, &[2])));
        assert_eq!(loss.consumed(), 2);
    }
    #[test]
    fn ack_loss_requires_owned_notification_and_exact_empty_control() {
        let loss = ObserveLoss::default();
        let owner = "127.0.0.1:5683".parse().unwrap();
        let other = "127.0.0.1:5684".parse().unwrap();
        loss.arm(owner, &[1], true).unwrap();
        assert!(!loss.received(owner, &[0x60, 0, 0, 1]));
        loss.sent(other, &note(1, &[1]));
        loss.sent(owner, &note(1, &[2]));
        assert!(!loss.received(owner, &[0x60, 0, 0, 1]));
        loss.sent(owner, &note(1, &[1]));
        loss.sent(owner, &note(2, &[1])); // cannot replace the already bound MID
        for (peer, bytes) in [
            (other, &b"\x60\x00\x00\x01"[..]),
            (owner, &b"\x60\x00\x00\x02"[..]),
            (owner, &b"\x70\x00\x00\x01"[..]),
            (owner, &b"\x60\x01\x00\x01"[..]),
            (owner, &b"\x60\x00\x00\x01\x00"[..]),
        ] {
            assert!(!loss.received(peer, bytes));
        }
        assert_eq!(loss.consumed(), 0);
        assert!(loss.received(owner, &[0x60, 0, 0, 1]));
        assert!(!loss.received(owner, &[0x60, 0, 0, 1]));
        assert_eq!(loss.consumed(), 1);
    }
}

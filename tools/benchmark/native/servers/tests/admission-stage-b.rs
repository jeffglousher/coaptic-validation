//! Stage B is an independent, feature-gated integration executable.
//! Compilation, qualification and timing are UNRUN until external qualification.
#[path = "admission_stage_b/fixture.rs"]
mod fixture;
const CONTRACT: &str = include_str!("../../../admission_stage_b_contract.json");
const HASH: &str = "161b7fd033cd7c2cc37b203f878b4307de913e2da2b651bacdbe9e84c186a83c";
mod stage_b {
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn rx_unprotected() {
        super::fixture::run(super::fixture::Case::Rx, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn rx_oscore() {
        super::fixture::run(super::fixture::Case::Rx, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn tx_unprotected() {
        super::fixture::run(super::fixture::Case::Tx, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn tx_oscore() {
        super::fixture::run(super::fixture::Case::Tx, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn observe_cancel_unprotected() {
        super::fixture::run(super::fixture::Case::Observe, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn observe_cancel_oscore() {
        super::fixture::run(super::fixture::Case::Observe, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn notification_block2_unprotected() {
        super::fixture::run(super::fixture::Case::Notification, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn notification_block2_oscore() {
        super::fixture::run(super::fixture::Case::Notification, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn ordinary_block2_unprotected() {
        super::fixture::run(super::fixture::Case::Ordinary, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn ordinary_block2_oscore() {
        super::fixture::run(super::fixture::Case::Ordinary, true, true);
    }
}
mod stage_b_validation {
    #[test]
    fn rx_unprotected() {
        super::fixture::run(super::fixture::Case::Rx, false, false);
    }
    #[test]
    fn rx_oscore() {
        super::fixture::run(super::fixture::Case::Rx, true, false);
    }
    #[test]
    fn tx_unprotected() {
        super::fixture::run(super::fixture::Case::Tx, false, false);
    }
    #[test]
    fn tx_oscore() {
        super::fixture::run(super::fixture::Case::Tx, true, false);
    }
    #[test]
    fn observe_cancel_unprotected() {
        super::fixture::run(super::fixture::Case::Observe, false, false);
    }
    #[test]
    fn observe_cancel_oscore() {
        super::fixture::run(super::fixture::Case::Observe, true, false);
    }
    #[test]
    fn notification_block2_unprotected() {
        super::fixture::run(super::fixture::Case::Notification, false, false);
    }
    #[test]
    fn notification_block2_oscore() {
        super::fixture::run(super::fixture::Case::Notification, true, false);
    }
    #[test]
    fn ordinary_block2_unprotected() {
        super::fixture::run(super::fixture::Case::Ordinary, false, false);
    }
    #[test]
    fn ordinary_block2_oscore() {
        super::fixture::run(super::fixture::Case::Ordinary, true, false);
    }
    #[test]
    fn ordinary_three_rx_owners_refuse_unprotected() {
        super::fixture::run(super::fixture::Case::Negative, false, false);
    }
    #[test]
    fn ordinary_three_rx_owners_refuse_oscore() {
        super::fixture::run(super::fixture::Case::Negative, true, false);
    }
}

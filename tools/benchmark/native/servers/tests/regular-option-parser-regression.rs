//! Source-specific parser regression executable; qualification and timing are separate.
#[path = "regular_option_regression/long_options.rs"]
mod long_options;
#[path = "admission_stage_b/fixture.rs"]
mod pressure_fixture;
const CONTRACT: &str = include_str!("../../../regular_option_regression_contract.json");
const HASH: &str = "bcb57fc34170707f1395a449d9f511a3fb292f094599b6f1c35a630581c6a205";
mod stage_b {
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn rx_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Rx, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn rx_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Rx, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn tx_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Tx, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn tx_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Tx, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn observe_cancel_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Observe, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn observe_cancel_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Observe, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn notification_block2_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Notification, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn notification_block2_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Notification, true, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn ordinary_block2_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Ordinary, false, true);
    }
    #[test]
    #[ignore = "explicit Stage B timing selection only"]
    fn ordinary_block2_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Ordinary, true, true);
    }
    #[test]
    #[ignore = "explicit parser regression timing selection only"]
    fn long_small_device_unprotected() {
        super::long_options::run(false, false, true);
    }
    #[test]
    #[ignore = "explicit parser regression timing selection only"]
    fn long_small_device_oscore() {
        super::long_options::run(false, true, true);
    }
    #[test]
    #[ignore = "explicit parser regression timing selection only"]
    fn long_default_unprotected() {
        super::long_options::run(true, false, true);
    }
    #[test]
    #[ignore = "explicit parser regression timing selection only"]
    fn long_default_oscore() {
        super::long_options::run(true, true, true);
    }
}
mod stage_b_validation {
    #[test]
    fn rx_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Rx, false, false);
    }
    #[test]
    fn rx_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Rx, true, false);
    }
    #[test]
    fn tx_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Tx, false, false);
    }
    #[test]
    fn tx_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Tx, true, false);
    }
    #[test]
    fn observe_cancel_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Observe, false, false);
    }
    #[test]
    fn observe_cancel_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Observe, true, false);
    }
    #[test]
    fn notification_block2_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Notification, false, false);
    }
    #[test]
    fn notification_block2_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Notification, true, false);
    }
    #[test]
    fn ordinary_block2_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Ordinary, false, false);
    }
    #[test]
    fn ordinary_block2_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Ordinary, true, false);
    }
    #[test]
    fn ordinary_three_rx_owners_refuse_unprotected() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Negative, false, false);
    }
    #[test]
    fn ordinary_three_rx_owners_refuse_oscore() {
        super::pressure_fixture::run(super::pressure_fixture::Case::Negative, true, false);
    }
    #[test]
    fn long_small_device_unprotected() {
        super::long_options::run(false, false, false);
    }
    #[test]
    fn long_small_device_oscore() {
        super::long_options::run(false, true, false);
    }
    #[test]
    fn long_default_unprotected() {
        super::long_options::run(true, false, false);
    }
    #[test]
    fn long_default_oscore() {
        super::long_options::run(true, true, false);
    }
}

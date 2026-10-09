fn main() {
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    println!("cargo:rerun-if-env-changed=COAPTIC_DEVICE_RUN_ID");
}

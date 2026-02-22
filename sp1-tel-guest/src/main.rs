#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: sp1_tel_guest::TelInput = sp1_zkvm::io::read();
    sp1_tel_guest::run_tel_verification(&input);
}

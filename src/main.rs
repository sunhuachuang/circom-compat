mod witness;
pub use witness::{Wasm, WitnessCalculator};

pub mod circom;
pub use circom::{CircomBuilder, CircomCircuit, CircomConfig, CircomReduction};

#[cfg(feature = "ethereum")]
pub mod ethereum;

mod zkey;
pub use zkey::read_zkey;

mod zkey_bls12_381;
pub use zkey_bls12_381::read_zkey as read_bls12_381_zkey;

pub mod zkp;

pub mod input;

use input::decode_prove_input;
use std::fs::{read_to_string, write};
use zkp::bls12_381::{prove, verify, proofs_to_abi_bytes};

// const WASM_BYTES: &[u8] = include_bytes!("../materials/game2048_60.wasm");
// const R1CS_BYTES: &[u8] = include_bytes!("../materials/game2048_60.r1cs");
// const ZKEY_BYTES: &[u8] = include_bytes!("../materials/game2048_60.zkey");

//const WASM_BYTES: &[u8] = include_bytes!("../materials/game2048_60_bls.wasm");
//const R1CS_BYTES: &[u8] = include_bytes!("../materials/game2048_60_bls.r1cs");
const ZKEY_BYTES: &[u8] = include_bytes!("../materials/game2048_60_bls.zkey");
const WASM_BYTES: &[u8] = include_bytes!("../materials/test/game2048_60.wasm");
const R1CS_BYTES: &[u8] = include_bytes!("../materials/test/game2048_60.r1cs");

/// INPUT=test_input OUTPUT=test_output PROOF=test_proof cargo run --release
#[tokio::main]
async fn main() {
    let input_path = std::env::var("INPUT").expect("env INPUT missing");
    let output_path = std::env::var("OUTPUT").expect("env OUTPUT missing");
    let proof_path = std::env::var("PROOF").expect("env PROOF missing");

    let input_hex = read_to_string(input_path).expect("Unable to read input file");
    let input_bytes =
        hex::decode(input_hex.trim_start_matches("0x")).expect("Unable to decode input file");
    let input = decode_prove_input(&input_bytes).expect("Unable to decode input");
    println!("input ok");

    let (pi, proof) = prove(WASM_BYTES, R1CS_BYTES, ZKEY_BYTES, input).unwrap();
    println!("proof ok");
    assert!(verify(WASM_BYTES, R1CS_BYTES, ZKEY_BYTES, &pi, &proof).unwrap());
    println!("verify ok");
    let (pi_bytes, proof_bytes) = proofs_to_abi_bytes(&pi, &proof).unwrap();

    let pi_hex = format!("0x{}", hex::encode(pi_bytes));
    write(output_path, pi_hex).expect("Unable to create output file");

    let proof_hex = format!("0x{}", hex::encode(proof_bytes));
    write(proof_path, proof_hex).expect("Unable to create proof file");
}

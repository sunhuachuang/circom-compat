use anyhow::{anyhow, Error};
use ark_bn254::{Bn254, Fr};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_snark::SNARK;
use ethabi::{encode, ethereum_types::U256, Token};
use num_bigint::BigInt;
use once_cell::sync::OnceCell;
use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
use std::io::{BufReader, Cursor};
use std::{collections::HashMap, fs::File};
use wasmer::{Module, Store};

use crate::{
    read_zkey,
    circom::{R1CSFile, R1CS},
    CircomBuilder, CircomConfig, CircomReduction, WitnessCalculator,
};

type Result<T> = core::result::Result<T, Error>;

type GrothBn = Groth16<Bn254, CircomReduction>;

pub struct Input {
    pub maps: HashMap<String, Vec<BigInt>>,
}

static CONFIG: OnceCell<(CircomConfig<Fr>, ProvingKey<Bn254>)> = OnceCell::new();

pub fn init_config(wasm: &str, r1cs: &str, zkey: &str) -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(wasm, r1cs)
        .map_err(|_| anyhow!("Failed to new circom config"))?;

    let mut zkey_file = File::open(zkey)?;
    let (prover_key, _) = read_zkey(&mut zkey_file)?;

    CONFIG
        .set((cfg, prover_key))
        .map_err(|_| anyhow!("Failed to set circom config"))?;
    Ok(())
}

// pub fn init_from_bytes(wasm: &[u8], r1cs: &[u8], zkey: &[u8]) -> Result<()> {
//     let store = Store::default();
//     let module = Module::new(&store, wasm)?;

//     let reader = BufReader::new(Cursor::new(r1cs));
//     let r1cs_file = R1CSFile::<Fr>::new(reader)?;

//     let cfg = CircomConfig {
//         wtns: WitnessCalculator::from_module(module)
//             .map_err(|_| anyhow!("Failed to calculate circom witness"))?,
//         r1cs: R1CS::from(r1cs_file),
//         sanity_check: false,
//     };

//     let mut zkey_reader = BufReader::new(Cursor::new(zkey));
//     let (prover_key, _) = read_zkey(&mut zkey_reader)?;

//     CONFIG
//         .set((cfg, prover_key))
//         .map_err(|_| anyhow!("Failed to set circom config"))?;
//     Ok(())
// }

pub fn prove(input: Input) -> Result<(Vec<Fr>, Proof<Bn254>)> {
    let (cfg, prover_key) = CONFIG
        .get()
        .ok_or_else(|| anyhow!("Failed to get circom config"))?;

    let mut builder = CircomBuilder::new(cfg.clone());
    builder.push_inputs(input.maps);

    let circom = builder.build().map_err(|_| anyhow!("Failed to build"))?;
    let pi = circom
        .get_public_inputs()
        .ok_or_else(|| anyhow!("Failed to get public inputs"))?;

    let mut rng = ChaChaRng::from_entropy();
    let proof = GrothBn::prove(prover_key, circom, &mut rng)?;

    Ok((pi, proof))
}

pub fn verify(publics: &[Fr], proof: &Proof<Bn254>) -> Result<bool> {
    let (_, prover_key) = CONFIG
        .get()
        .ok_or_else(|| anyhow!("Failed to get circom config"))?;

    Ok(GrothBn::verify(&prover_key.vk, publics, proof)?)
}

#[inline]
fn parse_filed_to_token<F: PrimeField>(f: &F) -> Token {
    let bytes = f.into_bigint().to_bytes_be();
    Token::Uint(U256::from_big_endian(&bytes))
}

pub fn proofs_to_abi_bytes(publics: &[Fr], proof: &Proof<Bn254>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut pi_token = vec![];
    for x in publics.iter() {
        pi_token.push(parse_filed_to_token(x));
    }

    let mut proof_token = vec![];
    let (ax, ay) = proof.a.xy().ok_or_else(|| anyhow!("Infallible point"))?;
    proof_token.push(parse_filed_to_token(ax));
    proof_token.push(parse_filed_to_token(ay));

    let (bx, by) = proof.b.xy().ok_or_else(|| anyhow!("Infallible point"))?;
    proof_token.push(parse_filed_to_token(&bx.c1));
    proof_token.push(parse_filed_to_token(&bx.c0));
    proof_token.push(parse_filed_to_token(&by.c1));
    proof_token.push(parse_filed_to_token(&by.c0));

    let (cx, cy) = proof.c.xy().ok_or_else(|| anyhow!("Infallible point"))?;
    proof_token.push(parse_filed_to_token(cx));
    proof_token.push(parse_filed_to_token(cy));

    let pi_bytes = encode(&pi_token);
    let proof_bytes = encode(&proof_token);

    Ok((pi_bytes, proof_bytes))
}

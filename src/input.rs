use std::collections::HashMap;

use ethabi::{decode, encode, ethereum_types::U256, ParamType, Token};
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};

pub struct Input {
    pub maps: HashMap<String, Vec<BigInt>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Game2048Input {
    pub board: Vec<Vec<u8>>,
    #[serde(rename = "packedBoard")]
    pub packed_board: Vec<String>,
    #[serde(rename = "packedDir")]
    pub packed_dir: String,
    pub direction: Vec<u8>,
    pub address: String,
    pub nonce: String,
    pub step: u64,
    #[serde(rename = "stepAfter")]
    pub step_after: u64,
}

impl Game2048Input {
    #[allow(dead_code)]
    pub fn to_hex(&self) -> String {
        let mut board = vec![];
        for x in self.board.iter() {
            board.push(Token::Bytes(x.to_vec()));
        }

        let mut packed_board = vec![];
        for x in self.packed_board.iter() {
            packed_board.push(Token::Uint(U256::from_dec_str(x).unwrap()))
        }

        let packed_dir = Token::Uint(U256::from_dec_str(&self.packed_dir).unwrap());
        let address = Token::Uint(U256::from_dec_str(&self.address).unwrap());
        let nonce = Token::Uint(U256::from_dec_str(&self.nonce).unwrap());
        let direction = Token::Bytes(self.direction.clone());
        let step = Token::Uint(U256::from(self.step));
        let step_after = Token::Uint(U256::from(self.step_after));

        let bytes = encode(&[
            Token::Array(board),
            Token::Array(packed_board),
            packed_dir,
            direction,
            address,
            nonce,
            step,
            step_after,
        ]);
        format!("0x{}", hex::encode(&bytes))
    }
}

pub fn decode_prove_input(bytes: &[u8]) -> Result<Input, anyhow::Error> {
    let input_tokens = decode(
        &[
            ParamType::Array(Box::new(ParamType::Bytes)),
            ParamType::Array(Box::new(ParamType::Uint(256))),
            ParamType::Uint(256),
            ParamType::Bytes,
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
        ],
        bytes,
    )?;

    let f_uint = |token: Token| -> BigInt {
        let mut bytes = [0u8; 32];
        token.into_uint().unwrap().to_big_endian(&mut bytes);
        BigInt::from_bytes_be(Sign::Plus, &bytes)
    };

    let f_array_bytes = |token: Token| -> Vec<BigInt> {
        let token = token.into_array().unwrap();
        let mut tmp = vec![];
        for x in token {
            for y in x.into_bytes().unwrap() {
                tmp.push(BigInt::from(y))
            }
        }
        tmp
    };

    let board = f_array_bytes(input_tokens[0].clone());
    let mut packed_board = vec![];
    for x in input_tokens[1].clone().into_array().unwrap() {
        packed_board.push(f_uint(x))
    }
    let packed_dir = f_uint(input_tokens[2].clone());
    let direction = input_tokens[3].clone().into_bytes().unwrap();
    let direction = direction.iter().map(|x| BigInt::from(*x)).collect();
    let address = f_uint(input_tokens[4].clone());
    let nonce = f_uint(input_tokens[5].clone());
    let step = f_uint(input_tokens[6].clone());
    let step_after = f_uint(input_tokens[7].clone());

    let mut maps = HashMap::new();
    maps.insert("board".to_string(), board);
    maps.insert("packedBoard".to_string(), packed_board);
    maps.insert("packedDir".to_string(), vec![packed_dir]);
    maps.insert("direction".to_string(), direction);
    maps.insert("address".to_string(), vec![address]);
    maps.insert("step".to_string(), vec![step]);
    maps.insert("stepAfter".to_string(), vec![step_after]);
    maps.insert("nonce".to_string(), vec![nonce]);

    Ok(Input { maps })
}

#[cfg(test)]
mod test {
    use crate::input::decode_prove_input;

    use super::Game2048Input;

    #[test]
    fn test_serialize() {
        let input = r##"
        {
            "board": [
                [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0],
                [0, 2, 4, 6, 0, 1, 2, 4, 0, 0, 0, 5, 0, 0, 1, 3]
            ],
            "packedBoard": ["35218731827200", "2515675923718842875939"],
            "packedDir": "311800516178808354245949615821275955",
            "direction": [0, 3, 3, 0, 0, 0, 3, 0, 3, 3, 0, 3, 3, 0, 3, 0, 2, 0, 3, 3, 0, 2, 0, 3, 0, 0, 3, 0, 2, 0, 3, 3, 0, 0, 3, 0, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 3, 2, 3, 3, 0, 3, 3, 0, 0, 3, 0, 3, 0, 3],
            "address": "6789",
            "step": 0,
            "stepAfter": 60,
            "nonce": "456"
        }
        "##;

        let input: Game2048Input = serde_json::from_str(input).unwrap();
        let hex = input.to_hex();
        println!("{}", hex);

        let input_hex = hex.trim_start_matches("0x");
        let input_bytes = hex::decode(input_hex).expect("Unable to decode input file");
        decode_prove_input(&input_bytes).expect("Unable to decode input");
    }
}

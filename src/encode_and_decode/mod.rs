use crate::crypt;
use ascii85;
use base32;
use base64::{decode, encode};
use boba;
use bs58;
use cienli::ciphers::*;
use crypto::digest::Digest;
use crypto::*;
use crypto_brainfuck;
use hex;
use neon::prelude::*;
// encode and decode
pub fn brainfuck_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let chipher = crypto_brainfuck::encode(&plain_text);
    Ok(cx.string(chipher))
}
pub fn brainfuck_decode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let plain_text = crypto_brainfuck::decode(&cipher_text);
    Ok(cx.string(plain_text))
}
pub fn at_bash_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let at_bash = atbash::Atbash::new(&plain_text);
    let chipher = at_bash.encipher();
    Ok(cx.string(chipher))
}
pub fn at_bash_decode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let at_bash = atbash::Atbash::new(&cipher_text);
    let plain_text = at_bash.decipher();
    Ok(cx.string(plain_text))
}
pub fn caesar_encode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let plain_text = arg0.value(&mut cx);
    let rotation = arg1.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match caesar::Caesar::new(rotation as u8) {
        Ok(ceasar_cipher) => {
            let data = cx.string(ceasar_cipher.encipher(&plain_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("The rotation must be in range 1 and 26.");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn caesar_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let cipher_text = arg0.value(&mut cx);
    let rotation = arg1.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match caesar::Caesar::new(rotation as u8) {
        Ok(ceasar_cipher) => {
            let data = cx.string(ceasar_cipher.decipher(&cipher_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("The rotation must be in range 1 and 26.");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn polybius_square_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let polybius_square_cipher = polybius_square::PolybiusSquare::new(&plain_text);
    let chipher = polybius_square_cipher.encipher();
    Ok(cx.string(chipher))
}
pub fn polybius_square_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let polybius_square_cipher = polybius_square::PolybiusSquare::new(&cipher_text);
    let result = JsObject::new(&mut cx);
    match polybius_square_cipher.decipher() {
        Ok(data) => {
            let new_data = cx.string(data);
            result.set(&mut cx, "data", new_data).ok();
        }
        Err(_) => {
            let error_message = cx.string("invalid key");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn scytale_encode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let plain_text = arg0.value(&mut cx);
    let key = arg1.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match scytale::Scytale::new(key as usize) {
        Ok(scytale_cipher) => {
            let data = cx.string(scytale_cipher.encipher(&plain_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("invalid key");
            result.set(&mut cx, "error", error_message).ok();
        }
    }
    Ok(result)
}
pub fn scytale_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let cipher_text = arg0.value(&mut cx);
    let key = arg1.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match scytale::Scytale::new(key as usize) {
        Ok(scytale_cipher) => {
            let data = cx.string(scytale_cipher.decipher(&cipher_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("invalid key");
            result.set(&mut cx, "error", error_message).ok();
        }
    }
    Ok(result)
}
pub fn vigenere_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let plain_text = arg0.value(&mut cx);
    let key = arg1.value(&mut cx);
    let vigenere_cipher = vigenere::Vigenere::new(&key);
    let chipher = vigenere_cipher.encipher(&plain_text);
    Ok(cx.string(chipher))
}
pub fn vigenere_decode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let cipher_text = arg0.value(&mut cx);
    let key = arg1.value(&mut cx);
    let vigenere_cipher = vigenere::Vigenere::new(&key);
    let plain_text = vigenere_cipher.decipher(&cipher_text);
    Ok(cx.string(plain_text))
}
pub fn x_or_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let plain_text = arg0.value(&mut cx);
    let key = arg1.value(&mut cx);
    let x_or_cipher = xor::Xor::new(&key);
    let chipher = x_or_cipher.encipher(&plain_text);
    Ok(cx.string(chipher))
}
pub fn x_or_decode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let cipher_text = arg0.value(&mut cx);
    let key = arg1.value(&mut cx);
    let x_or_cipher = xor::Xor::new(&key);
    let plain_text = x_or_cipher.decipher(&cipher_text);
    Ok(cx.string(plain_text))
}
pub fn rot_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let plain_text = arg0.value(&mut cx);
    let algorithm = arg1.value(&mut cx) as u8;
    let rot_cipher: rot::Rot;
    if algorithm == 5 {
        rot_cipher = rot::Rot::new(&plain_text, rot::RotType::Rot5)
    } else if algorithm == 13 {
        rot_cipher = rot::Rot::new(&plain_text, rot::RotType::Rot13);
    } else if algorithm == 18 {
        rot_cipher = rot::Rot::new(&plain_text, rot::RotType::Rot18);
    } else if algorithm == 47 {
        rot_cipher = rot::Rot::new(&plain_text, rot::RotType::Rot47);
    } else {
        return Ok(cx.string("invalid cipher"));
    }
    let cipher = rot_cipher.encipher();
    Ok(cx.string(cipher))
}
pub fn rot_decode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let cipher_text = arg0.value(&mut cx);
    let algorithm = arg1.value(&mut cx) as u8;
    let rot_cipher: rot::Rot;
    if algorithm == 5 {
        rot_cipher = rot::Rot::new(&cipher_text, rot::RotType::Rot5)
    } else if algorithm == 13 {
        rot_cipher = rot::Rot::new(&cipher_text, rot::RotType::Rot13);
    } else if algorithm == 18 {
        rot_cipher = rot::Rot::new(&cipher_text, rot::RotType::Rot18);
    } else if algorithm == 47 {
        rot_cipher = rot::Rot::new(&cipher_text, rot::RotType::Rot47);
    } else {
        return Ok(cx.string("invalid cipher"));
    }
    let plain_text = rot_cipher.decipher();
    Ok(cx.string(plain_text))
}

pub fn bacon_encode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let plain_text = arg0.value(&mut cx);
    let key: Vec<char> = arg1.value(&mut cx).chars().collect();
    let result = JsObject::new(&mut cx);
    match bacon::Bacon::new((key[0], key[1])) {
        Ok(bacon_chipher) => {
            let data = cx.string(bacon_chipher.encipher(&plain_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("Non coprime key");
            result.set(&mut cx, "error", error_message).ok();
        }
    }
    Ok(result)
}
pub fn bacon_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let cipher_text = arg0.value(&mut cx);
    let key: Vec<char> = arg1.value(&mut cx).chars().collect();
    let result = JsObject::new(&mut cx);
    match bacon::Bacon::new((key[0], key[1])) {
        Ok(bacon_chipher) => {
            let data = cx.string(bacon_chipher.decipher(&cipher_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("Non coprime key");
            result.set(&mut cx, "error", error_message).ok();
        }
    }
    Ok(result)
}

pub fn affine_encode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let arg2: Handle<JsNumber> = cx.argument::<JsNumber>(2)?;
    let plain_text = arg0.value(&mut cx);
    let num1 = arg1.value(&mut cx) as u16;
    let num2 = arg2.value(&mut cx) as u16;
    let result = JsObject::new(&mut cx);
    match affine::Affine::new((num1, num2)) {
        Ok(affine_cipher) => {
            let data = cx.string(affine_cipher.encipher(&plain_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("Non coprime key");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn affine_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let arg2: Handle<JsNumber> = cx.argument::<JsNumber>(2)?;
    let cipher_text = arg0.value(&mut cx);
    let num1 = arg1.value(&mut cx) as u16;
    let num2 = arg2.value(&mut cx) as u16;
    let result = JsObject::new(&mut cx);
    match affine::Affine::new((num1, num2)) {
        Ok(affine_cipher) => {
            let data = cx.string(affine_cipher.decipher(&cipher_text));
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("Non coprime key");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn base_64_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let chipher = encode(plain_text);
    Ok(cx.string(chipher))
}
pub fn base_64_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match decode(cipher_text) {
        Ok(cipher_text) => match String::from_utf8(cipher_text) {
            Ok(cipher_text) => {
                let data = cx.string(cipher_text);
                result.set(&mut cx, "data", data).ok();
            }
            Err(_) => {
                let error_message = cx.string("Failed to covert to string");
                result.set(&mut cx, "error", error_message).ok();
            }
        },
        Err(_) => {
            let error_message = cx.string("Failed to covert to string");
            result.set(&mut cx, "error", error_message).ok();
        }
    }
    Ok(result)
}
pub fn base_58_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let alphabet = arg1.value(&mut cx) as u8;
    let plain_text = arg0.value(&mut cx);
    let cipher: String;
    if alphabet == 1 {
        cipher = bs58::encode(plain_text)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string();
    } else if alphabet == 2 {
        cipher = bs58::encode(plain_text)
            .with_alphabet(bs58::Alphabet::MONERO)
            .into_string();
    } else if alphabet == 3 {
        cipher = bs58::encode(plain_text)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_string();
    } else if alphabet == 4 {
        cipher = bs58::encode(plain_text)
            .with_alphabet(bs58::Alphabet::FLICKR)
            .into_string();
    } else {
        cipher = bs58::encode(plain_text)
            .with_alphabet(bs58::Alphabet::DEFAULT)
            .into_string();
    }
    Ok(cx.string(cipher))
}
pub fn base_58_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsNumber> = cx.argument::<JsNumber>(1)?;
    let alphabet = arg1.value(&mut cx) as u8;
    let cipher_text = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    if alphabet == 1 {
        match bs58::decode(cipher_text)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_vec()
        {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded) => {
                    let data = cx.string(decoded);
                    result.set(&mut cx, "data", data).ok();
                }
                Err(_) => {
                    let error_message = cx.string("incorrect alphabet");
                    result.set(&mut cx, "error", error_message).ok();
                }
            },
            Err(_) => {
                let error_message = cx.string("decoding failure");
                result.set(&mut cx, "error", error_message).ok();
            }
        };
    } else if alphabet == 2 {
        match bs58::decode(cipher_text)
            .with_alphabet(bs58::Alphabet::MONERO)
            .into_vec()
        {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded) => {
                    let data = cx.string(decoded);
                    result.set(&mut cx, "data", data).ok();
                }
                Err(_) => {
                    let error_message = cx.string("incorrect alphabet");
                    result.set(&mut cx, "error", error_message).ok();
                }
            },
            Err(_) => {
                let error_message = cx.string("decoding failure");
                result.set(&mut cx, "error", error_message).ok();
            }
        };
    } else if alphabet == 3 {
        match bs58::decode(cipher_text)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .into_vec()
        {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded) => {
                    let data = cx.string(decoded);
                    result.set(&mut cx, "data", data).ok();
                }
                Err(_) => {
                    let error_message = cx.string("incorrect alphabet");
                    result.set(&mut cx, "error", error_message).ok();
                }
            },
            Err(_) => {
                let error_message = cx.string("decoding failure");
                result.set(&mut cx, "error", error_message).ok();
            }
        };
    } else if alphabet == 4 {
        match bs58::decode(cipher_text)
            .with_alphabet(bs58::Alphabet::FLICKR)
            .into_vec()
        {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded) => {
                    let data = cx.string(decoded);
                    result.set(&mut cx, "data", data).ok();
                }
                Err(_) => {
                    let error_message = cx.string("incorrect alphabet");
                    result.set(&mut cx, "error", error_message).ok();
                }
            },
            Err(_) => {
                let error_message = cx.string("decoding failure");
                result.set(&mut cx, "error", error_message).ok();
            }
        };
    } else {
        match bs58::decode(cipher_text)
            .with_alphabet(bs58::Alphabet::DEFAULT)
            .into_vec()
        {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded) => {
                    let data = cx.string(decoded);
                    result.set(&mut cx, "data", data).ok();
                }
                Err(_) => {
                    let error_message = cx.string("incorrect alphabet");
                    result.set(&mut cx, "error", error_message).ok();
                }
            },
            Err(_) => {
                let error_message = cx.string("decoding failure");
                result.set(&mut cx, "error", error_message).ok();
            }
        };
    }
    Ok(result)
}
pub fn base_32_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let cipher_text = base32::encode(base32::Alphabet::Crockford, plain_text.as_bytes());
    Ok(cx.string(cipher_text))
}
pub fn base_32_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match base32::decode(base32::Alphabet::Crockford, &cipher_text) {
        Some(data) => match String::from_utf8(data) {
            Ok(data) => {
                let data = cx.string(data);
                result.set(&mut cx, "data", data).ok();
            }
            Err(_) => {
                let error_message = cx.string("Failed to convert to string");
                result.set(&mut cx, "error", error_message).ok();
            }
        },
        None => {
            let error_message = cx.string("decoding failure");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn hex_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let cipher_text = hex::encode(plain_text);
    Ok(cx.string(cipher_text))
}
pub fn hex_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match hex::decode(cipher_text) {
        Ok(data) => match String::from_utf8(data) {
            Ok(data) => {
                let data = cx.string(data);
                result.set(&mut cx, "data", data).ok();
            }
            Err(_) => {
                let error_message = cx.string("failed to convert to string");
                result.set(&mut cx, "error", error_message).ok();
            }
        },
        Err(_) => {
            let error_message = cx.string("decoding failure, none hex data");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}
pub fn ascii85_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let cipher_text = ascii85::encode(plain_text.as_bytes());
    Ok(cx.string(cipher_text))
}
pub fn ascii85_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match ascii85::decode(&cipher_text) {
        Ok(data) => match String::from_utf8(data) {
            Ok(data) => {
                let data = cx.string(data);
                result.set(&mut cx, "data", data).ok();
            }
            Err(_) => {
                let error_message = cx.string("failed to convert to string");
                result.set(&mut cx, "error", error_message).ok();
            }
        },
        Err(_) => {
            let error_message = cx.string("decoding failure, none hex data");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}

pub fn dec_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let cipher_text = plain_text.as_bytes();
    let mut message: String = String::new();
    for character in cipher_text {
        let new_string = format!("{} ", character);
        message.push_str(&new_string);
    }
    Ok(cx.string(message))
}

pub fn dec_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsArray> = cx.argument::<JsArray>(0)?;
    let vec: Vec<Handle<JsValue>> = arg0.to_vec(&mut cx)?;
    let mut plain_text: Vec<u8> = Vec::new();
    for char in vec {
        let value = char.clone();
        let new_value = value
            .downcast::<JsNumber, _>(&mut cx)
            .unwrap()
            .value(&mut cx);
        plain_text.push(new_value as u8);
    }
    let result = JsObject::new(&mut cx);
    match String::from_utf8(plain_text) {
        Ok(data) => {
            let data = cx.string(data);
            result.set(&mut cx, "data", data).ok();
        }
        Err(_) => {
            let error_message = cx.string("decoding failure, invalid data");
            result.set(&mut cx, "error", error_message).ok();
        }
    }
    Ok(result)
}
pub fn bubble_babble_encode(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let cipher_text = boba::encode(plain_text);
    Ok(cx.string(cipher_text))
}
pub fn bubble_babble_decode(mut cx: FunctionContext) -> JsResult<JsObject> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let cipher_text = arg0.value(&mut cx);
    let result = JsObject::new(&mut cx);
    match boba::decode(cipher_text) {
        Ok(plain_text) => {
            match String::from_utf8(plain_text) {
                Ok(data) => {
                    let data = cx.string(data);
                    result.set(&mut cx, "data", data).ok();
                }
                Err(_) => {
                    let error_message = cx.string("failed to convert to string");
                    result.set(&mut cx, "error", error_message).ok();
                }
            };
        }
        Err(_) => {
            let error_message = cx.string("decoding failure, invalid byte or bytes");
            result.set(&mut cx, "error", error_message).ok();
        }
    };
    Ok(result)
}

pub fn sha1_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha1::Sha1::new();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha256_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha2::Sha256::new();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha512_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha2::Sha512::new();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha384_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha2::Sha384::new();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn md5_linux_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let arg1: Handle<JsString> = cx.argument::<JsString>(1)?;
    let plain_text = arg0.value(&mut cx);
    let salt = arg1.value(&mut cx);
    Ok(cx.string(crypt::md5(&plain_text, &salt)))
}
pub fn whirlpool_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = whirlpool::Whirlpool::new();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha3_224_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::sha3_224();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha3_256_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::sha3_256();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha3_384_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::sha3_384();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn sha3_512_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::sha3_512();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn shake128_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::shake_128();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn shake256_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::shake_256();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn keccak224_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::keccak224();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn keccak256_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::keccak256();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn keccak384_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::keccak384();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}
pub fn keccak512_hash(mut cx: FunctionContext) -> JsResult<JsString> {
    let arg0: Handle<JsString> = cx.argument::<JsString>(0)?;
    let plain_text = arg0.value(&mut cx);
    let mut hasher = sha3::Sha3::keccak512();
    hasher.input_str(&plain_text);
    Ok(cx.string(hasher.result_str()))
}

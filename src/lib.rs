extern crate neon;
use neon::prelude::*;
mod binwalk;
mod cracker;
mod encode_and_decode;
mod identifier;
mod ip_analysis;
mod password_analysis;
mod steganography;
mod crypt;
// main function
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // encode and decode
    cx.export_function("brainfuck_encode", encode_and_decode::brainfuck_encode)?;
    cx.export_function("brainfuck_decode", encode_and_decode::brainfuck_decode)?;
    cx.export_function("at_bash_encode", encode_and_decode::at_bash_encode)?;
    cx.export_function("at_bash_decode", encode_and_decode::at_bash_decode)?;
    cx.export_function(
        "polybius_square_encode",
        encode_and_decode::polybius_square_encode,
    )?;
    cx.export_function(
        "polybius_square_decode",
        encode_and_decode::polybius_square_decode,
    )?;
    cx.export_function("caesar_encode", encode_and_decode::caesar_encode)?;
    cx.export_function("caesar_decode", encode_and_decode::caesar_decode)?;
    cx.export_function("scytale_encode", encode_and_decode::scytale_encode)?;
    cx.export_function("scytale_decode", encode_and_decode::scytale_decode)?;
    cx.export_function("vigenere_encode", encode_and_decode::vigenere_encode)?;
    cx.export_function("vigenere_decode", encode_and_decode::vigenere_decode)?;
    cx.export_function("x_or_encode", encode_and_decode::x_or_encode)?;
    cx.export_function("x_or_decode", encode_and_decode::x_or_decode)?;
    cx.export_function("rot_encode", encode_and_decode::rot_encode)?;
    cx.export_function("rot_decode", encode_and_decode::rot_decode)?;
    cx.export_function("bacon_encode", encode_and_decode::bacon_encode)?;
    cx.export_function("bacon_decode", encode_and_decode::bacon_decode)?;
    cx.export_function("affine_encode", encode_and_decode::affine_encode)?;
    cx.export_function("affine_decode", encode_and_decode::affine_decode)?;
    cx.export_function("base64_encode", encode_and_decode::base_64_encode)?;
    cx.export_function("base64_decode", encode_and_decode::base_64_decode)?;
    cx.export_function("base58_encode", encode_and_decode::base_58_encode)?;
    cx.export_function("base58_decode", encode_and_decode::base_58_decode)?;
    cx.export_function("base32_encode", encode_and_decode::base_32_encode)?;
    cx.export_function("base32_decode", encode_and_decode::base_32_decode)?;
    cx.export_function("hex_encode", encode_and_decode::hex_encode)?;
    cx.export_function("hex_decode", encode_and_decode::hex_decode)?;
    cx.export_function("ascii85_encode", encode_and_decode::ascii85_encode)?;
    cx.export_function("ascii85_decode", encode_and_decode::ascii85_decode)?;
    cx.export_function("dec_encode", encode_and_decode::dec_encode)?;
    cx.export_function("dec_decode", encode_and_decode::dec_decode)?;
    cx.export_function(
        "bubble_babble_encode",
        encode_and_decode::bubble_babble_encode,
    )?;
    cx.export_function(
        "bubble_babble_decode",
        encode_and_decode::bubble_babble_decode,
    )?;
    cx.export_function("sha1_hash", encode_and_decode::sha1_hash)?;
    cx.export_function("sha256_hash", encode_and_decode::sha256_hash)?;
    cx.export_function("sha512_hash", encode_and_decode::sha512_hash)?;
    cx.export_function("sha384_hash", encode_and_decode::sha384_hash)?;
    cx.export_function("md5_linux_hash", encode_and_decode::md5_linux_hash)?;
    cx.export_function("whirlpool_hash", encode_and_decode::whirlpool_hash)?;
    cx.export_function("sha3_224_hash", encode_and_decode::sha3_224_hash)?;
    cx.export_function("sha3_256_hash", encode_and_decode::sha3_256_hash)?;
    cx.export_function("sha3_512_hash", encode_and_decode::sha3_512_hash)?;
    cx.export_function("sha3_384_hash", encode_and_decode::sha3_384_hash)?;
    cx.export_function("keccak224_hash", encode_and_decode::keccak224_hash)?;
    cx.export_function("keccak256_hash", encode_and_decode::keccak256_hash)?;
    cx.export_function("keccak384_hash", encode_and_decode::keccak384_hash)?;
    cx.export_function("keccak512_hash", encode_and_decode::keccak512_hash)?;
    // hash identification
    cx.export_function("identify", identifier::identify)?;
    // steganography
    cx.export_function(
        "white_space_steg_hide",
        steganography::white_space_steg_hide,
    )?;
    cx.export_function(
        "white_space_steg_reveal",
        steganography::white_space_steg_reveal,
    )?;
    cx.export_function(
        "png_steg_text_file_hide",
        steganography::png_steg_text_file_hide,
    )?;
    cx.export_function(
        "png_steg_text_file_reveal",
        steganography::png_steg_text_file_reveal,
    )?;
    cx.export_function(
        "png_steg_png_file_hide",
        steganography::png_steg_png_file_hide,
    )?;
    cx.export_function(
        "png_steg_png_file_reveal",
        steganography::png_steg_png_file_reveal,
    )?;
    // ip analysis
    cx.export_function("grab_banner", ip_analysis::grab_banner)?;
    cx.export_function("scan_port_addrs", ip_analysis::scan_port_addrs)?;
    cx.export_function("scan_port_addrs_range", ip_analysis::scan_port_addrs_range)?;
    // password strength analysis
    cx.export_function(
        "password_strength_estimator",
        password_analysis::password_strength_estimator,
    )?;

    // binwalk
    cx.export_function("binwalk_signature_scan", binwalk::binwalk_signature_scan)?;
    cx.export_function(
        "binwalk_signature_extract",
        binwalk::binwalk_signature_extract,
    )?;

    // cracker
    cx.export_function("cracker_new", cracker::cracker_new)?;
    cx.export_function(
        "cracker_crack_using_password_file",
        cracker::cracker_crack_using_password_file,
    )?;
    cx.export_function("get_counter", cracker::get_counter)?;

    cx.export_function(
        "cracker_new_from_shadow_file",
        cracker::cracker_new_from_shadow_file,
    )?;
    cx.export_function("get_salt", cracker::get_salt)?;
    cx.export_function("get_hash", cracker::get_hash)?;
    cx.export_function("get_algorithms", cracker::get_algorithms)?;
    Ok(())
}

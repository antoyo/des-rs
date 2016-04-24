extern crate des;

use std::fs::File;
use std::io::{Read, Result};

use des::{decrypt, encrypt};

fn read_file(filename: &str) -> Result<Vec<u8>> {
    let mut file = try!(File::open(filename));
    let mut result = vec![];
    try!(file.read_to_end(&mut result));
    Ok(result)
}

#[test]
fn encrypt_decrypt_image() {
    let original_content = read_file("tests/Rust.png").unwrap();
    let expected_content = read_file("tests/Rust.png.des").unwrap();

    let key = b"rustrust";
    let cipher = encrypt(&original_content, &key);

    assert_eq!(expected_content, cipher);
    assert!(cipher != original_content);

    let decrypted_content = decrypt(&cipher, &key);

    assert_eq!(decrypted_content, original_content);
    assert!(decrypted_content != expected_content);
}

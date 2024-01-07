/*
 * Copyright (c) 2016 Boucher, Antoni <bouanto@zoho.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

extern crate des;

use std::fs::File;
use std::io::{Read, Result};

use des::{decrypt, encrypt, encrypt_3des, decrypt_3des};

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

#[test]
fn encrypt_decrypt_image_3des() {
    let original_content = read_file("tests/Rust.png").unwrap();
    let expected_content = read_file("tests/Rust.png.3des").unwrap();

    let key = b"rustrust";
    let key2 = b"2024PRSu";
    let key3 = b"2024PRSu";
    let cipher = encrypt_3des(&original_content, &key, &key2, &key3);
    assert_eq!(expected_content, cipher);
    assert!(cipher != original_content);

    let decrypted_content = decrypt_3des(&cipher, &key, &key2, &key3);

    assert_eq!(decrypted_content, original_content);
    assert!(decrypted_content != expected_content);
}
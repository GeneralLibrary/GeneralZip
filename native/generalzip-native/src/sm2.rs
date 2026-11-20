use sm2::pke::DecryptingKey;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

fn decrypt(private_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, i32> {
    if private_key.len() != 32 || ciphertext.len() < 97 || ciphertext.len() > 1_048_576 {
        return Err(crate::status::ERR_ARG);
    }

    let key = DecryptingKey::from_slice(private_key).map_err(|_| crate::status::ERR_ARG)?;
    key.decrypt(ciphertext)
        .map_err(|_| crate::status::ERR_FORMAT)
}

/// Decrypts an SM2 C1-C3-C2 ciphertext using the constant-time RustCrypto implementation.
#[no_mangle]
pub unsafe extern "system" fn gzp_sm2_decrypt(
    private_key: *const u8,
    private_key_len: u32,
    ciphertext: *const u8,
    ciphertext_len: u32,
    output: *mut u8,
    output_capacity: u32,
    output_len: *mut u32,
) -> i32 {
    if private_key.is_null()
        || ciphertext.is_null()
        || (output.is_null() && output_capacity != 0)
        || output_len.is_null()
    {
        return crate::status::ERR_ARG;
    }
    if private_key_len != 32 || ciphertext_len < 97 || ciphertext_len > 1_048_576 {
        return crate::status::ERR_ARG;
    }

    unsafe { *output_len = 0 };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let private_key = unsafe { slice::from_raw_parts(private_key, private_key_len as usize) };
        let ciphertext = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len as usize) };
        let plaintext = decrypt(private_key, ciphertext)?;
        if plaintext.len() > output_capacity as usize {
            return Err(crate::status::ERR_BUFFER);
        }

        unsafe {
            if !plaintext.is_empty() {
                std::ptr::copy_nonoverlapping(plaintext.as_ptr(), output, plaintext.len());
            }
            *output_len = plaintext.len() as u32;
        }
        Ok(())
    }));

    match result {
        Ok(Ok(())) => crate::status::OK,
        Ok(Err(code)) => code,
        Err(_) => crate::status::ERR_PANIC,
    }
}

#[cfg(test)]
mod tests {
    use super::decrypt;

    fn from_hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => panic!("invalid hex"),
                };
                (digit(pair[0]) << 4) | digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn decrypts_interop_anchor() {
        let private_key =
            from_hex("8c8b89335e42c636156ee63fd0c7afa0e1c1845b4a86feea77daef214b2b6cd8");
        let mut ciphertext = vec![0x04];
        ciphertext.extend(from_hex(
            "28fb184b5a7a49cf8839fec53aba1d9987f8e9f8b540db4261d47a63e279950f26e590f7bd8a2178fd7983fef3da653d811b07058b1eb416debb0566085406773d6ade8f26c3200fcbedbe55ec731133b78cc8d437fa3582b9d24f6a50e1bfd9fb6e2c82fa8f58846a77b8c8fd6ca1cd4a9fd0a07e8d4c7c7108b2a96b14212382d8be6bd67f7ebd94a15f50600dc47d61",
        ));
        let plaintext = decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(
            plaintext,
            from_hex("676d73736c20696e7465726f7020616e63686f723a2047656e6572616c5a697020534d3220e9aa8ce8af81e59091e9878f")
        );
    }
}

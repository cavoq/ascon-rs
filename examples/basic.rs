use ascon::{Aead128, Cxof128, Hash256};

fn main() -> Result<(), ascon::Error> {
    // Demonstration values only. Provision a secret key and a fresh nonce in use.
    let cipher = Aead128::new(&[0x42; 16]);
    let nonce = [0x01; 16];
    let mut message = *b"Hello from Rust";
    let tag = cipher.encrypt_in_place(&nonce, b"example", &mut message);
    println!("Ciphertext: {message:02x?}\nTag: {tag:02x?}");
    cipher.decrypt_in_place(&nonce, b"example", &mut message, &tag)?;
    assert_eq!(&message, b"Hello from Rust");

    let mut hash = Hash256::new();
    hash.update(b"Hello ");
    hash.update(b"from Rust");
    println!("Hash: {:02x?}", hash.finalize());

    let mut cxof = Cxof128::new(b"example protocol v1")?;
    cxof.update(&message);
    let mut reader = cxof.finalize();
    let mut output = [0; 48];
    reader.read(&mut output[..17]);
    reader.read(&mut output[17..]);
    println!("CXOF: {output:02x?}");
    Ok(())
}

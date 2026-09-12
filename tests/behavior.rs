use ascon::{cxof128, hash256, xof128, Aead128, Cxof128, Error, Hash256, Xof128};

#[test]
fn authentication_failure_never_changes_output() {
    let key = [0x42; 16];
    let nonce = [0x23; 16];
    let cipher = Aead128::new(&key);
    for len in [0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 255, 1024] {
        let mut ciphertext = vec![0x55; len];
        let tag = cipher.encrypt_in_place(&nonce, b"associated data", &mut ciphertext);
        // Corrupt every bit of the tag, and each key/nonce/AD/ciphertext byte.
        for kind in 0..5 {
            let count = match kind {
                0 => 128,
                1 | 2 => 16,
                3 => 15,
                _ => len,
            };
            for i in 0..count {
                let (mut k, mut n, mut t) = (key, nonce, tag);
                let mut ad = *b"associated data";
                let mut ct = ciphertext.clone();
                match kind {
                    0 => t[i / 8] ^= 1 << (i % 8),
                    1 => k[i] ^= 1,
                    2 => n[i] ^= 1,
                    3 => ad[i] ^= 1,
                    _ => ct[i] ^= 1,
                }
                let c = Aead128::new(&k);
                let mut out = vec![0xaa; len];
                assert_eq!(
                    c.decrypt(&n, &ad, &ct, &t, &mut out),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(out, vec![0xaa; len]);
                let before = ct.clone();
                assert_eq!(
                    c.decrypt_in_place(&n, &ad, &mut ct, &t),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(ct, before);
            }
        }
    }
}

#[test]
fn invalid_lengths_leave_output_unchanged() {
    let c = Aead128::new(&[0; 16]);
    let mut out = [0xab; 2];
    assert_eq!(
        c.encrypt(&[0; 16], &[], &[0], &mut out),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        c.decrypt(&[0; 16], &[], &[0], &[0; 16], &mut out),
        Err(Error::InvalidLength)
    );
    assert_eq!(
        cxof128(b"message", &[0; 257], &mut out),
        Err(Error::CustomizationTooLong)
    );
    assert_eq!(out, [0xab; 2]);
    assert!(Cxof128::new(&[0; 256]).is_ok());
}

#[test]
fn streaming_all_split_points_and_output_prefixes() {
    let message: Vec<_> = (0..129).collect();
    let customization = [0x73; 256];
    let mut expected_xof = [0; 137];
    let mut expected_cxof = [0; 137];
    xof128(&message, &mut expected_xof);
    cxof128(&message, &customization, &mut expected_cxof).unwrap();
    for split in 0..=message.len() {
        let mut h = Hash256::default();
        let mut x = Xof128::default();
        let mut c = Cxof128::new(&customization).unwrap();
        for part in [&message[..split], &[], &message[split..]] {
            h.update(part);
            x.update(part);
            c.update(part);
        }
        assert_eq!(h.finalize(), hash256(&message));
        let (mut x, mut c) = (x.finalize(), c.finalize());
        let (mut actual_x, mut actual_c) = ([0; 137], [0; 137]);
        for (xb, cb) in actual_x.chunks_mut(1).zip(actual_c.chunks_mut(1)) {
            x.read(&mut []);
            c.read(&mut []);
            x.read(xb);
            c.read(cb);
        }
        assert_eq!(actual_x, expected_xof);
        assert_eq!(actual_c, expected_cxof);
    }
    for len in 0..=137 {
        let mut out = vec![0; len];
        xof128(&message, &mut out);
        assert_eq!(out, expected_xof[..len]);
        cxof128(&message, &customization, &mut out).unwrap();
        assert_eq!(out, expected_cxof[..len]);
    }
    let mut empty_custom = [0; 137];
    cxof128(&message, &[], &mut empty_custom).unwrap();
    assert_ne!(empty_custom, expected_xof);
}

use ascon::{cxof128, hash256, xof128, Aead128, Cxof128, Hash256, Xof128};
use std::collections::BTreeMap;

fn records(text: &str) -> Vec<BTreeMap<&str, Vec<u8>>> {
    text.trim()
        .split("\n\n")
        .map(|record| {
            record
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once('=')?;
                    let (name, value) = (name.trim(), value.trim());
                    if name == "Count" {
                        return None;
                    }
                    assert_eq!(value.len() % 2, 0);
                    Some((
                        name,
                        (0..value.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                            .collect(),
                    ))
                })
                .collect()
        })
        .collect()
}

#[test]
fn aead_reference_vectors() {
    let vectors = records(include_str!("vectors/aead.txt"));
    assert_eq!(vectors.len(), 1089);
    for (index, v) in vectors.iter().enumerate() {
        let cipher = Aead128::new(v["Key"].as_slice().try_into().unwrap());
        let nonce = v["Nonce"].as_slice().try_into().unwrap();
        let (pt, ad, ct) = (&v["PT"], &v["AD"], &v["CT"]);
        let (expected, tag) = ct.split_at(pt.len());
        let tag = tag.try_into().unwrap();
        let mut out = vec![0; pt.len()];
        assert_eq!(
            &cipher.encrypt(nonce, ad, pt, &mut out).unwrap(),
            tag,
            "tag vector {}",
            index + 1
        );
        assert_eq!(out, expected, "ciphertext vector {}", index + 1);
        cipher.decrypt(nonce, ad, expected, tag, &mut out).unwrap();
        assert_eq!(&out, pt);
        let actual_tag = cipher.encrypt_in_place(nonce, ad, &mut out);
        assert_eq!(&actual_tag, tag);
        assert_eq!(out, expected);
        cipher.decrypt_in_place(nonce, ad, &mut out, tag).unwrap();
        assert_eq!(&out, pt);
    }
}

#[test]
fn hash_reference_vectors() {
    let vectors = records(include_str!("vectors/hash.txt"));
    assert_eq!(vectors.len(), 1025);
    for v in vectors {
        assert_eq!(hash256(&v["Msg"]).as_slice(), v["MD"]);
        let mut hash = Hash256::new();
        for chunk in v["Msg"].chunks(7) {
            hash.update(chunk);
        }
        assert_eq!(hash.finalize().as_slice(), v["MD"]);
    }
}

#[test]
fn xof_reference_vectors() {
    let vectors = records(include_str!("vectors/xof.txt"));
    assert_eq!(vectors.len(), 1025);
    for v in vectors {
        let mut out = vec![0; v["MD"].len()];
        xof128(&v["Msg"], &mut out);
        assert_eq!(out, v["MD"]);
        let mut xof = Xof128::new();
        for chunk in v["Msg"].chunks(9) {
            xof.update(chunk);
        }
        let mut reader = xof.finalize();
        for chunk in out.chunks_mut(3) {
            reader.read(chunk);
        }
        assert_eq!(out, v["MD"]);
    }
}

#[test]
fn cxof_reference_vectors() {
    let vectors = records(include_str!("vectors/cxof.txt"));
    assert_eq!(vectors.len(), 1089);
    for v in vectors {
        let mut out = vec![0; v["MD"].len()];
        cxof128(&v["Msg"], &v["Z"], &mut out).unwrap();
        assert_eq!(out, v["MD"]);
        let mut xof = Cxof128::new(&v["Z"]).unwrap();
        for chunk in v["Msg"].chunks(5) {
            xof.update(chunk);
        }
        let mut reader = xof.finalize();
        for chunk in out.chunks_mut(11) {
            reader.read(chunk);
        }
        assert_eq!(out, v["MD"]);
    }
}

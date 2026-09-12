//! Byte-aligned examples published by NIST's ACVP server.
//! See vectors/NIST-ACVP.md for the pinned source and selection criteria.

use ascon::{cxof128, hash256, xof128, Cxof128, Hash256, Xof128, XofReader};
use std::collections::BTreeMap;

struct Vector {
    id: String,
    message: Vec<u8>,
    customization: Vec<u8>,
    digest: Vec<u8>,
}

fn decode(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors(mode: &str, count: usize) -> Vec<Vector> {
    let selected: Vec<_> = include_str!("vectors/nist-acvp.txt")
        .trim()
        .split("\n\n")
        .map(|record| {
            record
                .lines()
                .map(|line| {
                    let (name, value) = line.split_once('=').unwrap();
                    (name.trim(), value.trim())
                })
                .collect::<BTreeMap<_, _>>()
        })
        .filter(|fields| fields["Mode"] == mode)
        .map(|fields| Vector {
            id: format!("{mode} tgId={} tcId={}", fields["TgId"], fields["TcId"]),
            message: decode(fields["Msg"]),
            customization: decode(fields.get("Z").copied().unwrap_or("")),
            digest: decode(fields["MD"]),
        })
        .collect();
    assert_eq!(selected.len(), count, "{mode} fixture count");
    selected
}

fn read_in_chunks(mut reader: XofReader, len: usize) -> Vec<u8> {
    let mut output = vec![0; len];
    for chunk in output.chunks_mut(9) {
        reader.read(&mut []);
        reader.read(chunk);
    }
    output
}

#[test]
fn nist_hash256_examples() {
    for vector in vectors("Hash256", 12) {
        assert_eq!(
            hash256(&vector.message).as_slice(),
            vector.digest,
            "{} one-shot",
            vector.id
        );
        let mut hash = Hash256::new();
        for chunk in vector.message.chunks(7) {
            hash.update(&[]);
            hash.update(chunk);
        }
        assert_eq!(
            hash.finalize().as_slice(),
            vector.digest,
            "{} streaming",
            vector.id
        );
    }
}

#[test]
fn nist_xof128_examples() {
    for vector in vectors("XOF128", 3) {
        let mut output = vec![0; vector.digest.len()];
        xof128(&vector.message, &mut output);
        assert_eq!(output, vector.digest, "{} one-shot", vector.id);

        let mut xof = Xof128::new();
        for chunk in vector.message.chunks(7) {
            xof.update(&[]);
            xof.update(chunk);
        }
        assert_eq!(
            read_in_chunks(xof.finalize(), vector.digest.len()),
            vector.digest,
            "{} streaming",
            vector.id
        );
    }
}

#[test]
fn nist_cxof128_examples() {
    for vector in vectors("CXOF128", 1) {
        let mut output = vec![0; vector.digest.len()];
        cxof128(&vector.message, &vector.customization, &mut output).unwrap();
        assert_eq!(output, vector.digest, "{} one-shot", vector.id);

        let mut xof = Cxof128::new(&vector.customization).unwrap();
        for chunk in vector.message.chunks(7) {
            xof.update(&[]);
            xof.update(chunk);
        }
        assert_eq!(
            read_in_chunks(xof.finalize(), vector.digest.len()),
            vector.digest,
            "{} streaming",
            vector.id
        );
    }
}

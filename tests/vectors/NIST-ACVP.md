# NIST ACVP examples

`nist-acvp.txt` contains all directly supported, byte-aligned examples from
NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) sample vectors at
commit [`975de31eb83d87039ec88934fdc47d8c312b892d`](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d),
retrieved on 2026-09-12. The source identifies the algorithm as `Ascon` and the
revision as `SP800-232`.

The files are `internalProjection.json` under
`gen-val/json-files/Ascon-{Mode}-SP800-232/`. These projections contain both
inputs and the expected results. The test outputs were copied from NIST,
without computing them using this library or the Ascon C implementation.

| Mode | Group ID | Case IDs | Cases |
| --- | --- | --- | ---: |
| Hash256 | 1 | 1, 2, 10, 16, 17, 26, 30, 43, 45, 49, 52, 60 | 12 |
| XOF128 | 1 | 19, 39, 56 | 3 |
| CXOF128 | 1 | 5 | 1 |

Selection is mechanical: the message bit length (`len`), output bit length
(`outLen`, or 256 for Hash256), and customization bit length (`csLen`, or zero
when absent) must each be divisible by eight. Every matching example is
included. The source `msg`, `md`, and `cs` hexadecimal strings are copied
unchanged to `Msg`, `MD`, and `Z`; `tgId` and `tcId` identify the original case.
No partial-byte inputs are rounded, truncated, or padded to make them fit.

The selected hash inputs include 0, 1, 2, 4, 8, 16, and 8192-byte messages. XOF
outputs range from 2 to 7799 bytes. The CXOF case uses a 2489-byte message,
12-byte customization, and 2416-byte output. Tests exercise both one-shot and
incremental interfaces, including reads and writes crossing the 8-byte rate.

The AEAD file was also checked. It contains **no** examples combining
byte-aligned plaintext/ciphertext and associated data, a full 128-bit tag, and
disabled nonce masking, so no AEAD cases from that file are included. The
sample also has no directly supported CXOF case with 256-byte customization.
AEAD and maximum customization remain covered by the separately documented
Ascon-team known-answer vectors and C-reference differential tests. The latter
exercise the maximum customization length; the vendored Ascon-team CXOF
vectors cover customization lengths from 0 through 32 bytes.

These are published conformance examples, not a NIST validation or security
certification. The implementation's byte-oriented API intentionally excludes
non-byte-aligned inputs, truncated AEAD tags, and the optional nonce-masking
mode.

SHA-256 hashes of the original downloaded files:

| Mode | SHA-256 |
| --- | --- |
| AEAD128 | `0c5baffbab9000cd2329c1a2670f4d480e4e184c52e49f9c785f9baebeb15b1b` |
| Hash256 | `643274a80f256c517c2fbb34fca4eda13b6526d48f6f9387ad22ae6a515d0136` |
| XOF128 | `66efeb34ae67c8ea01ef2fade03d9c61c3fc46a4a5c0a75cb5bb11627e66a983` |
| CXOF128 | `a387c6d9254a312a32c7bd23a23db68ec14fd1d8fe1d2854d07977642bd13db6` |

The SHA-256 hash of `nist-acvp.txt` is
`0ab724931f16923eab8c06a862c6e56f562bf33b9b8066268fa7412d8abca16c`.

Run with `cargo test --locked -p ascon-rs --test nist_acvp`.

#!/usr/bin/env python3
"""Differential tests against a pinned checkout of the Ascon team's C reference.

Usage: python3 scripts/test-reference.py /path/to/ascon-c
Requires Python 3, cc, and Linux. Builds only inside a temporary directory.
"""

import ctypes as c
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
REFERENCE_COMMIT = "446347f21b209f3921c65ece70027c366cbe1693"


def bind(lib, name, signature):
    fn = getattr(lib, name)
    fn.argtypes = signature
    fn.restype = c.c_int32
    return fn


def main():
    reference = Path(sys.argv[1]).resolve()
    commit = subprocess.check_output(
        ["git", "-C", str(reference), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != REFERENCE_COMMIT:
        raise SystemExit(f"Expected reference commit {REFERENCE_COMMIT}, got {commit}")
    vectors = {
        "aead.txt": "crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt",
        "hash.txt": "crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt",
        "xof.txt": "crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt",
        "cxof.txt": "crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt",
    }
    for local, upstream in vectors.items():
        if (ROOT / "tests/vectors" / local).read_bytes() != (reference / upstream).read_bytes():
            raise SystemExit(f"Vendored vector file {local} differs from {REFERENCE_COMMIT}")
    subprocess.run(["cargo", "build", "-p", "ascon-ffi", "--release", "--locked"], cwd=ROOT, check=True)
    p, n, u = c.c_void_p, c.c_size_t, c.c_ulonglong
    rust = c.CDLL(str(ROOT / "target/release/libascon_ffi.so"))
    enc = bind(rust, "ascon_aead128_encrypt", [p, p, p, n, p, n, p, n, p])
    dec = bind(rust, "ascon_aead128_decrypt", [p, p, p, n, p, n, p, p, n])
    hash_fn = bind(rust, "ascon_hash256", [p, n, p])
    xof_fn = bind(rust, "ascon_xof128", [p, n, p, n])
    cxof_fn = bind(rust, "ascon_cxof128", [p, n, p, n, p, n])
    rng = random.Random(232)
    data = lambda length: bytes(rng.randrange(256) for _ in range(length))
    buffer = lambda length: c.create_string_buffer(max(1, length))

    with tempfile.TemporaryDirectory(prefix="ascon-differential-") as work:
        libs = {}
        for family, algorithm in [("aead", "asconaead128"), ("hash", "asconhash256"), ("hash", "asconxof128"), ("cxof", "asconcxof128")]:
            source = reference / f"crypto_{family}" / algorithm / "ref"
            library = Path(work) / f"{algorithm}.so"
            subprocess.run(["cc", "-shared", "-fPIC", "-O2", f"-I{source}", f"-I{reference / 'tests'}",
                            *map(str, source.glob("*.c")), "-o", str(library)], check=True)
            libs[algorithm] = c.CDLL(str(library))
        ref_enc = bind(libs["asconaead128"], "crypto_aead_encrypt", [p, c.POINTER(u), p, u, p, u, p, p, p])
        ref_hash = bind(libs["asconhash256"], "crypto_hash", [p, p, u])
        ref_xof = bind(libs["asconxof128"], "crypto_hash", [p, p, u])
        ref_cxof = bind(libs["asconcxof128"], "crypto_cxof", [p, u, p, u, p, u])
        lengths = [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1024, 4096]
        for index in range(128):
            length = lengths[index] if index < len(lengths) else rng.randrange(4097)
            message, ad = data(length), data(rng.randrange(257))
            key, nonce = data(16), data(16)
            expected, actual, tag, plain = buffer(length + 16), buffer(length), buffer(16), buffer(length)
            written = u()
            assert ref_enc(expected, c.byref(written), message, length, ad, len(ad), None, nonce, key) == 0
            assert written.value == length + 16
            assert enc(key, nonce, ad, len(ad), message, length, actual, length, tag) == 0
            assert actual.raw[:length] + tag.raw == expected.raw
            assert dec(key, nonce, ad, len(ad), actual, length, tag, plain, length) == 0
            assert plain.raw[:length] == message
            expected, actual = buffer(64), buffer(64)
            assert ref_hash(expected, message, length) == 0
            assert hash_fn(message, length, actual) == 0
            assert actual.raw[:32] == expected.raw[:32]
            assert ref_xof(expected, message, length) == 0
            assert xof_fn(message, length, actual, 64) == 0
            assert actual.raw == expected.raw
            custom = data([0, 1, 7, 8, 9, 255, 256][index % 7])
            out_len = [1, 7, 8, 9, 63, 64, 65, 137, 1024][index % 9]
            expected, actual = buffer(out_len), buffer(out_len)
            assert ref_cxof(expected, out_len, message, length, custom, len(custom)) == 0
            assert cxof_fn(message, length, custom, len(custom), actual, out_len) == 0
            assert actual.raw == expected.raw
    print("512 differential cases passed (128 per algorithm, including 256-byte customization).")


if __name__ == "__main__":
    main()

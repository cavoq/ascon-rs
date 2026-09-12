These four complete known-answer test files are copied unchanged from
https://github.com/ascon/ascon-c at commit
`446347f21b209f3921c65ece70027c366cbe1693` (CC0; see LICENSE-CC0).

| Local file | Upstream path | Cases |
| --- | --- | ---: |
| aead.txt | crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt | 1089 |
| hash.txt | crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt | 1025 |
| xof.txt | crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt | 1025 |
| cxof.txt | crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt | 1089 |

They target the standardized little-endian SP 800-232 algorithms, not Ascon v1.2.
Tests run offline after Cargo dependencies have been fetched.

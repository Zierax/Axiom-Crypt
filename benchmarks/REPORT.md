# AXIOM-CRYPT Benchmark Report
> Generated: 2026-05-05 08:55:52

## Encryption Time

![Encryption Time](enc_time.png)

## Size Overhead

![Size Overhead](size_overhead.png)

## Security Feature Radar

![Security Radar](radar.png)

## KDF Strength (GPU Attacker)

![KDF Strength](kdf_strength.png)

## Longevity vs Quantum Threat

![Threat Timeline](threat_timeline.png)

## Raw Results

| Tool | File Size | Enc Time | Dec Time | CT Overhead |
|------|-----------|----------|----------|-------------|
| AXIOM-CRYPT v3 | 1 KB | 0.655s | 0.402s | +6.3 KB (626.6%) |
| OpenSSL AES-256-GCM | 1 KB | 0.253s | 0.289s | +0.0 KB (3.1%) |
| OpenSSL AES-256-CBC | 1 KB | 0.335s | 0.398s | +0.0 KB (3.1%) |
| GPG AES-256 | 1 KB | 0.354s | 0.122s | +-0.9 KB (-87.5%) |
| AXIOM-CRYPT v3 | 10 KB | 1.059s | 0.516s | +60.3 KB (602.7%) |
| OpenSSL AES-256-GCM | 10 KB | 0.315s | 0.312s | +0.0 KB (0.3%) |
| OpenSSL AES-256-CBC | 10 KB | 0.215s | 0.219s | +0.0 KB (0.3%) |
| GPG AES-256 | 10 KB | 0.012s | 0.010s | +-9.8 KB (-98.2%) |
| AXIOM-CRYPT v3 | 100 KB | 0.456s | 0.398s | +600.3 KB (600.3%) |
| OpenSSL AES-256-GCM | 100 KB | 0.256s | 0.465s | +0.0 KB (0.0%) |
| OpenSSL AES-256-CBC | 100 KB | 0.249s | 0.190s | +0.0 KB (0.0%) |
| GPG AES-256 | 100 KB | 0.011s | 0.013s | +-99.6 KB (-99.6%) |
| AXIOM-CRYPT v3 | 1 MB | 0.435s | 0.338s | +6144.3 KB (600.0%) |
| OpenSSL AES-256-GCM | 1 MB | 0.207s | 0.205s | +0.0 KB (0.0%) |
| OpenSSL AES-256-CBC | 1 MB | 0.298s | 0.281s | +0.0 KB (0.0%) |
| GPG AES-256 | 1 MB | 0.062s | 0.029s | +-1021.4 KB (-99.7%) |

## Notes

- AXIOM-CRYPT encryption time is dominated by Argon2id (64 MB, 3 iterations).
  This is **intentional** — it equalises GPU and CPU attacker cost.
- Size overhead includes chaff packets (indistinguishable dummy ciphertexts).
- All times averaged over multiple runs where applicable.
- Security radar scores are qualitative assessments, not formal proofs.

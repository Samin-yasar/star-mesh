# Security Policy

## Reporting Security Vulnerabilities

Star-Mesh is a research prototype and protocol specification intended for cryptographic and systems research, protocol analysis, and implementation experimentation. If you discover a security vulnerability in this repository, please **do not** open a public GitHub issue. Instead, follow these responsible disclosure guidelines.

For a broader statement of scope, limitations, and implementation guidance, see [DISCLAIMER.md](DISCLAIMER.md).

### Reporting Process

Use the repository's private vulnerability reporting flow on GitHub:

1. **Preferred channel**: Submit a report via GitHub Security Advisories for this repository:
   https://github.com/Samin-yasar/star-mesh/security/advisories/new

2. Include the following in your report:
   - Description of the vulnerability
   - Affected component(s) and version(s)
   - Steps to reproduce (if applicable)
   - Potential impact assessment
   - Suggested fix (if available)

3. **Timeline**:
   - Initial response: Within 48 hours
   - Security assessment: Within 1 week
   - Patch development: 2–4 weeks (depending on severity)
   - Coordinated disclosure: After patch release

4. **Eligibility**:
   - Vulnerabilities in cryptographic implementations
   - Issues affecting Forward Secrecy (FS) or Post-Compromise Security (PCS)
   - Incorrect FIPS 203 / RFC 7748 / RFC 5869 implementations
   - Secret key material exposure or leakage

> If private reporting is unavailable in the repository settings, the maintainer should enable GitHub's private security advisories before publishing this policy as the canonical disclosure path.

### Out of Scope

The following are **not** considered security vulnerabilities for the purposes of this repository:
- Denial of Service (DoS) in the prototype implementation, unless it reflects a realistic deployment issue
- Social engineering or user credential compromise
- Network infrastructure attacks (DNS hijacking, BGP hijacking)
- Research hypotheticals that do not affect the current protocol design or implementation
- Documentation or configuration errors unrelated to the protocol or code path

## Security Guarantees

These claims describe the properties evaluated in the current prototype and protocol model. They are not guarantees for a production deployment without additional hardening, authentication, and operational controls.

### What Star-Mesh Provides

✅ **Forward Secrecy (FS)**
- Compromise of long-term keys does not reveal past session keys
- Achieved via ephemeral DH and symmetric ratchet (§3.3.1, paper)
- Validated by test: `test_forward_secrecy_via_ratchet`

✅ **Post-Compromise Security (PCS)**
- Compromise of session state is recovered after PQ ratchet step
- One-time ML-KEM key ensures ephemeral secret not recoverable
- Validated by test: `test_pcs_via_secret_erasure`

✅ **Hybrid Post-Quantum Resilience**
- Protects against passive quantum adversaries (eavesdropping)
- ML-KEM-768 (FIPS 203) provides NIST Security Level 3
- Combined with classical X25519 for defense-in-depth
- Per §3.2 of protocol paper

✅ **Transcript Binding**
- Handshake message tampering produces different session keys
- HKDF info parameter includes all parties' identities and ephemeral keys
- Validated by test: `test_transcript_binding_changes_okm`

✅ **Secret Erasure**
- Sensitive key material cleared from memory after use
- Uses `zeroize` crate for deterministic clearing
- DecapsulationKey consumed (moved) after one-time use
- Validated by test: `test_pcs_via_secret_erasure`

### What Star-Mesh Does NOT Provide

❌ **Anonymity**
- User identities are bound to long-term keys (DSA/DH identity bundle)
- Not suitable for scenarios requiring strong anonymity

❌ **Metadata Privacy**
- Handshake message sizes (1952 B DSA keys + ML-KEM ciphertexts) leak identity hints
- DHT lookups reveal peer relationships (not encrypted)
- See research notes (docs/research-notes.md §5) for open questions

❌ **Protection Against Active Attacks**
- No authentication on handshake (DSA signatures only in future work)
- Vulnerable to MITM if pre-key bundles are not authenticated
- Requires external authentication mechanism (not in scope of v0.3.0)

❌ **Production-Ready Networking**
- PoC implementation only
- No churn handling, rate limiting, or replay protection
- See roadmap (docs/roadmap.md) for deployment hardening tasks

## Implementation Security Review

### Cryptographic Primitives

| Primitive | Standard | Implementation | Status |
|-----------|----------|-----------------|--------|
| ML-KEM-768 | FIPS 203 | `ml-kem` crate 0.3 | ✅ Audited by RustCrypto |
| X25519 | RFC 7748 | `x25519-dalek` 2.0 | ✅ Widely used, audited |
| HKDF-SHA256 | RFC 5869 | `hkdf` crate 0.12 | ✅ Standard HMAC-based |
| BLAKE3 | De facto standard | `blake3` crate 1.0 | ✅ Published algorithm |
| Zeroize | Best practice | `zeroize` crate 1.0 | ✅ Memory clearing |

### Code Quality

| Metric | Status | Details |
|--------|--------|---------|
| No unsafe code | ✅ | Except in dependencies (only stdlib + crates) |
| No panics in crypto path | ✅ | All errors return `Result<T, CryptoError>` |
| Deterministic outputs | ✅ | Validated by `test_kdf_determinism` |
| Secret key erasure | ✅ | Zeroize trait on `DecapsulationKey` |
| Constant-time ops | ⚠️ | See "Known Limitations" below |

### Test Coverage

All security claims from the protocol paper are tested:

| Claim (Paper §) | Test | Status |
|-----------------|------|--------|
| Transcript binding (3.2) | `test_transcript_binding_changes_okm` | ✅ |
| Forward secrecy (3.3.1) | `test_forward_secrecy_via_ratchet` | ✅ |
| PCS via key erasure (3.3.3) | `test_pcs_via_secret_erasure` | ✅ |
| Hybrid SS convergence (3.2) | `test_hybrid_ss_consistency` | ✅ |
| KDF determinism (3.3) | `test_kdf_determinism` | ✅ |
| Session independence (3.2) | `test_key_independence_across_sessions` | ✅ |
| Chain key progression (3.3.1) | `test_chain_key_advancement` | ✅ |
| Asymmetric convergence (3.2) | `test_asymmetric_paths_converge` | ✅ |
| ML-KEM implicit rejection (FIPS 203) | `test_mlkem_implicit_rejection` | ✅ |

## Known Limitations & Future Mitigations

### Timing Attacks
**Current**: X25519 and ML-KEM operations may not be fully constant-time in all implementations.  
**Risk**: Side-channel leakage under specific threat models (lab conditions unlikely in deployed systems).  
**Mitigation (v0.4.0)**: Audit timing behavior; consider `subtle` crate for comparison operations; profile on target hardware.

### Random Number Generation
**Current**: Uses `rand::rng()` (OS entropy source via `getrandom`).  
**Risk**: If `getrandom` is misconfigured or blocked, RNG state could be weak.  
**Mitigation**: Explicitly configure entropy source in deployment; document RNG requirements.

### One-Time Pre-Key (OTPK) Consumption
**Current**: Protocol assumes OTPK consumption is tracked externally (not modeled in PoC).  
**Risk**: If OTPK is reused across handshakes, PCS guarantee degrades.  
**Mitigation (v0.4.0)**: Implement OTPK registry and revocation mechanism.

### Metadata Leakage
**Current**: Handshake message sizes and DHT lookups are unencrypted.  
**Risk**: Adversary can infer peer relationships, identity hints from key bundle sizes.  
**Mitigation (v0.4.0)**: Implement metadata-minimized cover traffic, randomized key bundle sizes.

### No MITM Protection
**Current**: Handshake includes no authentication (DSA signatures only in design).  
**Risk**: Active attacker can inject false pre-key bundles if DHT is compromised.  
**Mitigation**: Implement DSA signature verification; use public key infrastructure (PKI) or Web-of-Trust.

### Implicit Rejection in ML-KEM
**Current**: FIPS 203 §7.3 implicit rejection is implemented (decapsulation never fails).  
**Risk**: Weak ciphertexts silently recover a pseudorandom shared secret instead of rejecting.  
**Security**: This is by design in FIPS 203; no rejection gives adversary no feedback. Matches published standard.  
**Mitigation**: None needed; follows official FIPS spec.

## Deployment Checklist

Before using Star-Mesh in production, ensure:

- [ ] RNG is properly seeded and entropy source is verified
- [ ] Pre-key bundles are authenticated (via DSA signatures or external PKI)
- [ ] OTPK consumption is tracked and revoked after use
- [ ] Handshakes are rate-limited to prevent resource exhaustion
- [ ] Session state is stored securely (encrypted, access controlled)
- [ ] Audit logging captures all key derivation events
- [ ] Disaster recovery plan includes key backup & rotation procedures
- [ ] Security assessment is performed by cryptographic review team

## Compliance & Standards

✅ **FIPS 203** — ML-KEM-768 post-quantum KEM  
✅ **RFC 7748** — Elliptic Curves for Security  
✅ **RFC 5869** — HKDF: HMAC-based Extract-and-Expand KDF  
✅ **NIST SP 800-38D** — Implicit rejection (ML-KEM)  
✅ **Zeroize trait** — Deterministic secret erasure  

Not yet compliant:
- ❌ FIPS 140-2 (hardware crypto module requirements)
- ❌ NIST SP 800-52 (TLS recommendations — not applicable)
- ❌ NIST SP 800-175B (guidelines for symmetric key management — future work)

## Security References

### Published Papers & Specs
- FIPS 203 (2024): *Module-Lattice-Based Key-Encapsulation Mechanism Standard*
- RFC 7748 (2016): *Elliptic Curves for Security*
- RFC 5869 (2010): *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*
- Double Ratchet Algorithm (Signal Protocol / Moxie Marlinspike et al.)

### Related Protocols
- Signal Protocol (Wire & WhatsApp) — classical double ratchet baseline
- NIST Post-Quantum Standardization — ML-KEM selection criteria
- MLKEM-KEM hybrid constructions — defense-in-depth principles

### Tools & Audits
- `zeroize` crate — RustCrypto endorsed for secret erasure
- `x25519-dalek` — Widely audited (Veracruz project, etc.)
- `ml-kem` crate — RustCrypto official implementation

## Contact & Support

**Security inquiries**: GitHub Security Advisories for this repository: https://github.com/Samin-yasar/star-mesh/security/advisories/new  
**General support**: [GitHub Issues](https://github.com/Samin-yasar/star-mesh/issues)  
**Bug reports**: [GitHub Issues](https://github.com/Samin-yasar/star-mesh/issues)

---

**Last Updated**: August 14, 2026  
**Version**: v0.3.0  
**Policy Review Cycle**: Annual (or upon security advisory)

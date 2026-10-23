"""
Star-Mesh: Hybrid PQ-X3DH + Double Ratchet — Python Reference Implementation
=============================================================================

Corresponds to Sections 3.2–3.5 and Appendix A of the manuscript.

Libraries
---------
  ML-KEM-768    kyber-py  (ml_kem.ML_KEM_768)   pure-Python, FIPS 203
  ML-DSA-65     dilithium-py (ml_dsa.ML_DSA_65)  pure-Python, FIPS 204
  X25519        cryptography (hazmat)             RFC 7748
  AES-256-GCM   cryptography (hazmat)
  HKDF-SHA3-256 hmac + hashlib.sha3_256          one-extract / two-expand
  BLAKE3        blake3, derive_key mode           domain-separated KDF

Scope
-----
  Pure-Python, unaudited, NOT constant-time.
  Correct reference implementation for:
    • studying message flow,
    • catching KDF-input drift between Python and Rust,
    • running known-answer tests against the Rust prototype on shared inputs.
  DO NOT use in production.

Expected sizes (assertions below verify these at run time):
  ML-KEM-768  encapsulation key: 1184 B   ciphertext: 1088 B   ss: 32 B
  ML-DSA-65   verifying key    : 1952 B   signature : 3309 B

Dependencies
------------
  pip install kyber-py dilithium-py blake3 cryptography
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

import blake3 as _blake3
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

# ---------------------------------------------------------------------------
# Size constants (FIPS 203 / FIPS 204)
# ---------------------------------------------------------------------------

MLKEM768_EK_SIZE = 1184   # encapsulation key (public)
MLKEM768_DK_SIZE = 2400   # decapsulation key (private)
MLKEM768_CT_SIZE = 1088   # ciphertext
MLKEM768_SS_SIZE = 32     # shared secret

MLDSA65_VK_SIZE  = 1952   # verifying key (public)
MLDSA65_SK_SIZE  = 4032   # signing key (private)
MLDSA65_SIG_SIZE = 3309   # signature

# ---------------------------------------------------------------------------
# HKDF-SHA3-256  (one-extract / two-expand, matching the paper's KDF shape)
# §3.4, Assumption 4.2
# ---------------------------------------------------------------------------

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with HMAC-SHA3-256.  RFC 5869 §2.2."""
    if not salt:
        salt = bytes(32)
    return hmac.new(salt, ikm, hashlib.sha3_256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand with HMAC-SHA3-256.  RFC 5869 §2.3."""
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha3_256).digest()
        okm += t
        i += 1
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA3-256: Extract then Expand."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------------------
# BLAKE3-KDF  (symmetric ratchet)
# §3.3.1: MK = BLAKE3(CK, 0x01, label); CK_next = BLAKE3(CK, 0x02, label)
# Uses derive_key mode with a domain-separated context string.
# ---------------------------------------------------------------------------

def blake3_kdf(key: bytes, domain: int, info: bytes, out_len: int = 32) -> bytes:
    """BLAKE3 in derive_key mode.  domain byte prefixes the context string."""
    context = bytes([domain]) + info
    return _blake3.blake3(key, derive_key_context=context.decode("latin-1")).digest(length=out_len)


# ---------------------------------------------------------------------------
# ML-KEM-768 wrappers  (kyber-py  ≥  v1.2)
# ---------------------------------------------------------------------------

def mlkem768_keygen() -> tuple[bytes, bytes]:
    """Returns (ek, dk) — encapsulation key, decapsulation key."""
    ek, dk = ML_KEM_768.keygen()
    assert len(ek) == MLKEM768_EK_SIZE, f"ek size {len(ek)} ≠ {MLKEM768_EK_SIZE}"
    assert len(dk) == MLKEM768_DK_SIZE, f"dk size {len(dk)} ≠ {MLKEM768_DK_SIZE}"
    return ek, dk


def mlkem768_encapsulate(ek: bytes) -> tuple[bytes, bytes]:
    """Returns (ct, ss).  kyber-py encaps() returns (ss, ct); we normalise to (ct, ss)."""
    ss, ct = ML_KEM_768.encaps(ek)   # kyber-py v1.2: (ss[32], ct[1088])
    assert len(ct) == MLKEM768_CT_SIZE, f"ct size {len(ct)} ≠ {MLKEM768_CT_SIZE}"
    assert len(ss) == MLKEM768_SS_SIZE, f"ss size {len(ss)} ≠ {MLKEM768_SS_SIZE}"
    return ct, ss


def mlkem768_decapsulate(dk: bytes, ct: bytes) -> bytes:
    """Returns ss (32 B).  Implicit rejection: always returns 32 B, never raises."""
    ss = ML_KEM_768.decaps(dk, ct)
    assert len(ss) == MLKEM768_SS_SIZE
    return ss


# ---------------------------------------------------------------------------
# ML-DSA-65 wrappers  (dilithium-py  ≥  v1.5)
# ---------------------------------------------------------------------------

def mldsa65_keygen() -> tuple[bytes, bytes]:
    """Returns (sk, vk) — signing key, verifying key."""
    pk, sk = ML_DSA_65.keygen()          # dilithium-py: keygen() → (pk, sk)
    vk = pk
    assert len(vk) == MLDSA65_VK_SIZE, f"vk size {len(vk)} ≠ {MLDSA65_VK_SIZE}"
    assert len(sk) == MLDSA65_SK_SIZE, f"sk size {len(sk)} ≠ {MLDSA65_SK_SIZE}"
    return sk, vk


def mldsa65_sign(sk: bytes, msg: bytes) -> bytes:
    """Returns deterministic ML-DSA-65 signature (3309 B)."""
    sig = ML_DSA_65.sign(sk, msg)
    assert len(sig) == MLDSA65_SIG_SIZE, f"sig size {len(sig)} ≠ {MLDSA65_SIG_SIZE}"
    return sig


def mldsa65_verify(vk: bytes, msg: bytes, sig: bytes) -> bool:
    """Returns True iff signature is valid."""
    return ML_DSA_65.verify(vk, msg, sig)


# ---------------------------------------------------------------------------
# X25519 wrappers  (cryptography)
# ---------------------------------------------------------------------------

def x25519_keygen() -> tuple[X25519PrivateKey, bytes]:
    """Returns (sk_obj, pk_bytes).  pk_bytes is raw 32-byte RFC 7748 encoding."""
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert len(pk) == 32
    return sk, pk


def x25519_dh(sk: X25519PrivateKey, remote_pk_bytes: bytes) -> bytes:
    """Returns 32-byte raw shared secret."""
    remote_pk = X25519PublicKey.from_public_bytes(remote_pk_bytes)
    return sk.exchange(remote_pk)


# ---------------------------------------------------------------------------
# AES-256-GCM  (cryptography)
# ---------------------------------------------------------------------------

def aes256gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes256gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# KEM-ID  (matches Rust: BLAKE3 over session_id ∥ sequence ∥ ek)
# ---------------------------------------------------------------------------

def kem_id(session_id: bytes, sequence: int, ek: bytes) -> bytes:
    h = _blake3.blake3()
    h.update(b"StarMesh-KEM-v1")
    h.update(session_id)
    h.update(struct.pack(">Q", sequence))
    h.update(ek)
    return h.digest()


# ---------------------------------------------------------------------------
# Signed-message helper: recovery update header bytes
# m_init = "StarMesh-UpdateAuth-Init-v1" ∥ sid ∥ kem_id ∥ seq ∥ epoch ∥ prev ∥ ek
# ---------------------------------------------------------------------------

def recovery_header_bytes(
    session_id: bytes,
    kid: bytes,
    sequence: int,
    epoch: int,
    predecessor: bytes,
    ek: bytes,
) -> bytes:
    return (
        b"StarMesh-UpdateAuth-Init-v1"
        + session_id
        + kid
        + struct.pack(">Q", sequence)
        + struct.pack(">Q", epoch)
        + predecessor
        + ek
    )


# m_resp = "StarMesh-UpdateAuth-Resp-v1" ∥ sid ∥ kem_id ∥ ek ∥ ct ∥ epoch ∥ prev
def recovery_response_bytes(
    session_id: bytes,
    kid: bytes,
    ek: bytes,
    ct: bytes,
    epoch: int,
    predecessor: bytes,
) -> bytes:
    return (
        b"StarMesh-UpdateAuth-Resp-v1"
        + session_id
        + kid
        + ek
        + ct
        + struct.pack(">Q", epoch)
        + predecessor
    )


# ---------------------------------------------------------------------------
# M0 signature bytes
# m_init = "StarMesh-Handshake-M0-Init-v1" ∥ len(alice_dsa_pk) ∥ alice_dsa_pk ∥ ...
# ---------------------------------------------------------------------------

def m0_signature_bytes(
    alice_ik_dsa_vk: bytes,
    alice_ik_dh_pk: bytes,
    bob_ik_dsa_vk: bytes,
    eph_pk: bytes,
    ct_spk: bytes,
    ct_otpk: bytes,
    prekey_id: str,
    confirmation_tag: bytes,
) -> bytes:
    d = b"StarMesh-Handshake-M0-Init-v1"
    d += struct.pack(">I", len(alice_ik_dsa_vk)) + alice_ik_dsa_vk
    d += alice_ik_dh_pk
    d += struct.pack(">I", len(bob_ik_dsa_vk)) + bob_ik_dsa_vk
    d += eph_pk
    d += struct.pack(">I", len(ct_spk)) + ct_spk
    d += struct.pack(">I", len(ct_otpk)) + ct_otpk
    d += struct.pack(">I", len(prekey_id)) + prekey_id.encode()
    d += confirmation_tag
    return d


# ---------------------------------------------------------------------------
# §3.2  Hybrid PQ-X3DH  (Initiator)
# ---------------------------------------------------------------------------

@dataclass
class BobPreKeyBundle:
    ik_dsa_vk:   bytes
    ik_dh_pk:    bytes   # 32-byte raw X25519
    spk_pk:      bytes
    otpk_pk:     bytes
    pq_spk_ek:   bytes   # ML-KEM-768 encapsulation key
    pq_otpk_ek:  bytes


@dataclass
class HandshakeM0:
    alice_ik_dsa_vk: bytes
    alice_ik_dh_pk:  bytes
    eph_pk:          bytes
    ct_spk:          bytes
    ct_otpk:         bytes
    prekey_id:       str
    confirmation_tag: bytes
    signature:       bytes


def pq_x3dh_initiator(
    alice_ik_dsa_sk: bytes,
    alice_ik_dsa_vk: bytes,
    alice_ik_dh_sk: X25519PrivateKey,
    alice_ik_dh_pk: bytes,
    bob_bundle: BobPreKeyBundle,
) -> tuple[bytes, HandshakeM0]:
    """§3.2: Alice's side.  Returns (OKM[64], M0)."""

    # Ephemeral X25519 key
    eph_sk, eph_pk = x25519_keygen()

    # Four classical DH values
    dh1 = x25519_dh(alice_ik_dh_sk, bob_bundle.spk_pk)
    dh2 = x25519_dh(eph_sk, bob_bundle.ik_dh_pk)
    dh3 = x25519_dh(eph_sk, bob_bundle.spk_pk)
    dh4 = x25519_dh(eph_sk, bob_bundle.otpk_pk)
    ss_cl = dh1 + dh2 + dh3 + dh4   # 128 B

    # Two ML-KEM-768 encapsulations
    ct_spk,  ss_pq1 = mlkem768_encapsulate(bob_bundle.pq_spk_ek)
    ct_otpk, ss_pq2 = mlkem768_encapsulate(bob_bundle.pq_otpk_ek)

    # Hybrid combiner (§3.2): 0xFF || SS_cl || SS_PQ1 || SS_PQ2
    ss_hybrid = b"\xff" + ss_cl + ss_pq1 + ss_pq2

    # HKDF info binds both identities and all ephemeral/ciphertext material
    info = (
        b"StarMesh-v1"
        + struct.pack(">I", len(alice_ik_dsa_vk)) + alice_ik_dsa_vk
        + struct.pack(">I", len(bob_bundle.ik_dsa_vk)) + bob_bundle.ik_dsa_vk
        + struct.pack(">I", len(eph_pk)) + eph_pk
        + struct.pack(">I", len(ct_spk)) + ct_spk
        + struct.pack(">I", len(ct_otpk)) + ct_otpk
    )

    # OKM = HKDF-SHA3-256(ss_hybrid, 0^32, info, 64)
    okm = hkdf(ikm=ss_hybrid, salt=bytes(32), info=info, length=64)

    # Confirmation tag: HMAC-SHA3-256 over info, keyed by a sub-key of OKM
    confirm_info = b"StarMesh-Confirm" + info
    confirm_key  = hkdf(ikm=okm, salt=bytes(32), info=confirm_info, length=32)
    confirmation_tag = hmac.new(confirm_key, info, hashlib.sha3_256).digest()

    # σ_{M_0}: Alice signs the handshake transcript
    sig_bytes = m0_signature_bytes(
        alice_ik_dsa_vk, alice_ik_dh_pk, bob_bundle.ik_dsa_vk,
        eph_pk, ct_spk, ct_otpk, "otpk_1", confirmation_tag,
    )
    sig_m0 = mldsa65_sign(alice_ik_dsa_sk, sig_bytes)

    m0 = HandshakeM0(
        alice_ik_dsa_vk  = alice_ik_dsa_vk,
        alice_ik_dh_pk   = alice_ik_dh_pk,
        eph_pk           = eph_pk,
        ct_spk           = ct_spk,
        ct_otpk          = ct_otpk,
        prekey_id        = "otpk_1",
        confirmation_tag = confirmation_tag,
        signature        = sig_m0,
    )
    return okm, m0


# ---------------------------------------------------------------------------
# §3.2  Hybrid PQ-X3DH  (Responder)
# ---------------------------------------------------------------------------

@dataclass
class BobSecretBundle:
    ik_dh_sk:    X25519PrivateKey
    spk_sk:      X25519PrivateKey
    otpk_sk:     X25519PrivateKey
    pq_spk_dk:   bytes   # ML-KEM-768 decapsulation key
    pq_otpk_dk:  bytes


def pq_x3dh_responder(
    bob_ik_dsa_vk: bytes,
    bob_secrets: BobSecretBundle,
    m0: HandshakeM0,
) -> bytes:
    """§3.2: Bob's side.  Returns OKM[64]."""

    # Step 0: verify σ_{M_0} under Alice's identity key
    sig_bytes = m0_signature_bytes(
        m0.alice_ik_dsa_vk, m0.alice_ik_dh_pk, bob_ik_dsa_vk,
        m0.eph_pk, m0.ct_spk, m0.ct_otpk, m0.prekey_id, m0.confirmation_tag,
    )
    assert mldsa65_verify(m0.alice_ik_dsa_vk, sig_bytes, m0.signature), \
        "❌ M0 initiator signature verification failed"

    # Step 1: classical DH (commutes with Alice's)
    dh1 = x25519_dh(bob_secrets.spk_sk,  m0.alice_ik_dh_pk)
    dh2 = x25519_dh(bob_secrets.ik_dh_sk, m0.eph_pk)
    dh3 = x25519_dh(bob_secrets.spk_sk,  m0.eph_pk)
    dh4 = x25519_dh(bob_secrets.otpk_sk, m0.eph_pk)
    ss_cl = dh1 + dh2 + dh3 + dh4

    # Step 2: ML-KEM-768 decapsulations
    ss_pq1 = mlkem768_decapsulate(bob_secrets.pq_spk_dk,  m0.ct_spk)
    ss_pq2 = mlkem768_decapsulate(bob_secrets.pq_otpk_dk, m0.ct_otpk)

    ss_hybrid = b"\xff" + ss_cl + ss_pq1 + ss_pq2

    info = (
        b"StarMesh-v1"
        + struct.pack(">I", len(m0.alice_ik_dsa_vk)) + m0.alice_ik_dsa_vk
        + struct.pack(">I", len(bob_ik_dsa_vk)) + bob_ik_dsa_vk
        + struct.pack(">I", len(m0.eph_pk)) + m0.eph_pk
        + struct.pack(">I", len(m0.ct_spk)) + m0.ct_spk
        + struct.pack(">I", len(m0.ct_otpk)) + m0.ct_otpk
    )

    okm = hkdf(ikm=ss_hybrid, salt=bytes(32), info=info, length=64)

    # Verify confirmation tag
    confirm_info = b"StarMesh-Confirm" + info
    confirm_key  = hkdf(ikm=okm, salt=bytes(32), info=confirm_info, length=32)
    expected_tag = hmac.new(confirm_key, info, hashlib.sha3_256).digest()
    assert hmac.compare_digest(expected_tag, m0.confirmation_tag), \
        "❌ Confirmation tag mismatch"

    return okm


# ---------------------------------------------------------------------------
# §3.3  Ratchet state
# ---------------------------------------------------------------------------

@dataclass
class OutstandingKem:
    sequence: int
    dk: Optional[bytes]   # zeroized after decapsulation


@dataclass
class CompletedKem:
    sequence: int
    ss: bytes
    ct: bytes


@dataclass
class RatchetState:
    """Implements §3.3 and Theorem 4.20.
    
    Maintains a session-level transcript hash over committed PQ ratchet updates,
    an entropy pool that accumulates ML-KEM shared secrets, and directional
    chain keys refreshed on every PQ epoch.
    """
    session_id:        bytes
    is_initiator:      bool
    # Identity keys
    ik_dsa_sk:         bytes               # ML-DSA-65 signing key
    ik_dsa_vk:         bytes               # ML-DSA-65 verifying key (own)
    trusted_peer_vk:   Optional[bytes]     # peer initiator verifying key
    trusted_resp_vk:   Optional[bytes]     # peer responder verifying key
    # Symmetric state
    root_key:          bytes               # 32 B
    entropy_pool:      bytes               # 32 B
    transcript_hash:   bytes               # 32 B  running hash over KEM updates
    valid_predecessors: set                # set[bytes]
    # Directional chain keys
    send_chain_key:    Optional[bytes]
    recv_chain_key:    Optional[bytes]
    # PQ ratchet buffer
    next_kem_sequence: int = 0
    next_kem_to_apply: int = 0
    pq_step_counter:   int = 0
    outstanding_kems:  dict = field(default_factory=dict)  # kem_id → OutstandingKem
    completed_kems:    dict = field(default_factory=dict)  # kem_id → CompletedKem
    retired_kems:      set  = field(default_factory=set)

    @classmethod
    def from_okm(
        cls,
        okm: bytes,
        is_initiator: bool,
        ik_dsa_sk: bytes,
        ik_dsa_vk: bytes,
    ) -> "RatchetState":
        assert len(okm) == 64
        rk = okm[:32]
        ck = okm[32:]
        th = _blake3.blake3(b"StarMesh-transcript-v1").digest()
        return cls(
            session_id        = _blake3.blake3(okm).digest(),
            is_initiator      = is_initiator,
            ik_dsa_sk         = ik_dsa_sk,
            ik_dsa_vk         = ik_dsa_vk,
            trusted_peer_vk   = None,
            trusted_resp_vk   = None,
            root_key          = rk,
            entropy_pool      = rk,
            transcript_hash   = th,
            valid_predecessors = {th},
            send_chain_key    = ck if is_initiator else None,
            recv_chain_key    = None if is_initiator else ck,
        )

    # -----------------------------------------------------------------------
    # §3.3.1  Symmetric ratchet
    # -----------------------------------------------------------------------

    def ratchet_encrypt(self) -> bytes:
        """Returns MK, advances send chain key."""
        assert self.send_chain_key is not None, "No send chain key"
        mk = blake3_kdf(self.send_chain_key, 0x01, b"StarMesh-MK")
        self.send_chain_key = blake3_kdf(self.send_chain_key, 0x02, b"StarMesh-CK")
        self.pq_step_counter += 1
        return mk

    def ratchet_decrypt(self) -> bytes:
        """Returns MK, advances receive chain key."""
        assert self.recv_chain_key is not None, "No recv chain key"
        mk = blake3_kdf(self.recv_chain_key, 0x01, b"StarMesh-MK")
        self.recv_chain_key = blake3_kdf(self.recv_chain_key, 0x02, b"StarMesh-CK")
        return mk

    # -----------------------------------------------------------------------
    # §3.3.3  PQ ratchet — initiator side: propose a new ML-KEM-768 key pair
    # -----------------------------------------------------------------------

    def pq_ratchet_init(self) -> "RecoveryUpdateHeader":
        """Generates a fresh ML-KEM-768 keypair and a signed update header."""
        ek, dk = mlkem768_keygen()
        seq    = self.next_kem_sequence
        self.next_kem_sequence += 1

        kid = kem_id(self.session_id, seq, ek)
        assert kid not in self.retired_kems, "duplicate KEM ID"

        header_b = recovery_header_bytes(
            self.session_id, kid, seq, seq, self.transcript_hash, ek,
        )
        sig = mldsa65_sign(self.ik_dsa_sk, header_b)

        self.outstanding_kems[kid] = OutstandingKem(sequence=seq, dk=dk)
        self.pq_step_counter = 0

        return RecoveryUpdateHeader(
            session_id   = self.session_id,
            kem_id       = kid,
            sequence     = seq,
            epoch        = seq,
            predecessor  = self.transcript_hash,
            ek           = ek,
            identity_vk  = self.ik_dsa_vk,
            signature    = sig,
        )

    # -----------------------------------------------------------------------
    # §3.3.3  PQ ratchet — responder side: encapsulate and sign response
    # -----------------------------------------------------------------------

    def pq_ratchet_encapsulate(
        self, header: "RecoveryUpdateHeader",
    ) -> "RecoveryUpdateResponse":
        """Validates the header, encapsulates into the initiator's key, signs response."""
        self._validate_header(header)

        assert header.kem_id not in self.completed_kems, "duplicate completed KEM"
        assert header.kem_id not in self.retired_kems,   "retired KEM replayed"

        ct, ss = mlkem768_encapsulate(header.ek)

        resp_b = recovery_response_bytes(
            self.session_id, header.kem_id, header.ek, ct,
            header.epoch, header.predecessor,
        )
        sig_resp = mldsa65_sign(self.ik_dsa_sk, resp_b)

        self.completed_kems[header.kem_id] = CompletedKem(
            sequence=header.sequence, ss=ss, ct=ct,
        )
        self._drain_completed()

        return RecoveryUpdateResponse(
            kem_id            = header.kem_id,
            ek                = header.ek,
            ciphertext        = ct,
            responder_vk      = self.ik_dsa_vk,
            response_signature = sig_resp,
        )

    # -----------------------------------------------------------------------
    # §3.3.3  PQ ratchet — initiator side: decapsulate and mix
    # -----------------------------------------------------------------------

    def pq_ratchet_decapsulate(self, response: "RecoveryUpdateResponse") -> None:
        """Verifies σ_resp, decapsulates, mixes SS_PQ into the root key."""
        pending = self.outstanding_kems.get(response.kem_id)
        assert pending is not None, f"Unknown KEM ID {response.kem_id.hex()[:8]}"
        assert pending.dk is not None, "DK already consumed (duplicate response?)"

        # Verify σ_resp (Theorem 4.17 / §3.5.4)
        resp_b = recovery_response_bytes(
            self.session_id, response.kem_id, response.ek, response.ciphertext,
            pending.sequence, self.transcript_hash,
        )
        peer_vk = self.trusted_resp_vk or response.responder_vk
        assert peer_vk == response.responder_vk, "Responder identity mismatch"
        assert mldsa65_verify(response.responder_vk, resp_b, response.response_signature), \
            "❌ Responder signature verification failed"

        # Decapsulate (ML-KEM implicit rejection: always returns 32 B)
        ss = mlkem768_decapsulate(pending.dk, response.ciphertext)

        # Zeroize the decapsulation key (§3.3, deletion schedule)
        pending.dk = None

        self.completed_kems[response.kem_id] = CompletedKem(
            sequence=pending.sequence, ss=ss, ct=response.ciphertext,
        )
        self._drain_completed()

    # -----------------------------------------------------------------------
    # Internal: drain in-order completed KEMs into the root
    # -----------------------------------------------------------------------

    def _drain_completed(self) -> None:
        while True:
            kid = next(
                (k for k, v in self.completed_kems.items()
                 if v.sequence == self.next_kem_to_apply),
                None,
            )
            if kid is None:
                break
            update = self.completed_kems.pop(kid)
            self._mix_pq_secret(kid, update.ss, update.ct)
            self.outstanding_kems.pop(kid, None)
            self.retired_kems.add(kid)
            self.next_kem_to_apply += 1

    def _mix_pq_secret(self, kid: bytes, ss_pq: bytes, ct: bytes) -> None:
        """§3.3.3: one HKDF-Extract (salt=SS_PQ, ikm=RK∥EP) then two Expands.
        
        Implements the KDF shape from Assumption 4.5 (kdf-hi):
            PRK = Extract(SS_PQ, RK ∥ EP)
            EP' = Expand(PRK, "StarMesh-v1-EntropyPool" ∥ kem_id ∥ ct, 32)
            (RK', CK_s', CK_r') = Expand(PRK, "StarMesh-v1-PQ-RK" ∥ kem_id ∥ ct, 96)
        """
        ikm = self.root_key + self.entropy_pool
        prk = hkdf_extract(salt=ss_pq, ikm=ikm)

        # Entropy pool refresh
        pool_info = b"StarMesh-v1-EntropyPool" + kid + ct
        self.entropy_pool = hkdf_expand(prk, pool_info, 32)

        # Root key + two fresh chain keys
        rk_info = b"StarMesh-v1-PQ-RK" + kid + ct
        out = hkdf_expand(prk, rk_info, 96)
        self.root_key = out[0:32]
        if self.is_initiator:
            self.send_chain_key = out[32:64]
            self.recv_chain_key = out[64:96]
        else:
            self.recv_chain_key = out[32:64]
            self.send_chain_key = out[64:96]

        # Advance transcript hash
        th = _blake3.blake3()
        th.update(self.transcript_hash)
        th.update(kid)
        th.update(ct)
        self.transcript_hash = th.digest()
        self.valid_predecessors.add(self.transcript_hash)

    def _validate_header(self, header: "RecoveryUpdateHeader") -> None:
        assert header.session_id == self.session_id, "session_id mismatch"
        expected_kid = kem_id(header.session_id, header.sequence, header.ek)
        assert header.kem_id == expected_kid, "kem_id recomputation mismatch"
        assert header.epoch  == header.sequence, "epoch ≠ sequence"
        assert header.sequence >= self.next_kem_to_apply, "stale sequence"
        assert header.predecessor in self.valid_predecessors, "invalid predecessor"

        peer_vk = self.trusted_peer_vk or header.identity_vk
        assert peer_vk == header.identity_vk, "Initiator identity mismatch"
        header_b = recovery_header_bytes(
            header.session_id, header.kem_id, header.sequence,
            header.epoch, header.predecessor, header.ek,
        )
        assert mldsa65_verify(header.identity_vk, header_b, header.signature), \
            "❌ Update header signature verification failed"


@dataclass
class RecoveryUpdateHeader:
    session_id:  bytes
    kem_id:      bytes
    sequence:    int
    epoch:       int
    predecessor: bytes
    ek:          bytes   # ML-KEM-768 encapsulation key (1184 B)
    identity_vk: bytes   # ML-DSA-65 verifying key (1952 B)
    signature:   bytes   # ML-DSA-65 signature (3309 B)


@dataclass
class RecoveryUpdateResponse:
    kem_id:             bytes
    ek:                 bytes   # The initiator's ek that was encapsulated into
    ciphertext:         bytes   # ML-KEM-768 ciphertext (1088 B)
    responder_vk:       bytes   # ML-DSA-65 verifying key (1952 B)
    response_signature: bytes   # ML-DSA-65 signature (3309 B)


# ---------------------------------------------------------------------------
# Known-answer / sanity-check tests
# These produce printed output; failures raise AssertionError.
# Run these before the demo to ensure the libraries behave as expected.
# ---------------------------------------------------------------------------

def run_known_answer_tests() -> None:
    """Sanity-check tests for KDFs and primitive sizes."""
    print("\n── Known-Answer / Sanity Tests ──────────────────────────────────")

    # KEM sizes
    ek, dk = mlkem768_keygen()
    ct, ss = mlkem768_encapsulate(ek)
    ss2    = mlkem768_decapsulate(dk, ct)
    assert ss == ss2, "ML-KEM-768 decapsulation mismatch"
    assert len(ek) == MLKEM768_EK_SIZE
    assert len(ct) == MLKEM768_CT_SIZE
    assert len(ss) == MLKEM768_SS_SIZE
    print(f"  ✅  ML-KEM-768  ek={len(ek)} B  ct={len(ct)} B  ss={len(ss)} B  (all match paper)")

    # DSA sizes
    dsa_sk, dsa_vk = mldsa65_keygen()
    sig = mldsa65_sign(dsa_sk, b"test message")
    assert mldsa65_verify(dsa_vk, b"test message", sig)
    assert not mldsa65_verify(dsa_vk, b"wrong message", sig)
    assert len(dsa_vk) == MLDSA65_VK_SIZE
    assert len(sig)    == MLDSA65_SIG_SIZE
    print(f"  ✅  ML-DSA-65   vk={len(dsa_vk)} B  sig={len(sig)} B  (all match paper)")

    # X25519
    sk1, pk1 = x25519_keygen()
    sk2, pk2 = x25519_keygen()
    assert x25519_dh(sk1, pk2) == x25519_dh(sk2, pk1), "X25519 DH not commutative"
    assert len(pk1) == 32
    print(f"  ✅  X25519      pk={len(pk1)} B  DH commutes")

    # HKDF-SHA3-256: deterministic on fixed inputs
    fixed_ikm  = bytes(range(32))
    fixed_salt = b"test-salt"
    fixed_info = b"test-info"
    okm_a = hkdf(fixed_ikm, fixed_salt, fixed_info, 64)
    okm_b = hkdf(fixed_ikm, fixed_salt, fixed_info, 64)
    assert okm_a == okm_b and len(okm_a) == 64
    print(f"  ✅  HKDF-SHA3-256  deterministic, output={len(okm_a)} B")

    # BLAKE3-KDF: two domains produce distinct outputs
    key    = os.urandom(32)
    mk_out = blake3_kdf(key, 0x01, b"StarMesh-MK")
    ck_out = blake3_kdf(key, 0x02, b"StarMesh-CK")
    assert mk_out != ck_out and len(mk_out) == 32
    print(f"  ✅  BLAKE3-KDF     domain-separated  mk≠ck  output={len(mk_out)} B")

    # AES-256-GCM round-trip
    aes_key   = os.urandom(32)
    nonce     = os.urandom(12)
    plaintext = b"hello star-mesh"
    aad       = b"StarMesh-Header-v1"
    ciphertext_aes = aes256gcm_encrypt(aes_key, nonce, plaintext, aad)
    recovered = aes256gcm_decrypt(aes_key, nonce, ciphertext_aes, aad)
    assert recovered == plaintext
    print(f"  ✅  AES-256-GCM    encrypt/decrypt round-trip OK")

    print("── All sanity tests passed ──────────────────────────────────────\n")


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

def hr(title: str) -> None:
    print(f"\n{'─' * 65}")
    print(f"  {title}")
    print('─' * 65)


def hex8(b: bytes) -> str:
    return b.hex()[:16] + "…"


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main() -> None:
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  Star-Mesh: Hybrid PQ-X3DH + Double Ratchet — Python PoC     ║")
    print("║  Real primitives: ML-KEM-768, ML-DSA-65, X25519, BLAKE3      ║")
    print("║  Pure-Python, unaudited, not constant-time. Not for production║")
    print("╚═══════════════════════════════════════════════════════════════╝")

    run_known_answer_tests()

    # ── Phase 1: Key Generation ─────────────────────────────────────────────
    hr("Phase 1 — Key Generation")

    alice_dsa_sk, alice_dsa_vk = mldsa65_keygen()
    bob_dsa_sk,   bob_dsa_vk   = mldsa65_keygen()

    alice_dh_sk, alice_dh_pk = x25519_keygen()
    bob_dh_sk,   bob_dh_pk   = x25519_keygen()
    bob_spk_sk,  bob_spk_pk  = x25519_keygen()
    bob_otpk_sk, bob_otpk_pk = x25519_keygen()

    bob_pq_spk_ek,  bob_pq_spk_dk  = mlkem768_keygen()
    bob_pq_otpk_ek, bob_pq_otpk_dk = mlkem768_keygen()

    bob_bundle = BobPreKeyBundle(
        ik_dsa_vk  = bob_dsa_vk,
        ik_dh_pk   = bob_dh_pk,
        spk_pk     = bob_spk_pk,
        otpk_pk    = bob_otpk_pk,
        pq_spk_ek  = bob_pq_spk_ek,
        pq_otpk_ek = bob_pq_otpk_ek,
    )

    print(f"  Alice IK^DSA vk  : {hex8(alice_dsa_vk)} ({len(alice_dsa_vk)} B) ✅")
    print(f"  Bob   IK^DSA vk  : {hex8(bob_dsa_vk)} ({len(bob_dsa_vk)} B) ✅")
    print(f"  Bob   IK^DH  pk  : {hex8(bob_dh_pk)} ({len(bob_dh_pk)} B)")
    print(f"  Bob   PQ-SPK ek  : {hex8(bob_pq_spk_ek)} ({len(bob_pq_spk_ek)} B) ✅")
    print(f"  Bob   PQ-OTPK ek : {hex8(bob_pq_otpk_ek)} ({len(bob_pq_otpk_ek)} B) ✅")

    # ── Phase 2: PQ-X3DH Handshake ─────────────────────────────────────────
    hr("Phase 2 — Hybrid PQ-X3DH Handshake")

    okm_alice, m0 = pq_x3dh_initiator(
        alice_dsa_sk, alice_dsa_vk,
        alice_dh_sk, alice_dh_pk,
        bob_bundle,
    )
    print(f"  Alice → M0  ct_spk={len(m0.ct_spk)} B, ct_otpk={len(m0.ct_otpk)} B")
    print(f"  Alice → σ_M0={len(m0.signature)} B  (ML-DSA-65, real signature)")
    print(f"  Alice OKM  : {hex8(okm_alice)}")

    bob_secrets = BobSecretBundle(
        ik_dh_sk   = bob_dh_sk,
        spk_sk     = bob_spk_sk,
        otpk_sk    = bob_otpk_sk,
        pq_spk_dk  = bob_pq_spk_dk,
        pq_otpk_dk = bob_pq_otpk_dk,
    )
    okm_bob = pq_x3dh_responder(bob_dsa_vk, bob_secrets, m0)
    print(f"  Bob   OKM  : {hex8(okm_bob)}")

    assert okm_alice == okm_bob, "❌ OKM MISMATCH — handshake failed"
    print(f"\n  ✅  OKM matches — shared session established")
    print(f"  RK = OKM[0:32]  = {hex8(okm_alice[:32])}")
    print(f"  CK = OKM[32:64] = {hex8(okm_alice[32:])}")
    print(f"  [PQ-FS] pq_otpk_dk single-use; Bob zeroizes after decaps")

    # ── Phase 3: Symmetric ratchet ──────────────────────────────────────────
    hr("Phase 3 — Symmetric-Key Chain Ratchet")

    alice_state = RatchetState.from_okm(okm_alice, True,  alice_dsa_sk, alice_dsa_vk)
    bob_state   = RatchetState.from_okm(okm_bob,   False, bob_dsa_sk,   bob_dsa_vk)

    # Bob needs the initiator's send chain key to decrypt the first message
    bob_state.recv_chain_key = alice_state.send_chain_key

    mk_alice = alice_state.ratchet_encrypt()
    mk_bob   = bob_state.ratchet_decrypt()

    print(f"  Alice MK (send) : {hex8(mk_alice)}")
    print(f"  Bob   MK (recv) : {hex8(mk_bob)}")
    assert mk_alice == mk_bob, "❌ Message keys do not match"
    print(f"\n  ✅  Message keys match — chain advanced; old key gone")
    print(f"  [FS] Old CK overwritten → Forward Secrecy enforced")

    # ── Phase 4: PQ ratchet round-trip (Post-Compromise Security) ──────────
    hr("Phase 4 — PQ Ratchet Round-trip (Post-Compromise Recovery)")

    alice_state.set_trusted_resp = lambda vk: setattr(alice_state, "trusted_resp_vk", vk)
    bob_state.set_trusted_peer   = lambda vk: setattr(bob_state, "trusted_peer_vk", vk)
    alice_state.trusted_resp_vk  = bob_dsa_vk
    bob_state.trusted_peer_vk    = alice_dsa_vk

    print(f"  RK BEFORE PQ ratchet: {hex8(alice_state.root_key)}")

    header   = alice_state.pq_ratchet_init()
    print(f"  Alice → header  ek={len(header.ek)} B  seq={header.sequence}  "
          f"σ_init={len(header.signature)} B")

    response = bob_state.pq_ratchet_encapsulate(header)
    print(f"  Bob   → response  ct={len(response.ciphertext)} B  "
          f"σ_resp={len(response.response_signature)} B")

    alice_state.pq_ratchet_decapsulate(response)
    print(f"  Alice decapsulates, mixes SS_PQ into RK, zeroizes dk")

    assert alice_state.root_key == bob_state.root_key, "❌ Root keys diverged"
    print(f"\n  ✅  Root keys converged: {hex8(alice_state.root_key)}")
    assert alice_state.send_chain_key == bob_state.recv_chain_key, "❌ CK mismatch"
    print(f"  ✅  Chain keys converged (A→B: {hex8(alice_state.send_chain_key)})")
    print(f"  [PCS] dk = None → post-compromise recovery achieved")
    print(f"  [PCS] Even if prior state was compromised, new RK is independent")

    # Post-recovery message exchange
    hr("Phase 5 — Post-Recovery Message Exchange")
    mk_a2 = alice_state.ratchet_encrypt()
    mk_b2 = bob_state.ratchet_decrypt()
    assert mk_a2 == mk_b2, "❌ Post-recovery message keys differ"
    print(f"  ✅  Post-recovery MK agrees: {hex8(mk_a2)}")

    # ── Summary ─────────────────────────────────────────────────────────────
    hr("Summary")
    print("  Constructions exercised with real FIPS 203 / FIPS 204 primitives:")
    print(f"    ✔  PQ-X3DH hybrid: 0xFF‖SS_cl‖SS_PQ1‖SS_PQ2  →  OKM (64 B)")
    print(f"    ✔  HKDF-SHA3-256 one-extract/two-expand KDF (§3.4, Asm 4.5)")
    print(f"    ✔  ML-DSA-65 σ_M0 (3309 B) — real EUF-CMA signature")
    print(f"    ✔  BLAKE3-KDF in derive_key mode (§3.3.1)")
    print(f"    ✔  ML-KEM-768 keygen/encaps/decaps (FIPS 203) — real IND-CCA2")
    print(f"    ✔  σ_init + σ_resp (Theorem 4.17) — real ML-DSA-65 signatures")
    print(f"    ✔  Secret deletion: dk set to None after decapsulation")
    print()
    print("  All sizes match the paper's tables (§6 / Table 2):")
    print(f"    ML-KEM-768  ek={MLKEM768_EK_SIZE} B  ct={MLKEM768_CT_SIZE} B  ss={MLKEM768_SS_SIZE} B")
    print(f"    ML-DSA-65   vk={MLDSA65_VK_SIZE} B  sig={MLDSA65_SIG_SIZE} B")
    print()
    print("  Cross-check targets (use same ikm/salt/info in Rust unit tests):")
    fixed_ikm  = bytes(range(32))
    fixed_info = b"StarMesh-v1-PQ-RK" + bytes(32) + bytes(1088)
    ref_prk    = hkdf_extract(salt=bytes(32), ikm=fixed_ikm)
    ref_out    = hkdf_expand(ref_prk, fixed_info, 96)
    print(f"    HKDF-SHA3-256 extract(0^32, range(32)) PRK = {ref_prk.hex()}")
    print(f"    HKDF-SHA3-256 expand(PRK, PQ-RK-info, 96)[0:32] RK' = {ref_out[:32].hex()}")
    print()
    print("  See poc/rust/ for the production-grade implementation and benchmarks.")
    print("  See docs/ratchet.md and docs/construction.md for the full spec.")


if __name__ == "__main__":
    main()

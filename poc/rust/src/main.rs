use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};
use ml_kem::{MlKem768, Encapsulate, Decapsulate};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use std::collections::HashMap;

// Typings for convenience matching the paper's specs
type Key32 = [u8; 32];
type Key64 = [u8; 64];

pub struct BobPreKeyBundle {
    pub ik_dh_pk: XPublicKey,
    pub spk_pk: XPublicKey,
    pub otpk_pk: XPublicKey,
    pub pq_spk_pk: ml_kem::PublicKey<MlKem768>,
    pub pq_otpk_pk: ml_kem::PublicKey<MlKem768>,
}

pub struct BobSecretBundle {
    pub ik_dh_sk: StaticSecret,
    pub spk_sk: StaticSecret,
    pub otpk_sk: StaticSecret,
    pub pq_spk_sk: ml_kem::PrivateKey<MlKem768>,
    pub pq_otpk_sk: ml_kem::PrivateKey<MlKem768>,
}

/// Helper to run HKDF-SHA256 (paper uses SHA3-256; interface is identical)
fn hkdf_derive(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// Helper to run BLAKE3-KDF as specified in the paper
fn blake3_kdf(key: &Key32, domain: u8, info: &[u8]) -> Key32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key);
    hasher.update(&[domain]);
    hasher.update(info);
    let mut output = [0u8; 32];
    hasher.finalize_xof().fill(&mut output);
    output
}

pub struct HandshakeMessageM0 {
    pub alice_ik_dsa_pk: Vec<u8>,
    pub alice_ik_dh_pk: XPublicKey,
    pub alice_eph_pk: XPublicKey,
    pub ct_pq1: ml_kem::Ciphertext<MlKem768>,
    pub ct_pq2: ml_kem::Ciphertext<MlKem768>,
    pub prekey_id: String,
}

/// 3.2 Hybrid PQ-X3DH Handshake (Initiator Side)
pub fn pq_x3dh_initiator(
    alice_ik_dsa_pk: &[u8],
    alice_ik_dh_sk: &StaticSecret,
    alice_ik_dh_pk: &XPublicKey,
    bob_ik_dsa_pk: &[u8],
    bob_bundle: &BobPreKeyBundle,
) -> (Key64, HandshakeMessageM0) {
    let mut rng = OsRng;

    // Step 1: Classical X3DH Component
    let alice_eph_sk = StaticSecret::random_from_rng(&mut rng);
    let alice_eph_pk = XPublicKey::from(&alice_eph_sk);

    let dh1 = alice_ik_dh_sk.diffie_hellman(&bob_bundle.spk_pk);
    let dh2 = alice_eph_sk.diffie_hellman(&bob_bundle.ik_dh_pk);
    let dh3 = alice_eph_sk.diffie_hellman(&bob_bundle.spk_pk);
    let dh4 = alice_eph_sk.diffie_hellman(&bob_bundle.otpk_pk);

    let mut ss_cl = Vec::new();
    ss_cl.extend_from_slice(dh1.as_bytes());
    ss_cl.extend_from_slice(dh2.as_bytes());
    ss_cl.extend_from_slice(dh3.as_bytes());
    ss_cl.extend_from_slice(dh4.as_bytes());

    // Step 2: Post-Quantum KEM Component
    let (ct_pq1, ss_pq1) = bob_bundle.pq_spk_pk.encapsulate(&mut rng).expect("Kyber768 Encaps 1 failed");
    let (ct_pq2, ss_pq2) = bob_bundle.pq_otpk_pk.encapsulate(&mut rng).expect("Kyber768 Encaps 2 failed");

    // Step 3: Cryptographic Binding and Secret Derivation
    let mut ss_hybrid = Vec::new();
    ss_hybrid.push(0xFF);
    ss_hybrid.extend_from_slice(&ss_cl);
    ss_hybrid.extend_from_slice(ss_pq1.as_ref());
    ss_hybrid.extend_from_slice(ss_pq2.as_ref());

    // AD binds the long-term identities with length prefixes
    let mut ad = b"StarMesh".to_vec();
    ad.extend_from_slice(&(alice_ik_dsa_pk.len() as u32).to_be_bytes());
    ad.extend_from_slice(alice_ik_dsa_pk);
    ad.extend_from_slice(&(bob_ik_dsa_pk.len() as u32).to_be_bytes());
    ad.extend_from_slice(bob_ik_dsa_pk);

    let okm_bytes = hkdf_derive(&ss_hybrid, Some(&[0u8; 32]), &ad, 64);
    let mut okm = [0u8; 64];
    okm.copy_from_slice(&okm_bytes);

    let m0 = HandshakeMessageM0 {
        alice_ik_dsa_pk: alice_ik_dsa_pk.to_vec(),
        alice_ik_dh_pk: *alice_ik_dh_pk,
        alice_eph_pk,
        ct_pq1,
        ct_pq2,
        prekey_id: "otpk_1".to_string(),
    };

    (okm, m0)
}

/// 3.2 Hybrid PQ-X3DH Handshake (Responder Side)
pub fn pq_x3dh_responder(
    bob_ik_dsa_pk: &[u8],
    bob_secrets: &BobSecretBundle,
    m0: &HandshakeMessageM0,
) -> Key64 {
    // Step 1: Classical component (commutes with Alice's calculation)
    let dh1 = bob_secrets.spk_sk.diffie_hellman(&m0.alice_ik_dh_pk);
    let dh2 = bob_secrets.ik_dh_sk.diffie_hellman(&m0.alice_eph_pk);
    let dh3 = bob_secrets.spk_sk.diffie_hellman(&m0.alice_eph_pk);
    let dh4 = bob_secrets.otpk_sk.diffie_hellman(&m0.alice_eph_pk);

    let mut ss_cl = Vec::new();
    ss_cl.extend_from_slice(dh1.as_bytes());
    ss_cl.extend_from_slice(dh2.as_bytes());
    ss_cl.extend_from_slice(dh3.as_bytes());
    ss_cl.extend_from_slice(dh4.as_bytes());

    // Step 2: Post-Quantum decapsulations
    let ss_pq1 = bob_secrets.pq_spk_sk.decapsulate(&m0.ct_pq1).expect("Kyber768 Decaps 1 failed");
    let ss_pq2 = bob_secrets.pq_otpk_sk.decapsulate(&m0.ct_pq2).expect("Kyber768 Decaps 2 failed");

    // Concatenate to reconstruct SS_hybrid
    let mut ss_hybrid = Vec::new();
    ss_hybrid.push(0xFF);
    ss_hybrid.extend_from_slice(&ss_cl);
    ss_hybrid.extend_from_slice(ss_pq1.as_ref());
    ss_hybrid.extend_from_slice(ss_pq2.as_ref());

    let mut ad = b"StarMesh".to_vec();
    ad.extend_from_slice(&(m0.alice_ik_dsa_pk.len() as u32).to_be_bytes());
    ad.extend_from_slice(&m0.alice_ik_dsa_pk);
    ad.extend_from_slice(&(bob_ik_dsa_pk.len() as u32).to_be_bytes());
    ad.extend_from_slice(bob_ik_dsa_pk);

    let okm_bytes = hkdf_derive(&ss_hybrid, Some(&[0u8; 32]), &ad, 64);
    let mut okm = [0u8; 64];
    okm.copy_from_slice(&okm_bytes);

    okm
}

/// 3.3 Ratchet State struct
pub struct RatchetState {
    pub root_key: Key32,
    pub send_chain_key: Option<Key32>,
    pub recv_chain_key: Option<Key32>,
    pub pq_sk_local: Option<ml_kem::PrivateKey<MlKem768>>,
    pub pq_pk_local: Option<ml_kem::PublicKey<MlKem768>>,
    pub pq_step_counter: u32,
    pub skipped_keys: HashMap<(Key32, u32), Key32>,
}

impl RatchetState {
    pub fn new(okm: &Key64, is_initiator: bool) -> Self {
        let root_key = {
            let mut rk = [0u8; 32];
            rk.copy_from_slice(&okm[0..32]);
            rk
        };
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&okm[32..64]);

        let send_chain_key;
        let recv_chain_key;

        if is_initiator {
            send_chain_key = Some(ck);
            recv_chain_key = None;
        } else {
            recv_chain_key = Some(ck);
            send_chain_key = None;
        }

        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            pq_sk_local: None,
            pq_pk_local: None,
            pq_step_counter: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// 3.3.1 Symmetric Ratchet sending step
    pub fn ratchet_encrypt(&mut self) -> Key32 {
        let ck = self.send_chain_key.as_mut().expect("No send chain key");
        let mk = blake3_kdf(ck, 0x01, b"StarMesh-MK");
        let next_ck = blake3_kdf(ck, 0x02, b"StarMesh-CK");
        ck.copy_from_slice(&next_ck);
        self.pq_step_counter += 1;
        mk
    }

    /// 3.3.1 Symmetric Ratchet receiving step
    pub fn ratchet_decrypt(&mut self) -> Key32 {
        let ck = self.recv_chain_key.as_mut().expect("No recv chain key");
        let mk = blake3_kdf(ck, 0x01, b"StarMesh-MK");
        let next_ck = blake3_kdf(ck, 0x02, b"StarMesh-CK");
        ck.copy_from_slice(&next_ck);
        mk
    }

    /// 3.3.3 PQ Ratchet initialization (Alice side)
    pub fn pq_ratchet_init(&mut self) -> ml_kem::PublicKey<MlKem768> {
        let mut rng = OsRng;
        let (sk, pk) = MlKem768::generate(&mut rng).expect("Kyber768 Keygen failed");
        self.pq_sk_local = Some(sk);
        self.pq_pk_local = Some(pk.clone());
        self.pq_step_counter = 0;
        pk
    }

    /// 3.3.3 PQ Ratchet encapsulation (Bob side)
    pub fn pq_ratchet_encapsulate(
        &mut self,
        remote_pq_pk: &ml_kem::PublicKey<MlKem768>,
    ) -> ml_kem::Ciphertext<MlKem768> {
        let mut rng = OsRng;
        let (ct, ss_pq) = remote_pq_pk.encapsulate(&mut rng).expect("Kyber768 Encaps failed");
        self.mix_pq_secret(ss_pq.as_ref());
        ct
    }

    /// 3.3.3 PQ Ratchet decapsulation and zeroization (Alice side)
    pub fn pq_ratchet_decapsulate(&mut self, ct: &ml_kem::Ciphertext<MlKem768>) {
        let mut sk = self.pq_sk_local.take().expect("No pending PQ secret key");
        let ss_pq = sk.decapsulate(ct).expect("Kyber768 Decaps failed");
        self.mix_pq_secret(ss_pq.as_ref());

        // Shred/zeroize the private key
        sk.zeroize();
    }

    fn mix_pq_secret(&mut self, ss_pq: &[u8]) {
        let out = hkdf_derive(ss_pq, Some(&self.root_key), b"StarMesh-PQ-RK", 64);
        self.root_key.copy_from_slice(&out[0..32]);
        self.send_chain_key = Some({
            let mut ck = [0u8; 32];
            ck.copy_from_slice(&out[32..64]);
            ck
        });
    }
}

fn hex_str(bytes: &[u8]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}...", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn hr(title: &str) {
    println!("\n{}", "─".repeat(60));
    println!("  {}", title);
    println!("{}", "─".repeat(60));
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Star-Mesh: Rust Hybrid PQ-X3DH + Double Ratchet — PoC   ║");
    println!("║  Corresponds to Sections 3.2 and 3.3 of the paper       ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    let mut rng = OsRng;

    hr("Phase 1 — Key Generation");

    let alice_ik_dsa_pk = vec![0x42u8; 1952]; // Simulated ML-DSA-65 identity public key (1952 B)
    let bob_ik_dsa_pk   = vec![0x24u8; 1952]; // Simulated ML-DSA-65 identity public key (1952 B)

    // Alice long-term Classical keys
    let alice_ik_dh_sk = StaticSecret::random_from_rng(&mut rng);
    let alice_ik_dh_pk = XPublicKey::from(&alice_ik_dh_sk);

    // Bob long-term Classical and Post-Quantum keys
    let bob_ik_dh_sk = StaticSecret::random_from_rng(&mut rng);
    let bob_ik_dh_pk = XPublicKey::from(&bob_ik_dh_sk);

    let bob_spk_sk = StaticSecret::random_from_rng(&mut rng);
    let bob_spk_pk = XPublicKey::from(&bob_spk_sk);

    let bob_otpk_sk = StaticSecret::random_from_rng(&mut rng);
    let bob_otpk_pk = XPublicKey::from(&bob_otpk_sk);

    let (bob_pq_spk_sk, bob_pq_spk_pk) = MlKem768::generate(&mut rng).unwrap();
    let (bob_pq_otpk_sk, bob_pq_otpk_pk) = MlKem768::generate(&mut rng).unwrap();

    let bob_bundle = BobPreKeyBundle {
        ik_dh_pk: bob_ik_dh_pk,
        spk_pk: bob_spk_pk,
        otpk_pk: bob_otpk_pk,
        pq_spk_pk: bob_pq_spk_pk,
        pq_otpk_pk: bob_pq_otpk_pk,
    };

    let bob_secrets = BobSecretBundle {
        ik_dh_sk: bob_ik_dh_sk,
        spk_sk: bob_spk_sk,
        otpk_sk: bob_otpk_sk,
        pq_spk_sk: bob_pq_spk_sk,
        pq_otpk_sk: bob_pq_otpk_sk,
    };

    println!("  Alice's IK (DSA) pk: {}", hex_str(&alice_ik_dsa_pk));
    println!("  Bob's IK (DSA) pk  : {}", hex_str(&bob_ik_dsa_pk));
    println!("  Bob's IK (DH) pk   : {}", hex_str(bob_bundle.ik_dh_pk.as_bytes()));
    // For ML-KEM, we can hash the public key bytes for printing
    let spk_bytes: [u8; 1184] = bob_bundle.pq_spk_pk.clone().into();
    println!("  Bob's PQ-SPK pk    : {}", hex_str(&spk_bytes));

    hr("Phase 2 — Hybrid PQ-X3DH Handshake");

    let (okm_alice, m0) = pq_x3dh_initiator(&alice_ik_dsa_pk, &alice_ik_dh_sk, &alice_ik_dh_pk, &bob_ik_dsa_pk, &bob_bundle);
    println!("  Alice computes OKM: {}", hex_str(&okm_alice));
    println!("  Transmitted M0 payload includes IK^DSA_pk,A ({} B) and IK^DH_pk,A ({} B)", m0.alice_ik_dsa_pk.len(), m0.alice_ik_dh_pk.as_bytes().len());

    let okm_bob = pq_x3dh_responder(&bob_ik_dsa_pk, &bob_secrets, &m0);
    println!("  Bob   computes OKM: {}", hex_str(&okm_bob));

    assert_eq!(okm_alice, okm_bob, "❌ OKM MISMATCH — handshake failed");
    println!("\n  ✅ OKM matches — shared session established.");
    println!("  RK  = OKM[0:32]  = {}", hex_str(&okm_alice[0..32]));
    println!("  CK  = OKM[32:64] = {}", hex_str(&okm_alice[32..64]));

    hr("Phase 3 — Symmetric-Key Chain Ratchet");

    let mut alice_state = RatchetState::new(&okm_alice, true);
    let mut bob_state = RatchetState::new(&okm_bob, false);

    // Sync Bob's recv chain to Alice's initial send chain for the demo
    bob_state.recv_chain_key = alice_state.send_chain_key;

    let mk_alice = alice_state.ratchet_encrypt();
    let mk_bob = bob_state.ratchet_decrypt();
    println!("  Alice MK (send)   : {}", hex_str(&mk_alice));
    println!("  Bob   MK (recv)   : {}", hex_str(&mk_bob));

    assert_eq!(mk_alice, mk_bob, "❌ Message keys do not match");
    println!("\n  ✅ Message keys match. Chain advanced; old key is gone.");

    hr("Phase 4 — Post-Quantum Ratchet Step (Post-Compromise Security)");

    println!("  Root key BEFORE PQ ratchet: {}", hex_str(&alice_state.root_key));
    println!("");

    let alice_pq_pk = alice_state.pq_ratchet_init();
    let alice_pq_pk_bytes: [u8; 1184] = alice_pq_pk.into();
    println!("  Alice generates ephemeral ML-KEM pk: {}", hex_str(&alice_pq_pk_bytes));

    let ct_pq = bob_state.pq_ratchet_encapsulate(&alice_pq_pk);
    let ct_pq_bytes: [u8; 1088] = ct_pq.clone().into();
    println!("  Bob encapsulates → ct: {}", hex_str(&ct_pq_bytes));

    alice_state.pq_ratchet_decapsulate(&ct_pq);
    println!("  Alice decapsulates, updates RK, zeroizes pq_sk_local.");
    println!("");

    assert_eq!(alice_state.root_key, bob_state.root_key, "❌ Root keys diverged");
    println!("  ✅ Root keys converged: {}", hex_str(&alice_state.root_key));
    println!("  [Security note] pq_sk_local = None → PCS recovery achieved.");

    hr("Summary");
    println!("  Demonstrated constructions:");
    println!("    ✔  Hybrid SS derivation:  SS_hybrid = 0xFF||SS_cl||SS_PQ1||SS_PQ2");
    println!("    ✔  HKDF binding with AD:  OKM = HKDF(SS_hybrid, 0^32, AD, 64)");
    println!("    ✔  Symmetric ratchet:     MK = BLAKE3-KDF(CK, 0x01, info)");
    println!("    ✔  PQ ratchet update:     RK,CK = HKDF(SS_PQ, RK, 'StarMesh-PQ-RK', 64)");
    println!("    ✔  Secret zeroization:    pq_sk_local cleared after decapsulation");
}

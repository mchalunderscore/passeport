//! OpenPGP detached signing + verification for the self-contained gpg CLI.
//!
//! rpgp builds and hashes the OpenPGP signature; the single raw Ed25519 op is
//! delegated to `sign_fn` — the Passeport bridge in production (the seed never
//! enters this process), or a local key in tests. This is the same delegation
//! seam rpgp uses internally: `SecretKeyTrait::create_signature`.

use std::io::Write;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use pgp::Deserializable;
use pgp::composed::cleartext::CleartextSignedMessage;
use pgp::composed::{Message, SignedPublicKey, StandaloneSignature};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{PublicKey, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize;
use pgp::types::{
    EskType, Fingerprint, KeyId, KeyVersion, Mpi, PkeskBytes, PublicKeyTrait, PublicParams,
    SecretKeyTrait, SignatureBytes,
};
use rand::{CryptoRng, Rng};

/// EdDSA over Ed25519 uses OpenPGP public-key algorithm 22 (EdDSALegacy) for a
/// v4 key, and Passeport signs with SHA-512 (hash id 10) to match real gpg.
pub const PK_ALGO_EDDSA: u8 = 22;
pub const HASH_ALGO_SHA512: u8 = 10;

/// Delegate that performs the raw Ed25519 op over an OpenPGP digest — the app
/// bridge in production, a local key in tests. Returns the 64-byte signature.
pub type SignDelegate<'a> = Box<dyn Fn(&[u8]) -> Result<Vec<u8>> + 'a>;

/// A signer holding only public key material; the raw Ed25519 operation is
/// delegated to `sign_fn`. rpgp treats it as a `SecretKeyTrait` and calls
/// `create_signature` with the OpenPGP hash digest.
pub struct RemoteSigner<'a> {
    public: PublicKey,
    sign_fn: SignDelegate<'a>,
}

impl<'a> RemoteSigner<'a> {
    pub fn new(public: PublicKey, sign_fn: SignDelegate<'a>) -> Self {
        Self { public, sign_fn }
    }
}

// PublicKeyTrait requires Debug; the boxed closure isn't Debug, so hand-roll it.
impl std::fmt::Debug for RemoteSigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

impl PublicKeyTrait for RemoteSigner<'_> {
    fn version(&self) -> KeyVersion {
        self.public.version()
    }
    fn fingerprint(&self) -> Fingerprint {
        self.public.fingerprint()
    }
    fn key_id(&self) -> KeyId {
        self.public.key_id()
    }
    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public.algorithm()
    }
    fn created_at(&self) -> &DateTime<Utc> {
        self.public.created_at()
    }
    fn expiration(&self) -> Option<u16> {
        self.public.expiration()
    }
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        self.public.verify_signature(hash, data, sig)
    }
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        self.public.encrypt(rng, plain, typ)
    }
    fn serialize_for_hashing(&self, writer: &mut impl Write) -> pgp::errors::Result<()> {
        self.public.serialize_for_hashing(writer)
    }
    fn public_params(&self) -> &PublicParams {
        self.public.public_params()
    }
}

impl SecretKeyTrait for RemoteSigner<'_> {
    type PublicKey = PublicKey;
    type Unlocked = Self;

    fn unlock<F, G, T>(&self, _pw: F, work: G) -> pgp::errors::Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> pgp::errors::Result<T>,
    {
        work(self)
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        _hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        // `data` is the OpenPGP hash digest; bare Ed25519 over it is exactly
        // what rpgp's own EdDSALegacy path and our bridge Sign op both do.
        let sig = (self.sign_fn)(data)
            .map_err(|e| pgp::errors::Error::Message(format!("bridge sign failed: {e:#}")))?;
        if sig.len() != 64 {
            return Err(pgp::errors::Error::Message(format!(
                "expected a 64-byte ed25519 signature, got {}",
                sig.len()
            )));
        }
        Ok(SignatureBytes::Mpis(vec![
            Mpi::from_slice(&sig[0..32]),
            Mpi::from_slice(&sig[32..64]),
        ]))
    }

    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }
}

/// Produce a git-acceptable ASCII-armored detached OpenPGP signature over
/// `message`. `created` is the signature creation time (hashed into the sig).
pub fn detached_sign(
    signer: &RemoteSigner,
    message: &[u8],
    created: DateTime<Utc>,
) -> Result<String> {
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::SHA2_512,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)),
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint())),
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))];

    let sig = config
        .sign(signer, String::new, message)
        .context("failed to create OpenPGP signature")?;
    StandaloneSignature::new(sig)
        .to_armored_string(None.into())
        .context("failed to armor OpenPGP signature")
}

/// Produce a cleartext-signed (`--clear-sign`) armored message over `text`. The
/// signature is delegated to the bridge via `signer`, like the detached path.
pub fn clearsign(signer: &RemoteSigner, text: &str, created: DateTime<Utc>) -> Result<String> {
    let mut config = SignatureConfig::v4(
        SignatureType::Text,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::SHA2_512,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(created)),
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint())),
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(signer.key_id()))];

    CleartextSignedMessage::new(text, config, signer, String::new)
        .context("failed to create cleartext signature")?
        .to_armored_string(None.into())
        .context("failed to armor cleartext signature")
}

/// Produce an inline-signed (`-s`, non-detached) armored OpenPGP message over
/// `data`. Signature delegated to the bridge via `signer`.
pub fn inline_sign(signer: &RemoteSigner, data: &[u8], file_name: &str) -> Result<String> {
    Message::new_literal_bytes(file_name, data)
        .sign(
            rand::thread_rng(),
            signer,
            String::new,
            HashAlgorithm::SHA2_512,
        )
        .context("failed to create inline signature")?
        .to_armored_string(None.into())
        .context("failed to armor inline signature")
}

/// Encrypt `plaintext` to our OWN OpenPGP encryption subkey (cv25519). Fully
/// public — no seed, no bridge. Returns armored or binary OpenPGP message bytes.
pub fn encrypt_to_self(
    pubkey: &SignedPublicKey,
    plaintext: &[u8],
    file_name: &str,
    armor: bool,
) -> Result<Vec<u8>> {
    let encryption_subkey = pubkey
        .public_subkeys
        .iter()
        .find(|sub| sub.key.is_encryption_key())
        .context("this identity has no encryption subkey")?;

    let encrypted = Message::new_literal_bytes(file_name, plaintext)
        .encrypt_to_keys_seipdv1(
            rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            &[&encryption_subkey.key],
        )
        .context("failed to encrypt the message")?;

    if armor {
        Ok(encrypted
            .to_armored_string(None.into())
            .context("failed to armor the encrypted message")?
            .into_bytes())
    } else {
        encrypted
            .to_bytes()
            .context("failed to serialize the encrypted message")
    }
}

/// Parse an OpenPGP message that may be ASCII-armored or binary.
pub fn parse_message(bytes: &[u8]) -> Result<Message> {
    if bytes.starts_with(b"-----BEGIN PGP") {
        Ok(Message::from_armor_single(bytes)
            .context("failed to parse the armored message")?
            .0)
    } else {
        Message::from_bytes(bytes).context("failed to parse the binary message")
    }
}

/// Outcome of verifying a detached signature against our own identity.
pub enum VerifyOutcome {
    /// The signature is from our key and verifies.
    Good {
        key_id: String,
        fingerprint: String,
        created: Option<DateTime<Utc>>,
        user_id: String,
    },
    /// The signature claims our key but the math does not check out.
    Bad { key_id: String },
    /// The signature is from some other key — unverifiable without a keyring.
    ForeignKey { key_id: String },
}

/// Verify a detached armored signature against our own public key over
/// `message`. Only our identity's signatures can be verified (no keyring); a
/// signature from any other key returns `ForeignKey` so the caller can emit the
/// gpg `ERRSIG`/`NO_PUBKEY` failure rather than a fabricated "good".
pub fn verify_detached(
    pubkey: &SignedPublicKey,
    sig_armored: &[u8],
    message: &[u8],
) -> Result<VerifyOutcome> {
    let (standalone, _) =
        StandaloneSignature::from_armor_single(sig_armored).context("failed to parse signature")?;
    let sig = &standalone.signature;

    let our_fpr = pubkey.primary_key.fingerprint();
    let our_keyid = pubkey.primary_key.key_id();
    let sig_keyid = sig.issuer().first().map(|k| hex_upper(k.as_ref()));

    let is_ours = sig
        .issuer_fingerprint()
        .first()
        .map(|f| **f == our_fpr)
        .unwrap_or(false)
        || sig
            .issuer()
            .first()
            .map(|k| **k == our_keyid)
            .unwrap_or(false);

    if !is_ours {
        return Ok(VerifyOutcome::ForeignKey {
            key_id: sig_keyid.unwrap_or_else(|| "0000000000000000".to_owned()),
        });
    }

    // The signature names our key; a verification failure is a BAD signature
    // (report it as such) rather than an operational error.
    if standalone.verify(&pubkey.primary_key, message).is_err() {
        return Ok(VerifyOutcome::Bad {
            key_id: hex_upper(our_keyid.as_ref()),
        });
    }

    let user_id = pubkey
        .details
        .users
        .first()
        .map(|u| u.id.id().to_string())
        .unwrap_or_default();

    Ok(VerifyOutcome::Good {
        key_id: hex_upper(our_keyid.as_ref()),
        fingerprint: hex_upper(our_fpr.as_bytes()),
        created: sig.created().copied(),
        user_id,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{self, SlotRole, SlotSecret};
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a RemoteSigner backed by the real seed-derived primary key, so the
    /// signing delegate mirrors what the bridge does in production.
    fn local_signer(uid: &str) -> (SignedPublicKey, [u8; 32]) {
        let pgp_seed = *identity::derive_pgp_seed(&[7u8; 32]).unwrap();
        let materials = identity::slot_materials(&pgp_seed, uid).unwrap();
        let primary_seed = match &materials
            .iter()
            .find(|m| m.role == SlotRole::Sign)
            .unwrap()
            .secret
        {
            SlotSecret::Ed25519(seed) => **seed,
            _ => panic!("primary is not ed25519"),
        };
        let signed_secret = identity::generate_signed_key(&pgp_seed, uid).unwrap();
        let public: SignedPublicKey = signed_secret.into();
        (public, primary_seed)
    }

    #[test]
    fn detached_sign_verifies_against_our_key() {
        let uid = "Passeport Test <test@example.invalid>";
        let (public, primary_seed) = local_signer(uid);
        let signer = RemoteSigner::new(
            public.primary_key.clone(),
            Box::new(move |data: &[u8]| {
                Ok(SigningKey::from_bytes(&primary_seed)
                    .sign(data)
                    .to_bytes()
                    .to_vec())
            }),
        );

        let message = b"tree 9f8c...\nauthor Passeport <p@x> 1767225600 +0000\n\nsigned commit\n";
        let created = chrono::DateTime::from_timestamp(1_767_300_000, 0).unwrap();
        let armored = detached_sign(&signer, message, created).unwrap();
        assert!(armored.contains("BEGIN PGP SIGNATURE"));

        match verify_detached(&public, armored.as_bytes(), message).unwrap() {
            VerifyOutcome::Good {
                key_id, user_id, ..
            } => {
                assert_eq!(key_id.len(), 16);
                assert!(user_id.contains("test@example.invalid"));
            }
            VerifyOutcome::Bad { .. } => panic!("our own valid signature reported bad"),
            VerifyOutcome::ForeignKey { .. } => panic!("our own signature classified foreign"),
        }
    }

    #[test]
    fn tampered_message_fails_verification() {
        let uid = "Passeport Test <test@example.invalid>";
        let (public, primary_seed) = local_signer(uid);
        let signer = RemoteSigner::new(
            public.primary_key.clone(),
            Box::new(move |data: &[u8]| {
                Ok(SigningKey::from_bytes(&primary_seed)
                    .sign(data)
                    .to_bytes()
                    .to_vec())
            }),
        );
        let armored = detached_sign(
            &signer,
            b"original payload",
            chrono::DateTime::from_timestamp(1_767_300_000, 0).unwrap(),
        )
        .unwrap();
        // Our key, wrong message → a BAD signature (reported, not an error).
        assert!(matches!(
            verify_detached(&public, armored.as_bytes(), b"tampered payload").unwrap(),
            VerifyOutcome::Bad { .. }
        ));
    }

    #[test]
    fn encrypt_then_decrypt_roundtrips() {
        let uid = "Passeport Test <test@example.invalid>";
        let pgp_seed = *crate::identity::derive_pgp_seed(&[7u8; 32]).unwrap();
        let secret = crate::identity::generate_signed_key(&pgp_seed, uid).unwrap();
        let public: SignedPublicKey = secret.clone().into();

        let plaintext = b"attack at dawn -- GNU-free";
        // Armored round-trip (the exact decrypt path run_pgp_decrypt uses).
        let armored = encrypt_to_self(&public, plaintext, "msg.txt", true).unwrap();
        assert!(String::from_utf8_lossy(&armored).contains("BEGIN PGP MESSAGE"));
        let (decrypted, _) = parse_message(&armored)
            .unwrap()
            .decrypt(String::new, &[&secret])
            .unwrap();
        assert_eq!(decrypted.get_content().unwrap().unwrap(), plaintext);

        // Binary round-trip.
        let binary = encrypt_to_self(&public, plaintext, "", false).unwrap();
        assert_ne!(binary.first(), Some(&b'-'));
        let (decrypted, _) = parse_message(&binary)
            .unwrap()
            .decrypt(String::new, &[&secret])
            .unwrap();
        assert_eq!(decrypted.get_content().unwrap().unwrap(), plaintext);
    }

    #[test]
    fn clearsign_and_inline_produce_armor() {
        let uid = "Passeport Test <test@example.invalid>";
        let (public, primary_seed) = local_signer(uid);
        let signer = RemoteSigner::new(
            public.primary_key.clone(),
            Box::new(move |d: &[u8]| {
                Ok(SigningKey::from_bytes(&primary_seed)
                    .sign(d)
                    .to_bytes()
                    .to_vec())
            }),
        );
        let created = chrono::DateTime::from_timestamp(1_767_300_000, 0).unwrap();
        assert!(
            clearsign(&signer, "hello\nworld\n", created)
                .unwrap()
                .contains("BEGIN PGP SIGNED MESSAGE")
        );
        assert!(
            inline_sign(&signer, b"inline payload", "")
                .unwrap()
                .contains("BEGIN PGP MESSAGE")
        );
    }
}

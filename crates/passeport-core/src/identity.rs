use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::TimeZone;
use hkdf::Hkdf;
use pgp::composed::KeyType;
use pgp::composed::key::{SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::types::{EcdhPublicParams, PlainSecretParams, PublicKeyTrait, PublicParams, SecretParams};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Which of the three card slots a piece of key material belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRole {
    Sign,
    Decrypt,
    Auth,
}

impl SlotRole {
    pub fn keyref(self) -> &'static str {
        match self {
            SlotRole::Sign => "OPENPGP.1",
            SlotRole::Decrypt => "OPENPGP.2",
            SlotRole::Auth => "OPENPGP.3",
        }
    }
}

/// Secret scalar for one slot. Ed25519 stores the 32-byte seed; X25519 stores
/// the clamped scalar in little-endian (dalek convention).
pub enum SlotSecret {
    Ed25519(Zeroizing<[u8; 32]>),
    X25519(Zeroizing<[u8; 32]>),
}

/// Everything the card needs about one slot: public material for recognition
/// and the secret for private operations.
pub struct SlotMaterial {
    pub role: SlotRole,
    pub fingerprint: Vec<u8>,
    /// Compressed public point, 0x40-prefixed (33 bytes).
    pub q: Vec<u8>,
    pub secret: SlotSecret,
}

/// Derive the identity and extract all three slots' material from the seed.
pub fn slot_materials(seed: &[u8; 32], user_id: &str) -> Result<Vec<SlotMaterial>> {
    let key = generate_signed_key(seed, user_id)?;

    let mut materials = Vec::with_capacity(3);
    materials.push(build_material(
        SlotRole::Sign,
        key.primary_key.fingerprint().as_bytes().to_vec(),
        key.primary_key.public_params(),
        key.primary_key.secret_params(),
    )?);

    let mut enc = None;
    let mut auth = None;
    for subkey in &key.secret_subkeys {
        match subkey.key.public_params() {
            PublicParams::ECDH(_) if enc.is_none() => enc = Some(subkey),
            PublicParams::EdDSALegacy { .. } if auth.is_none() => auth = Some(subkey),
            _ => {}
        }
    }
    let enc = enc.context("missing encryption subkey")?;
    let auth = auth.context("missing authentication subkey")?;

    materials.push(build_material(
        SlotRole::Decrypt,
        enc.key.fingerprint().as_bytes().to_vec(),
        enc.key.public_params(),
        enc.key.secret_params(),
    )?);
    materials.push(build_material(
        SlotRole::Auth,
        auth.key.fingerprint().as_bytes().to_vec(),
        auth.key.public_params(),
        auth.key.secret_params(),
    )?);

    Ok(materials)
}

fn build_material(
    role: SlotRole,
    fingerprint: Vec<u8>,
    public: &PublicParams,
    secret: &SecretParams,
) -> Result<SlotMaterial> {
    let (q, slot_secret) = match (public, secret) {
        (
            PublicParams::EdDSALegacy { q, .. },
            SecretParams::Plain(PlainSecretParams::EdDSALegacy(s)),
        ) => (
            q.as_bytes().to_vec(),
            SlotSecret::Ed25519(mpi_to_32_be(s.as_bytes())?),
        ),
        (
            PublicParams::ECDH(EcdhPublicParams::Known { p, .. }),
            SecretParams::Plain(PlainSecretParams::ECDH(s)),
        ) => {
            // OpenPGP stores the ECDH scalar big-endian; dalek wants little-endian.
            let mut le = mpi_to_32_be(s.as_bytes())?;
            le.reverse();
            (p.as_bytes().to_vec(), SlotSecret::X25519(le))
        }
        _ => bail!("unsupported key material for {:?}", role),
    };
    if q.len() != 33 || q[0] != 0x40 {
        bail!("unexpected compressed point encoding for {:?}", role);
    }
    Ok(SlotMaterial {
        role,
        fingerprint,
        q,
        secret: slot_secret,
    })
}

/// MPIs strip leading zero bytes; restore a fixed 32-byte big-endian value.
fn mpi_to_32_be(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if bytes.len() > 32 {
        bail!("scalar longer than 32 bytes");
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(out)
}

pub const HKDF_SALT: &[u8] = b"passeport-passkey-v1";
pub const PGP_INFO: &[u8] = b"passeport-pgp-v1";

/// Fixed OpenPGP creation time, part of the derivation contract.
pub const KEY_CREATION_EPOCH: i64 = 1_767_225_600; // 2026-01-01T00:00:00Z

pub fn decode_prf(encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("prf must be base64url without padding")?;
    if decoded.len() != 32 {
        bail!("prf must decode to exactly 32 bytes");
    }

    let mut prf = Zeroizing::new([0u8; 32]);
    prf.copy_from_slice(&decoded);
    Ok(prf)
}

pub fn derive_pgp_seed(prf: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), prf);
    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(PGP_INFO, output.as_mut())
        .map_err(|error| anyhow::anyhow!("failed to expand key material: {error:?}"))?;
    Ok(output)
}

fn pgp_epoch() -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::Utc
        .timestamp_opt(KEY_CREATION_EPOCH, 0)
        .single()
        .context("invalid fixed pgp timestamp")
}

pub fn generate_signed_key(seed: &[u8; 32], user_id: &str) -> Result<pgp::SignedSecretKey> {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let created = pgp_epoch()?;

    let encryption_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::ECDH(ECCCurve::Curve25519))
        .can_encrypt(true)
        .created_at(created)
        .build()
        .map_err(|error| anyhow::anyhow!("failed to build pgp encryption subkey: {error}"))?;

    let auth_subkey = SubkeyParamsBuilder::default()
        .key_type(KeyType::EdDSALegacy)
        .can_authenticate(true)
        .created_at(created)
        .build()
        .map_err(|error| anyhow::anyhow!("failed to build pgp auth subkey: {error}"))?;

    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .key_type(KeyType::EdDSALegacy)
        .can_certify(true)
        .can_sign(true)
        .created_at(created)
        .primary_user_id(user_id.to_owned())
        .subkey(encryption_subkey)
        .subkey(auth_subkey);

    let params = builder
        .build()
        .map_err(|error| anyhow::anyhow!("failed to build pgp key params: {error}"))?;
    let key = params
        .generate(&mut rng)
        .context("failed to generate pgp secret key")?;
    key.sign(&mut rng, String::new)
        .context("failed to self-sign pgp key")
}

/// Encode the 32-byte root seed as a 24-word BIP39 mnemonic for backup.
pub fn mnemonic_from_seed(seed: &[u8; 32]) -> Result<String> {
    let mnemonic = bip39::Mnemonic::from_entropy(seed).context("failed to encode mnemonic")?;
    Ok(mnemonic.to_string())
}

/// Recover the 32-byte root seed from a BIP39 mnemonic (validates checksum).
pub fn seed_from_mnemonic(phrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mnemonic = bip39::Mnemonic::parse(phrase.trim()).context("invalid recovery phrase")?;
    let (entropy, len) = mnemonic.to_entropy_array();
    if len != 32 {
        bail!("recovery phrase must encode 32 bytes (use the 24-word phrase)");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&entropy[..32]);
    Ok(seed)
}

/// Produce an armored OpenPGP revocation certificate for the primary key, so
/// the identity can be revoked even if the seed is lost. Deterministic: the
/// creation time is the fixed contract epoch.
pub fn revocation_certificate(seed: &[u8; 32], user_id: &str) -> Result<String> {
    let standalone = revocation_signature(seed, user_id)?;

    // gpg only accepts a revocation certificate via `--import` when it is
    // wrapped in a PUBLIC KEY BLOCK armor (as `gpg --gen-revoke` produces),
    // not a SIGNATURE block — so armor it explicitly with that block type.
    let mut headers = pgp::armor::Headers::new();
    headers.insert(
        "Comment".to_owned(),
        vec!["This is a revocation certificate".to_owned()],
    );
    let mut out = Vec::new();
    pgp::armor::write(
        &standalone,
        pgp::armor::BlockType::PublicKey,
        &mut out,
        Some(&headers),
        true,
    )
    .context("failed to armor revocation certificate")?;
    String::from_utf8(out).context("revocation certificate was not valid utf-8")
}

fn revocation_signature(
    seed: &[u8; 32],
    user_id: &str,
) -> Result<pgp::composed::StandaloneSignature> {
    use pgp::composed::StandaloneSignature;
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::packet::{RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::SecretKeyTrait;

    let key = generate_signed_key(seed, user_id)?;
    let primary = &key.primary_key;
    let public = primary.public_key();

    let mut config = SignatureConfig::v4(
        SignatureType::KeyRevocation,
        primary.algorithm(),
        HashAlgorithm::SHA2_256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(pgp_epoch()?)),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary.fingerprint())),
        Subpacket::regular(SubpacketData::RevocationReason(
            RevocationCode::NoReason,
            "Passeport backup revocation certificate".into(),
        )),
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(public.key_id()))];

    let signature = config
        .sign_key(primary, String::new, &public)
        .context("failed to create revocation signature")?;
    Ok(StandaloneSignature::new(signature))
}

/// Raw 32-byte Ed25519 public key of the authentication subkey.
pub fn auth_subkey_public(key: &pgp::SignedSecretKey) -> Result<[u8; 32]> {
    let auth = key
        .secret_subkeys
        .iter()
        .find(|subkey| matches!(subkey.key.public_params(), PublicParams::EdDSALegacy { .. }))
        .context("generated pgp key has no eddsa authentication subkey")?;

    let PublicParams::EdDSALegacy { q, .. } = auth.key.public_params() else {
        unreachable!("filtered on EdDSALegacy above");
    };
    // q is the compressed point: 0x40 prefix + 32-byte Ed25519 key.
    let q = q.as_bytes();
    if q.len() != 33 || q[0] != 0x40 {
        bail!("unexpected eddsa public key encoding");
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&q[1..]);
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::types::SecretKeyTrait;

    #[test]
    fn mnemonic_round_trips() {
        let seed = *derive_pgp_seed(&[7u8; 32]).unwrap();
        let phrase = mnemonic_from_seed(&seed).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let restored = seed_from_mnemonic(&phrase).unwrap();
        assert_eq!(*restored, seed);
    }

    #[test]
    fn mnemonic_matches_bip39_zero_vector() {
        // Canonical BIP39 test vector: 32 zero bytes of entropy.
        let phrase = mnemonic_from_seed(&[0u8; 32]).unwrap();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
        );
    }

    #[test]
    fn mnemonic_rejects_bad_checksum() {
        let mut phrase: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
                .split_whitespace()
                .collect();
        phrase[23] = "zoo"; // breaks the checksum word
        assert!(seed_from_mnemonic(&phrase.join(" ")).is_err());
    }

    #[test]
    fn revocation_certificate_is_valid_for_the_key() {
        let seed = *derive_pgp_seed(&[7u8; 32]).unwrap();
        let uid = "Passeport Test <test@example.invalid>";
        let armored = revocation_certificate(&seed, uid).unwrap();
        // gpg accepts revocation certs only inside a PUBLIC KEY BLOCK armor.
        assert!(armored.contains("BEGIN PGP PUBLIC KEY BLOCK"));

        // The signature must be a KeyRevocation that verifies against the
        // primary key it revokes.
        let sig = revocation_signature(&seed, uid).unwrap();
        assert_eq!(
            sig.signature.typ(),
            pgp::packet::SignatureType::KeyRevocation
        );
        let key = generate_signed_key(&seed, uid).unwrap();
        sig.signature
            .verify_key(&key.primary_key.public_key())
            .expect("revocation must verify against the primary key");
    }
}

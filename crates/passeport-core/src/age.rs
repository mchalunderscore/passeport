//! Crypto core shared by the native age CLI and `age-plugin-passeport`:
//! standard age X25519 file-key wrapping plus public/plugin key encodings.
//!
//! Encryption is self-contained (ephemeral scalar + the recipient's public
//! key). Decryption needs `scalar · ephemeral_share`, which only the seed
//! holder can compute — the plugin obtains it from the Passeport app bridge's
//! `ecdh` operation on the cv25519 encryption subkey (OPENPGP.2), Touch
//! approval-controlled. The wrap itself is byte-for-byte age's standard X25519 stanza, so
//! there is no bespoke cryptography — only a bespoke key custodian.

use anyhow::{Context, Result, bail};
use bech32::{Bech32, Hrp};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

/// Standard age X25519 recipient HRP: `age1…`.
const RECIPIENT_HRP: &str = "age";
/// Bech32 HRP for identities: `AGE-PLUGIN-PASSEPORT-1…` (uppercased on output).
const IDENTITY_HRP: &str = "age-plugin-passeport-";
/// Standard age X25519 secret-key HRP. This encoding is only constructed
/// inside the gated op process and is never returned to the CLI.
const SECRET_IDENTITY_HRP: &str = "age-secret-key-";

/// The age file key is a fixed 16 bytes.
pub const FILE_KEY_LEN: usize = 16;
/// Info string of age's X25519 stanza; reused verbatim so the wrap is standard.
const HKDF_INFO: &[u8] = b"age-encryption.org/v1/X25519";

pub fn encode_recipient(public_key: &[u8; 32]) -> Result<String> {
    let hrp = Hrp::parse(RECIPIENT_HRP).context("bad recipient hrp")?;
    bech32::encode::<Bech32>(hrp, public_key).context("failed to encode recipient")
}

pub fn encode_identity(public_key: &[u8; 32]) -> Result<String> {
    let hrp = Hrp::parse(IDENTITY_HRP).context("bad identity hrp")?;
    let lower = bech32::encode::<Bech32>(hrp, public_key).context("failed to encode identity")?;
    Ok(lower.to_uppercase())
}

/// Encode a standard age secret identity for the upstream age library. The
/// caller must keep the result confined to the short-lived gated op process.
pub fn encode_secret_identity(scalar: &[u8; 32]) -> Result<Zeroizing<String>> {
    let hrp = Hrp::parse(SECRET_IDENTITY_HRP).context("bad secret identity hrp")?;
    let encoded =
        bech32::encode::<Bech32>(hrp, scalar).context("failed to encode secret identity")?;
    Ok(Zeroizing::new(encoded.to_uppercase()))
}

pub fn decode_recipient(recipient: &str) -> Result<[u8; 32]> {
    decode_x25519(recipient, RECIPIENT_HRP)
}

pub fn decode_identity(identity: &str) -> Result<[u8; 32]> {
    // age uppercases identity strings; bech32 is case-insensitive but the
    // decoder wants a single case.
    decode_x25519(&identity.to_lowercase(), IDENTITY_HRP)
}

fn decode_x25519(encoded: &str, expected_hrp: &str) -> Result<[u8; 32]> {
    let (hrp, data) = bech32::decode(encoded).context("not valid bech32")?;
    if hrp.as_str() != expected_hrp {
        bail!("unexpected hrp: {}", hrp.as_str());
    }
    if data.len() != 32 {
        bail!("expected 32-byte key, got {}", data.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

/// Wrap `file_key` for `recipient_public`, returning the ephemeral share and
/// the AEAD body. Self-contained: no seed access required.
pub fn wrap_file_key(recipient_public: &[u8; 32], file_key: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if file_key.len() != FILE_KEY_LEN {
        bail!("file key must be {FILE_KEY_LEN} bytes");
    }
    let recipient = PublicKey::from(*recipient_public);
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let share = PublicKey::from(&ephemeral);
    let shared = Zeroizing::new(ephemeral.diffie_hellman(&recipient).to_bytes());
    if is_all_zero(shared.as_ref()) {
        bail!("x25519 produced an all-zero shared secret");
    }

    let wrap_key = derive_wrap_key(share.as_bytes(), recipient_public, shared.as_ref())?;
    let body = ChaCha20Poly1305::new((&*wrap_key).into())
        .encrypt(&[0u8; 12].into(), file_key)
        .map_err(|_| anyhow::anyhow!("failed to seal file key"))?;
    Ok((share.to_bytes(), body))
}

/// Unwrap a file key given the `shared` secret the bridge computed
/// (`scalar · ephemeral_share`) plus the stanza's share and body.
pub fn unwrap_file_key(
    recipient_public: &[u8; 32],
    ephemeral_share: &[u8; 32],
    shared: &[u8; 32],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if is_all_zero(shared) {
        bail!("x25519 produced an all-zero shared secret");
    }
    let wrap_key = derive_wrap_key(ephemeral_share, recipient_public, shared)?;
    let file_key = ChaCha20Poly1305::new((&*wrap_key).into())
        .decrypt(&[0u8; 12].into(), body)
        .map_err(|_| anyhow::anyhow!("failed to open file key (wrong key or corrupt stanza)"))?;
    Ok(Zeroizing::new(file_key))
}

fn derive_wrap_key(
    ephemeral_share: &[u8; 32],
    recipient_public: &[u8; 32],
    shared: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_share);
    salt[32..].copy_from_slice(recipient_public);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;
    Ok(key)
}

fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    #[test]
    fn recipient_roundtrips() {
        let pk = [7u8; 32];
        let encoded = encode_recipient(&pk).unwrap();
        assert!(encoded.starts_with("age1"));
        assert_eq!(decode_recipient(&encoded).unwrap(), pk);
    }

    #[test]
    fn standard_secret_identity_is_accepted_by_age_library() {
        let scalar = [11u8; 32];
        let encoded = encode_secret_identity(&scalar).unwrap();
        let identity: age_lib::x25519::Identity = encoded.parse().unwrap();
        assert_eq!(
            decode_recipient(&identity.to_public().to_string()).unwrap(),
            {
                let secret = x25519_dalek::StaticSecret::from(scalar);
                x25519_dalek::PublicKey::from(&secret).to_bytes()
            }
        );
    }

    #[test]
    fn identity_roundtrips_and_is_uppercase() {
        let pk = [9u8; 32];
        let encoded = encode_identity(&pk).unwrap();
        assert!(encoded.starts_with("AGE-PLUGIN-PASSEPORT-1"));
        assert_eq!(encoded, encoded.to_uppercase());
        assert_eq!(decode_identity(&encoded).unwrap(), pk);
    }

    #[test]
    fn wrap_then_unwrap_via_recipient_scalar() {
        // Stand in for OPENPGP.2: a static X25519 keypair. The bridge would
        // compute `scalar · share`; here we do it directly.
        let scalar = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&scalar).to_bytes();

        let file_key = [0x42u8; FILE_KEY_LEN];
        let (share, body) = wrap_file_key(&recipient_public, &file_key).unwrap();

        // Decryption side: shared = scalar · share (what ScdBridge ecdh returns).
        let shared = scalar.diffie_hellman(&PublicKey::from(share)).to_bytes();
        let recovered = unwrap_file_key(&recipient_public, &share, &shared, &body).unwrap();
        assert_eq!(recovered.as_slice(), &file_key);
    }

    #[test]
    fn unwrap_rejects_tampered_body() {
        let scalar = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&scalar).to_bytes();
        let (share, mut body) = wrap_file_key(&recipient_public, &[1u8; FILE_KEY_LEN]).unwrap();
        body[0] ^= 0xFF;
        let shared = scalar.diffie_hellman(&PublicKey::from(share)).to_bytes();
        assert!(unwrap_file_key(&recipient_public, &share, &shared, &body).is_err());
    }
}

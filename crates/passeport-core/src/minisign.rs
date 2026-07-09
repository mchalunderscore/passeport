//! minisign-compatible detached signatures over a seed-derived Ed25519 key.
//!
//! Signing needs the private key, so the raw Ed25519 operations run inside the
//! gated `op` process (which alone holds the seed); this module provides the
//! pure framing/assembly and the fully public verification path. The output is
//! byte-compatible with `jedisct1/minisign` and `jedisct1/rsign2`: prehashed
//! (`"ED"`) mode, so it verifies under `minisign -V` / `rsign verify` with no
//! `-l` flag. Format reference: the minisign spec + `rust-minisign` sources.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Signature algorithm bytes on a *signature* file: prehashed BLAKE2b-512.
const SIGALG_PREHASHED: [u8; 2] = *b"ED";
/// Legacy (sign-the-raw-message) algorithm — the public-key file always carries
/// this value, and verifiers accept it on signatures only with `allow_legacy`.
const SIGALG_LEGACY: [u8; 2] = *b"Ed";

const UNTRUSTED_PREFIX: &str = "untrusted comment: ";
const TRUSTED_PREFIX: &str = "trusted comment: ";

/// The 8-byte minisign key id: the first 8 bytes of the raw Ed25519 public key.
/// Deterministic, so a seed-derived identity keeps a stable id across runs.
pub fn key_id(public: &[u8; 32]) -> [u8; 8] {
    let mut id = [0u8; 8];
    id.copy_from_slice(&public[..8]);
    id
}

/// Raw Ed25519 public key for a 32-byte signing seed.
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Unkeyed BLAKE2b-512 (64-byte) prehash of a message — the content a prehashed
/// (`"ED"`) signature actually covers. Public: no secret material involved, so
/// the caller computes it before handing the digest to the gated signer.
pub fn prehash(message: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(message);
    let out = hasher.finalize();
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&out);
    digest
}

/// Render a minisign public-key file (comment line + base64 of the 42-byte
/// `sig_alg("Ed") || keynum(8) || pk(32)` struct).
pub fn public_key_file(public: &[u8; 32], untrusted_comment: &str) -> String {
    let mut payload = Vec::with_capacity(2 + 8 + 32);
    payload.extend_from_slice(&SIGALG_LEGACY); // pubkey sig_alg is ALWAYS "Ed"
    payload.extend_from_slice(&key_id(public));
    payload.extend_from_slice(public);
    format!(
        "{UNTRUSTED_PREFIX}{}\n{}\n",
        sanitize_comment(untrusted_comment),
        BASE64.encode(&payload)
    )
}

/// Assemble a complete minisign signature file (four lines), signing the
/// prehashed message and the trusted comment with `signer`. Must run where the
/// private key lives (the gated `op` process).
pub fn sign_prehashed(
    signer: &SigningKey,
    digest: &[u8; 64],
    trusted_comment: &str,
    untrusted_comment: &str,
) -> Result<String> {
    let id = key_id(&signer.verifying_key().to_bytes());

    // Line 2: detached Ed25519 signature over the BLAKE2b-512 prehash.
    let sig = signer.sign(digest);
    let mut sig_struct = Vec::with_capacity(2 + 8 + 64);
    sig_struct.extend_from_slice(&SIGALG_PREHASHED);
    sig_struct.extend_from_slice(&id);
    sig_struct.extend_from_slice(&sig.to_bytes());

    // Line 4: "global" signature over (sig || trusted_comment_bytes), which is
    // what makes the trusted comment tamper-evident.
    let trusted = sanitize_comment(trusted_comment);
    let mut global_input = Vec::with_capacity(64 + trusted.len());
    global_input.extend_from_slice(&sig.to_bytes());
    global_input.extend_from_slice(trusted.as_bytes());
    let global_sig = signer.sign(&global_input);

    Ok(format!(
        "{UNTRUSTED_PREFIX}{}\n{}\n{TRUSTED_PREFIX}{}\n{}\n",
        sanitize_comment(untrusted_comment),
        BASE64.encode(&sig_struct),
        trusted,
        BASE64.encode(global_sig.to_bytes()),
    ))
}

/// Verify a minisign signature file against a public-key file and the original
/// message. Fully public — no seed, no bridge. Checks the key-id match, the
/// content signature (raw or prehashed per the `Ed`/`ED` bytes), and the global
/// (trusted-comment) signature, exactly as `minisign -V` does.
pub fn verify(public_key_file: &str, signature_file: &str, message: &[u8]) -> Result<()> {
    let (pk_id, pk) = parse_public_key(public_key_file)?;
    let sig = parse_signature(signature_file)?;

    if sig.key_id != pk_id {
        bail!("signature key id does not match the public key");
    }
    let verifying = VerifyingKey::from_bytes(&pk).context("invalid ed25519 public key")?;

    let signed_content = match &sig.alg {
        b"ED" => prehash(message).to_vec(),
        b"Ed" => message.to_vec(),
        other => bail!("unknown signature algorithm {other:?}"),
    };
    verifying
        .verify(&signed_content, &Signature::from_bytes(&sig.signature))
        .context("content signature does not verify")?;

    let mut global_input = Vec::with_capacity(64 + sig.trusted_comment.len());
    global_input.extend_from_slice(&sig.signature);
    global_input.extend_from_slice(sig.trusted_comment.as_bytes());
    verifying
        .verify(&global_input, &Signature::from_bytes(&sig.global_signature))
        .context("trusted-comment (global) signature does not verify")?;
    Ok(())
}

struct ParsedSignature {
    alg: [u8; 2],
    key_id: [u8; 8],
    signature: [u8; 64],
    global_signature: [u8; 64],
    trusted_comment: String,
}

fn parse_public_key(file: &str) -> Result<([u8; 8], [u8; 32])> {
    let b64 = file
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .context("public key file has no payload line")?;
    let payload = BASE64
        .decode(b64)
        .context("public key payload is not valid base64")?;
    if payload.len() != 42 {
        bail!("public key payload must be 42 bytes, got {}", payload.len());
    }
    if payload[..2] != SIGALG_LEGACY {
        bail!("public key algorithm must be \"Ed\"");
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&payload[2..10]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&payload[10..42]);
    Ok((id, pk))
}

fn parse_signature(file: &str) -> Result<ParsedSignature> {
    let lines: Vec<&str> = file.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with("untrusted comment:"))
        .context("signature file has no untrusted comment line")?;

    let sig_b64 = lines
        .get(start + 1)
        .context("signature file is missing the signature line")?
        .trim();
    let trusted_line = lines
        .get(start + 2)
        .context("signature file is missing the trusted comment line")?;
    let global_b64 = lines
        .get(start + 3)
        .context("signature file is missing the global signature line")?
        .trim();

    let sig_payload = BASE64
        .decode(sig_b64)
        .context("signature line is not valid base64")?;
    if sig_payload.len() != 74 {
        bail!(
            "signature payload must be 74 bytes, got {}",
            sig_payload.len()
        );
    }
    let mut alg = [0u8; 2];
    alg.copy_from_slice(&sig_payload[..2]);
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&sig_payload[2..10]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_payload[10..74]);

    let trusted_comment = trusted_line
        .strip_prefix(TRUSTED_PREFIX)
        .or_else(|| trusted_line.strip_prefix("trusted comment:"))
        .context("malformed trusted comment line")?
        .to_owned();

    let global = BASE64
        .decode(global_b64)
        .context("global signature line is not valid base64")?;
    if global.len() != 64 {
        bail!("global signature must be 64 bytes, got {}", global.len());
    }
    let mut global_signature = [0u8; 64];
    global_signature.copy_from_slice(&global);

    Ok(ParsedSignature {
        alg,
        key_id,
        signature,
        global_signature,
        trusted_comment,
    })
}

/// minisign comment lines may not contain CR/LF; collapse any to spaces.
fn sanitize_comment(comment: &str) -> String {
    comment.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        *crate::identity::derive_minisign_seed(&[7u8; 32]).unwrap()
    }

    #[test]
    fn sign_verify_round_trips_prehashed() {
        let signer = SigningKey::from_bytes(&seed());
        let public = signer.verifying_key().to_bytes();
        let message = b"the quick brown fox jumps over the lazy dog";
        let sig_file = sign_prehashed(
            &signer,
            &prehash(message),
            "timestamp:1767225600\tfile:fox.txt\thashed",
            "signed by passeport",
        )
        .unwrap();
        let pk_file = public_key_file(&public, "passeport minisign key");
        verify(&pk_file, &sig_file, message).expect("round-trip must verify");
    }

    #[test]
    fn signature_byte_boundaries_match_spec() {
        let signer = SigningKey::from_bytes(&seed());
        let public = signer.verifying_key().to_bytes();
        let sig_file = sign_prehashed(&signer, &prehash(b"m"), "tc", "uc").unwrap();
        let lines: Vec<&str> = sig_file.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("untrusted comment: "));
        assert_eq!(
            lines[1].len(),
            100,
            "base64(74-byte SigStruct) is 100 chars"
        );
        assert!(lines[2].starts_with("trusted comment: "));
        assert_eq!(lines[3].len(), 88, "base64(64-byte global sig) is 88 chars");
        let pk_file = public_key_file(&public, "x");
        assert_eq!(
            pk_file.lines().nth(1).unwrap().len(),
            56,
            "base64(42-byte pubkey) is 56 chars"
        );
    }

    #[test]
    fn rejects_tampered_message() {
        let signer = SigningKey::from_bytes(&seed());
        let public = signer.verifying_key().to_bytes();
        let sig_file = sign_prehashed(&signer, &prehash(b"original"), "tc", "uc").unwrap();
        let pk_file = public_key_file(&public, "x");
        assert!(verify(&pk_file, &sig_file, b"tampered").is_err());
    }

    #[test]
    fn signature_and_pubkey_share_key_id() {
        let signer = SigningKey::from_bytes(&seed());
        let public = signer.verifying_key().to_bytes();
        let id = key_id(&public);
        let sig_file = sign_prehashed(&signer, &prehash(b"m"), "tc", "uc").unwrap();
        let sig_payload = BASE64.decode(sig_file.lines().nth(1).unwrap()).unwrap();
        assert_eq!(
            &sig_payload[2..10],
            &id,
            "sig keynum must equal pubkey keynum"
        );
    }

    #[test]
    fn frozen_derivation_vector() {
        // Contract lock for the seed-derived minisign identity at PRF=[7u8;32],
        // mirroring main.rs SELFTEST_FINGERPRINT for the OpenPGP tree. Any drift
        // in the HKDF label, the ed25519 handling, or the key-id rule breaks it.
        let public = public_key_from_seed(&seed());
        assert_eq!(hex::encode(key_id(&public)), "b9c23bddc3005bf1");
        assert_eq!(
            public_key_file(&public, "x").lines().nth(1).unwrap(),
            "RWS5wjvdwwBb8bnCO93DAFvxuOB8+ZVYStV/2cgn4WYCTAzXTG6zkOUe"
        );
    }

    #[test]
    fn minisign_seed_is_independent_of_pgp_seed() {
        // Domain separation: same PRF, different HKDF info => different key.
        let prf = [7u8; 32];
        let ms = *crate::identity::derive_minisign_seed(&prf).unwrap();
        let pgp = *crate::identity::derive_pgp_seed(&prf).unwrap();
        assert_ne!(ms, pgp);
    }
}

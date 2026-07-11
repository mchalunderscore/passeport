//! Primitive private-key operations and the `op` subcommand.
//!
//! `op` mode is what the Passeport app invokes (after unlocking the seed
//! under the app's approval policy) to answer a single request from the scd shim. The seed
//! reaches this process only on stdin and only for the lifetime of one call;
//! the shim itself never sees it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

use crate::identity::{self, SlotRole, SlotSecret};

/// A request from the shim to the key holder. Same shape on the wire (socket)
/// and inside `op` mode; the PRF is supplied out-of-band by the holder.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    /// Public material for all slots, so the shim can model the card.
    Pubkeys {
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        comment: Option<String>,
    },
    /// Ed25519 signature over `data` (already DigestInfo-stripped) by `keyref`.
    Sign {
        keyref: String,
        #[serde(with = "hex_bytes")]
        data: Vec<u8>,
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        comment: Option<String>,
    },
    /// X25519 shared secret between `keyref` and the 32-byte `point`.
    Ecdh {
        keyref: String,
        #[serde(with = "hex_bytes")]
        point: Vec<u8>,
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        comment: Option<String>,
    },
    /// Assemble a full minisign signature file with the seed-derived minisign
    /// key. `prehash` is the 64-byte BLAKE2b-512 digest of the message, computed
    /// publicly by the caller; the gated process signs it and the trusted
    /// comment. Handled in `run_op` (needs the minisign key, not the pgp seed).
    MinisignSign {
        #[serde(with = "hex_bytes")]
        prehash: Vec<u8>,
        trusted_comment: String,
        untrusted_comment: String,
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        comment: Option<String>,
    },
    /// Decrypt an OpenPGP message encrypted to our cv25519 encryption subkey.
    /// Ciphertext and plaintext use the shared bounded file/FIFO handoff.
    PgpDecrypt {
        ciphertext_path: String,
        plaintext_path: String,
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        comment: Option<String>,
    },
    /// Decrypt a standard age file with the cv25519 encryption subkey.
    /// The CLI and gated op exchange file paths instead of placing whole files
    /// on the line-delimited JSON bridge.
    AgeDecrypt {
        ciphertext_path: String,
        plaintext_path: String,
        #[serde(default)]
        client: Option<String>,
        #[serde(default)]
        comment: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Pubkeys {
        ok: bool,
        slots: Vec<SlotPublic>,
    },
    Sign {
        ok: bool,
        #[serde(with = "hex_bytes")]
        sig: Vec<u8>,
    },
    Ecdh {
        ok: bool,
        #[serde(with = "hex_bytes")]
        shared: Vec<u8>,
    },
    Minisign {
        ok: bool,
        signature_file: String,
    },
    PgpDecrypt {
        ok: bool,
    },
    AgeDecrypt {
        ok: bool,
    },
    Error {
        ok: bool,
        error: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotPublic {
    pub keyref: String,
    pub role: String,
    #[serde(with = "hex_bytes")]
    pub q: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub fpr: Vec<u8>,
}

/// Send one request to the Passeport app bridge over its Unix socket and read
/// the one-line JSON response. The single encoder/decoder for the bridge wire
/// protocol, shared by the scd shim and the age plugin.
pub fn call_socket(path: &str, request: &Request) -> Result<Response> {
    let stream = UnixStream::connect(path)
        .with_context(|| format!("cannot reach the Passeport app at {path} (is it running?)"))?;
    let mut writer = &stream;
    let line = serde_json::to_string(request)?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .context("no response from Passeport app")?;
    serde_json::from_str(response.trim())
        .with_context(|| format!("bad response from app: {}", response.trim()))
}

fn role_name(role: SlotRole) -> &'static str {
    match role {
        SlotRole::Sign => "sign",
        SlotRole::Decrypt => "decrypt",
        SlotRole::Auth => "auth",
    }
}

/// Answer one request given the seed. This is the single choke point through
/// which all private operations pass.
pub fn handle(seed: &[u8; 32], user_id: &str, request: &Request) -> Result<Response> {
    let materials = identity::slot_materials(seed, user_id)?;
    match request {
        Request::Pubkeys { .. } => {
            let slots = materials
                .iter()
                .map(|m| SlotPublic {
                    keyref: m.role.keyref().to_owned(),
                    role: role_name(m.role).to_owned(),
                    q: m.q.clone(),
                    fpr: m.fingerprint.clone(),
                })
                .collect();
            Ok(Response::Pubkeys { ok: true, slots })
        }
        Request::Sign { keyref, data, .. } => {
            let slot = materials
                .iter()
                .find(|m| m.role.keyref() == keyref)
                .with_context(|| format!("no such slot: {keyref}"))?;
            let SlotSecret::Ed25519(seed) = &slot.secret else {
                bail!("slot {keyref} cannot sign");
            };
            let signature = SigningKey::from_bytes(seed).sign(data);
            Ok(Response::Sign {
                ok: true,
                sig: signature.to_bytes().to_vec(),
            })
        }
        Request::Ecdh { keyref, point, .. } => {
            let slot = materials
                .iter()
                .find(|m| m.role.keyref() == keyref)
                .with_context(|| format!("no such slot: {keyref}"))?;
            let SlotSecret::X25519(scalar_le) = &slot.secret else {
                bail!("slot {keyref} cannot decrypt");
            };
            if point.len() != 32 {
                bail!("ecdh point must be 32 bytes");
            }
            let mut peer = [0u8; 32];
            peer.copy_from_slice(point);
            let secret = StaticSecret::from(**scalar_le);
            let shared = secret.diffie_hellman(&X25519Public::from(peer));
            Ok(Response::Ecdh {
                ok: true,
                shared: shared.as_bytes().to_vec(),
            })
        }
        Request::MinisignSign { .. } => {
            // Needs the minisign key (a separate HKDF domain), which `handle`
            // does not hold — `run_op` derives it from the PRF and handles this.
            bail!("minisign signing must be routed through run_op, not handle()")
        }
        Request::PgpDecrypt { .. } => {
            // Reconstructs the full secret key; routed through run_op.
            bail!("pgp decrypt must be routed through run_op, not handle()")
        }
        Request::AgeDecrypt { .. } => {
            bail!("age decrypt must be routed through run_op, not handle()")
        }
    }
}

/// `passeport-core op`: read `{prf, user_id, request}` from stdin, write the
/// response as one JSON line.
#[derive(Debug, Deserialize)]
struct OpEnvelope {
    prf: String,
    #[serde(default = "default_user_id")]
    user_id: String,
    request: Request,
}

fn default_user_id() -> String {
    "Passeport <passeport@localhost>".to_owned()
}

pub fn run_op() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read op request")?;
    let envelope: OpEnvelope =
        serde_json::from_str(&input).context("failed to parse op request json")?;

    let prf = identity::decode_prf(&envelope.prf)?;

    // Minisign uses its own seed domain and skips the (expensive) OpenPGP key
    // generation; everything else goes through the shared `handle` choke point.
    let response = match &envelope.request {
        Request::MinisignSign {
            prehash,
            trusted_comment,
            untrusted_comment,
            ..
        } => match run_minisign_sign(&prf, prehash, trusted_comment, untrusted_comment) {
            Ok(signature_file) => Response::Minisign {
                ok: true,
                signature_file,
            },
            Err(error) => Response::Error {
                ok: false,
                error: format!("{error:#}"),
            },
        },
        Request::PgpDecrypt {
            ciphertext_path,
            plaintext_path,
            ..
        } => match run_pgp_decrypt_file(&prf, &envelope.user_id, ciphertext_path, plaintext_path) {
            Ok(()) => Response::PgpDecrypt { ok: true },
            Err(error) => Response::Error {
                ok: false,
                error: format!("{error:#}"),
            },
        },
        Request::AgeDecrypt {
            ciphertext_path,
            plaintext_path,
            ..
        } => match run_age_decrypt_file(&prf, &envelope.user_id, ciphertext_path, plaintext_path) {
            Ok(()) => Response::AgeDecrypt { ok: true },
            Err(error) => Response::Error {
                ok: false,
                error: format!("{error:#}"),
            },
        },
        request => {
            let seed = identity::derive_pgp_seed(&prf)?;
            match handle(&seed, &envelope.user_id, request) {
                Ok(response) => response,
                Err(error) => Response::Error {
                    ok: false,
                    error: format!("{error:#}"),
                },
            }
        }
    };
    let line = serde_json::to_string(&response).context("failed to encode op response")?;
    println!("{line}");
    Ok(())
}

/// Sign a minisign signature file with the seed-derived minisign key. Runs only
/// inside the gated `op` process (which holds the PRF), never in the CLI shim.
fn run_minisign_sign(
    prf: &[u8; 32],
    prehash: &[u8],
    trusted_comment: &str,
    untrusted_comment: &str,
) -> Result<String> {
    if prehash.len() != 64 {
        bail!("minisign prehash must be 64 bytes (BLAKE2b-512)");
    }
    let seed = identity::derive_minisign_seed(prf)?;
    let signer = SigningKey::from_bytes(&seed);
    let mut digest = [0u8; 64];
    digest.copy_from_slice(prehash);
    crate::minisign::sign_prehashed(&signer, &digest, trusted_comment, untrusted_comment)
}

/// Decrypt an OpenPGP message with the seed-reconstructed secret key. Runs only
/// inside the gated `op` process; the seed never reaches the CLI shim.
fn run_pgp_decrypt(prf: &[u8; 32], user_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let seed = identity::derive_pgp_seed(prf)?;
    let key = identity::generate_signed_key(&seed, user_id)?;
    let message = crate::pgp_sign::parse_message(ciphertext)?;
    let (decrypted, _key_ids) = message
        .decrypt(String::new, &[&key])
        .context("failed to decrypt the message")?;
    decrypted
        .get_content()?
        .context("the decrypted message had no content")
}

fn run_pgp_decrypt_file(
    prf: &[u8; 32],
    user_id: &str,
    ciphertext_path: &str,
    plaintext_path: &str,
) -> Result<()> {
    let ciphertext = std::fs::read(ciphertext_path)
        .with_context(|| format!("failed to read OpenPGP ciphertext at {ciphertext_path}"))?;
    let plaintext = run_pgp_decrypt(prf, user_id, &ciphertext)?;
    crate::handoff::write_plaintext(plaintext_path, &plaintext)
}

/// Decrypt a standard age file with the seed-derived OPENPGP.2 scalar. The
/// temporary secret identity exists only in this gated op process.
fn run_age_decrypt(prf: &[u8; 32], user_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let seed = identity::derive_pgp_seed(prf)?;
    let materials = identity::slot_materials(&seed, user_id)?;
    let decrypt = materials
        .iter()
        .find(|material| material.role == SlotRole::Decrypt)
        .context("missing cv25519 decryption slot")?;
    let SlotSecret::X25519(scalar) = &decrypt.secret else {
        bail!("OPENPGP.2 is not an X25519 key");
    };
    let encoded = crate::age::encode_secret_identity(scalar)?;
    let age_identity: age_lib::x25519::Identity = encoded
        .parse()
        .map_err(|error| anyhow::anyhow!("failed to construct age identity: {error}"))?;
    age_lib::decrypt(&age_identity, ciphertext).context("failed to decrypt age file")
}

fn run_age_decrypt_file(
    prf: &[u8; 32],
    user_id: &str,
    ciphertext_path: &str,
    plaintext_path: &str,
) -> Result<()> {
    let ciphertext = std::fs::read(ciphertext_path)
        .with_context(|| format!("failed to read age ciphertext at {ciphertext_path}"))?;
    let plaintext = run_age_decrypt(prf, user_id, &ciphertext)?;
    crate::handoff::write_plaintext(plaintext_path, &plaintext)
}

/// Hex (de)serialization for `Vec<u8>` fields on the wire.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let string = String::deserialize(deserializer)?;
        hex::decode(&string).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn seed() -> [u8; 32] {
        let prf = [7u8; 32];
        *identity::derive_pgp_seed(&prf).unwrap()
    }

    #[test]
    fn sign_via_handle_verifies() {
        let seed = seed();
        let uid = "Passeport Test <test@example.invalid>";
        let materials = identity::slot_materials(&seed, uid).unwrap();
        let sign_q = materials
            .iter()
            .find(|m| m.role == SlotRole::Sign)
            .unwrap()
            .q
            .clone();

        let data = b"bytes to sign";
        let response = handle(
            &seed,
            uid,
            &Request::Sign {
                keyref: "OPENPGP.1".into(),
                data: data.to_vec(),
                client: None,
                comment: None,
            },
        )
        .unwrap();
        let Response::Sign { sig, .. } = response else {
            panic!("wrong response")
        };

        let mut pk = [0u8; 32];
        pk.copy_from_slice(&sign_q[1..]);
        let verifying = VerifyingKey::from_bytes(&pk).unwrap();
        let signature = Signature::from_bytes(&sig.try_into().unwrap());
        verifying.verify(data, &signature).unwrap();
    }

    #[test]
    fn minisign_sign_via_run_op_verifies() {
        let prf = [7u8; 32];
        let message = b"release-v1.2.3.tar.gz contents";
        let digest = crate::minisign::prehash(message);
        let signature_file =
            run_minisign_sign(&prf, &digest, "timestamp:1767225600", "passeport").unwrap();

        let ms_seed = identity::derive_minisign_seed(&prf).unwrap();
        let public = crate::minisign::public_key_from_seed(&ms_seed);
        let pubkey_file = crate::minisign::public_key_file(&public, "passeport");
        crate::minisign::verify(&pubkey_file, &signature_file, message).unwrap();
    }

    #[test]
    fn minisign_rejects_short_prehash() {
        assert!(run_minisign_sign(&[7u8; 32], &[0u8; 32], "tc", "uc").is_err());
    }

    #[test]
    fn age_decrypt_op_opens_standard_age_ciphertext() {
        let prf = [7u8; 32];
        let user_id = "Passeport Test <test@example.invalid>";
        let seed = identity::derive_pgp_seed(&prf).unwrap();
        let materials = identity::slot_materials(&seed, user_id).unwrap();
        let decrypt = materials
            .iter()
            .find(|material| material.role == SlotRole::Decrypt)
            .unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(&decrypt.q[1..]);
        let recipient: age_lib::x25519::Recipient = crate::age::encode_recipient(&public)
            .unwrap()
            .parse()
            .unwrap();
        let ciphertext = age_lib::encrypt(&recipient, b"standard age interop").unwrap();

        let plaintext = run_age_decrypt(&prf, user_id, &ciphertext).unwrap();
        assert_eq!(plaintext, b"standard age interop");
    }

    #[test]
    fn age_decrypt_file_handoff_handles_large_payloads_with_small_json() {
        let prf = [7u8; 32];
        let user_id = "Passeport Test <test@example.invalid>";
        let seed = identity::derive_pgp_seed(&prf).unwrap();
        let materials = identity::slot_materials(&seed, user_id).unwrap();
        let decrypt = materials
            .iter()
            .find(|material| material.role == SlotRole::Decrypt)
            .unwrap();
        let mut public = [0u8; 32];
        public.copy_from_slice(&decrypt.q[1..]);
        let recipient: age_lib::x25519::Recipient = crate::age::encode_recipient(&public)
            .unwrap()
            .parse()
            .unwrap();
        let plaintext = vec![0x5a; 2_000_000];
        let ciphertext = age_lib::encrypt(&recipient, &plaintext).unwrap();
        let handoff =
            crate::handoff::DecryptHandoff::create("passeport-age-", &ciphertext).unwrap();
        let reader = handoff.start_reader();

        let request = Request::AgeDecrypt {
            ciphertext_path: handoff.ciphertext_path(),
            plaintext_path: handoff.plaintext_path(),
            client: None,
            comment: None,
        };
        assert!(serde_json::to_vec(&request).unwrap().len() < 1_024);
        run_age_decrypt_file(
            &prf,
            user_id,
            &handoff.ciphertext_path(),
            &handoff.plaintext_path(),
        )
        .unwrap();
        assert_eq!(crate::handoff::join_reader(reader).unwrap(), plaintext);
    }

    #[test]
    fn pgp_decrypt_file_handoff_handles_large_payloads_with_small_json() {
        let prf = [7u8; 32];
        let user_id = "Passeport Test <test@example.invalid>";
        let seed = identity::derive_pgp_seed(&prf).unwrap();
        let secret = identity::generate_signed_key(&seed, user_id).unwrap();
        let public: pgp::SignedPublicKey = secret.into();
        let plaintext = vec![0x6b; 2_000_000];
        let ciphertext =
            crate::pgp_sign::encrypt_to_self(&public, &plaintext, "large.bin", false).unwrap();
        let handoff =
            crate::handoff::DecryptHandoff::create("passeport-pgp-", &ciphertext).unwrap();
        let reader = handoff.start_reader();
        let request = Request::PgpDecrypt {
            ciphertext_path: handoff.ciphertext_path(),
            plaintext_path: handoff.plaintext_path(),
            client: None,
            comment: None,
        };
        assert!(serde_json::to_vec(&request).unwrap().len() < 1_024);
        run_pgp_decrypt_file(
            &prf,
            user_id,
            &handoff.ciphertext_path(),
            &handoff.plaintext_path(),
        )
        .unwrap();
        assert_eq!(crate::handoff::join_reader(reader).unwrap(), plaintext);
    }

    #[test]
    fn request_roundtrips_through_json() {
        let request = Request::Sign {
            keyref: "OPENPGP.3".into(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            client: None,
            comment: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"op\":\"sign\""));
        assert!(json.contains("deadbeef"));
        let back: Request = serde_json::from_str(&json).unwrap();
        matches!(back, Request::Sign { .. });
    }
}

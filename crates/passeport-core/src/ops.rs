//! Primitive private-key operations and the `op` subcommand.
//!
//! `op` mode is what the Passeport app invokes (after unlocking the seed
//! behind Touch ID) to answer a single request from the scd shim. The seed
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
    let seed = identity::derive_pgp_seed(&prf)?;

    let response = match handle(&seed, &envelope.user_id, &envelope.request) {
        Ok(response) => response,
        Err(error) => Response::Error {
            ok: false,
            error: format!("{error:#}"),
        },
    };
    let line = serde_json::to_string(&response).context("failed to encode op response")?;
    println!("{line}");
    Ok(())
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

mod identity;
mod ops;
mod age;
mod age_plugin;
mod scd;

use std::io::{self, Read};

use anyhow::{Context, Result};
use base64::Engine;
use pgp::Deserializable;
use pgp::types::PublicKeyTrait;
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use zeroize::Zeroizing;

use identity::{
    auth_subkey_public, decode_prf, derive_pgp_seed, encryption_subkey_public, generate_signed_key,
};

#[derive(Debug, Deserialize)]
struct DeriveRequest {
    prf: String,
    user_id: String,
    ssh_comment: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeriveResponse {
    ssh: SshOutput,
    pgp: PgpOutput,
    age: AgeOutput,
}

#[derive(Debug, Serialize)]
struct SshOutput {
    public_key: String,
}

#[derive(Debug, Serialize)]
struct AgeOutput {
    recipient: String,
}

#[derive(Debug, Serialize)]
struct PgpOutput {
    fingerprint: String,
    public_key: String,
    secret_key: String,
}

fn main() {
    // age invokes the plugin as `age-plugin-passeport --age-plugin=<state>`.
    // We ship that name as a symlink to this binary, so dispatch on the flag.
    let args: Vec<String> = std::env::args().collect();
    if let Some(state) = args.iter().find_map(|a| a.strip_prefix("--age-plugin=")) {
        if let Err(error) = age_plugin::run(state) {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
        return;
    }

    let mode = std::env::args().nth(1);
    let result = match mode.as_deref() {
        Some("scd") => scd::serve(),
        Some("op") => ops::run_op(),
        Some("mnemonic-encode") => run_mnemonic_encode(),
        Some("mnemonic-decode") => run_mnemonic_decode(),
        Some("revoke") => run_revoke(),
        Some("selftest") => run_selftest(),
        Some("age-recipient") => run_age_recipient(),
        None => run(),
        Some(other) => Err(anyhow::anyhow!("unknown mode: {other}")),
    };
    if let Err(error) = result {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read request from stdin")?;

    let request: DeriveRequest =
        serde_json::from_str(&input).context("failed to parse request json")?;
    let response = derive_response(&request)?;

    serde_json::to_writer_pretty(io::stdout(), &response)
        .context("failed to write response json")?;
    Ok(())
}

fn derive_response(request: &DeriveRequest) -> Result<DeriveResponse> {
    let prf = decode_prf(&request.prf)?;
    let pgp_seed = derive_pgp_seed(&prf)?;
    let signed_key = generate_signed_key(&pgp_seed, &request.user_id)?;

    let public_key: pgp::SignedPublicKey = signed_key.clone().into();
    let public_armored = public_key
        .to_armored_string(None.into())
        .context("failed to armor pgp public key")?;
    let secret_armored = signed_key
        .to_armored_string(None.into())
        .context("failed to armor pgp secret key")?;
    let fingerprint = pgp_fingerprint(&public_armored)?;

    // The SSH identity is the OpenPGP authentication subkey (contract v2);
    // gpg-agent serves it over the ssh-agent protocol.
    let ssh_raw = auth_subkey_public(&signed_key)?;
    let ssh_public = PublicKey::new(
        KeyData::Ed25519(Ed25519PublicKey(ssh_raw)),
        request.ssh_comment.as_deref().unwrap_or("passeport"),
    );

    // The age recipient is the encryption subkey's X25519 public key.
    let age_recipient = age::encode_recipient(&encryption_subkey_public(&signed_key)?)?;

    Ok(DeriveResponse {
        ssh: SshOutput {
            public_key: ssh_public
                .to_openssh()
                .context("failed to serialize ssh public key")?,
        },
        pgp: PgpOutput {
            fingerprint,
            public_key: public_armored,
            secret_key: secret_armored,
        },
        age: AgeOutput {
            recipient: age_recipient,
        },
    })
}

/// `age-recipient`: read the encryption subkey's 32-byte X25519 public key as
/// hex from stdin, print `{recipient, identity}` for age. No seed access — the
/// app pipes the public point from its card cache.
fn run_age_recipient() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read public key from stdin")?;
    let bytes = hex::decode(input.trim()).context("public key must be hex")?;
    let public_key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let response = serde_json::json!({
        "recipient": age::encode_recipient(&public_key)?,
        "identity": age::encode_identity(&public_key)?,
    });
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn pgp_fingerprint(armored_pubkey: &str) -> Result<String> {
    let (signed_pub, _) = pgp::SignedPublicKey::from_armor_single(armored_pubkey.as_bytes())
        .context("failed to parse generated pgp public key")?;
    Ok(format!("{:?}", signed_pub.fingerprint()))
}

/// Frozen baseline: the OpenPGP fingerprint derived from PRF = [7u8; 32].
/// The self-test asserts this to catch any drift in the derivation contract
/// (rpgp version, RNG order, timestamps, labels).
const SELFTEST_PRF: [u8; 32] = [7u8; 32];
const SELFTEST_FINGERPRINT: &str = "ebe1398447f74b6e6fc8b103743f4ed741f9a822";

fn decode_seed(field: &str, encoded: &str) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .with_context(|| format!("{field} must be base64url without padding"))?;
    if decoded.len() != 32 {
        anyhow::bail!("{field} must decode to exactly 32 bytes");
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

#[derive(Deserialize)]
struct SeedInput {
    seed: String,
}

#[derive(Serialize)]
struct MnemonicOutput {
    mnemonic: String,
}

fn run_mnemonic_encode() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: SeedInput = serde_json::from_str(&input).context("failed to parse seed json")?;
    let seed = decode_seed("seed", &request.seed)?;
    let mnemonic = identity::mnemonic_from_seed(&seed)?;
    serde_json::to_writer(io::stdout(), &MnemonicOutput { mnemonic })?;
    Ok(())
}

#[derive(Deserialize)]
struct MnemonicInput {
    mnemonic: String,
}

#[derive(Serialize)]
struct SeedOutput {
    seed: String,
}

fn run_mnemonic_decode() -> Result<()> {
    use base64::Engine;
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: MnemonicInput =
        serde_json::from_str(&input).context("failed to parse mnemonic json")?;
    let seed = identity::seed_from_mnemonic(&request.mnemonic)?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed.as_ref());
    serde_json::to_writer(io::stdout(), &SeedOutput { seed: encoded })?;
    Ok(())
}

#[derive(Deserialize)]
struct RevokeInput {
    prf: String,
    #[serde(default = "default_user_id")]
    user_id: String,
}

fn default_user_id() -> String {
    "Passeport <passeport@localhost>".to_owned()
}

fn run_revoke() -> Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: RevokeInput =
        serde_json::from_str(&input).context("failed to parse revoke json")?;
    let prf = identity::decode_prf(&request.prf)?;
    let seed = identity::derive_pgp_seed(&prf)?;
    let armored = identity::revocation_certificate(&seed, &request.user_id)?;
    print!("{armored}");
    Ok(())
}

fn run_selftest() -> Result<()> {
    use base64::Engine;
    let prf = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SELFTEST_PRF);
    let request = DeriveRequest {
        prf,
        user_id: "Passeport Selftest <selftest@localhost>".to_owned(),
        ssh_comment: Some("passeport".to_owned()),
    };
    let response = derive_response(&request)?;
    if response.pgp.fingerprint == SELFTEST_FINGERPRINT {
        println!("OK {}", response.pgp.fingerprint);
        Ok(())
    } else {
        anyhow::bail!(
            "derivation contract drift: expected {SELFTEST_FINGERPRINT}, got {}",
            response.pgp.fingerprint
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn request() -> DeriveRequest {
        DeriveRequest {
            prf: URL_SAFE_NO_PAD.encode([7u8; 32]),
            user_id: "Passeport Test <test@example.invalid>".to_owned(),
            ssh_comment: Some("passeport-test".to_owned()),
        }
    }

    #[test]
    fn derives_deterministic_identity() {
        let first = derive_response(&request()).unwrap();
        let second = derive_response(&request()).unwrap();
        assert_eq!(first.ssh.public_key, second.ssh.public_key);
        assert_eq!(first.pgp.fingerprint, second.pgp.fingerprint);
        assert_eq!(first.pgp.public_key, second.pgp.public_key);
    }

    #[test]
    fn ssh_key_is_the_auth_subkey() {
        let response = derive_response(&request()).unwrap();
        assert!(response.ssh.public_key.starts_with("ssh-ed25519 "));
        assert!(response.ssh.public_key.ends_with(" passeport-test"));

        // The blob must encode the auth subkey, not an independent key.
        let prf = decode_prf(&request().prf).unwrap();
        let pgp_seed = derive_pgp_seed(&prf).unwrap();
        let signed_key = generate_signed_key(&pgp_seed, &request().user_id).unwrap();
        let raw = auth_subkey_public(&signed_key).unwrap();
        let direct = PublicKey::new(KeyData::Ed25519(Ed25519PublicKey(raw)), "passeport-test");
        assert_eq!(response.ssh.public_key, direct.to_openssh().unwrap());
    }

    #[test]
    fn rejects_wrong_prf_length() {
        let mut request = request();
        request.prf = URL_SAFE_NO_PAD.encode([1u8; 31]);
        assert!(derive_response(&request).is_err());
    }
}

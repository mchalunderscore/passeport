//! A self-contained, pure-Rust `gpg` drop-in for the single Passeport identity
//! (Mode 2). It implements exactly the surface git + provisioning need —
//! detached signing, verifying OUR OWN signatures, public-key export, colon
//! listing, and version — with the one private signing op delegated to the
//! running app over the bridge socket. Anything requiring a third-party keyring
//! or secret-key export is refused with a clear, non-zero error, never a faked
//! success. See TODO / the gpg-cli-surface recon for the exact contract.

use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use pgp::Deserializable;
use pgp::composed::SignedPublicKey;
use pgp::types::PublicKeyTrait;

use crate::pgp_sign::{self, HASH_ALGO_SHA512, PK_ALGO_EDDSA, VerifyOutcome};

const HELP_TEXT: &str = "\
Passeport gpg — a self-contained OpenPGP CLI for your one Passeport identity.
Private-key operations run in the app (Touch ID-gated); the seed never leaves it.

Supported:
  -b -s -a -u KEY --detach-sign   detached signature (git commit/tag signing)
  -s / --clear-sign               inline or clear-signed message
  --verify SIG [FILE]             verify a signature made by THIS identity
  -e -r KEY [--armor]             encrypt to your own key
  -d / --decrypt                  decrypt a message encrypted to your key
  --export --armor                export your public key
  -k / -K / --list-keys [--with-colons], --fingerprint, --version

Refused by design (single identity, no keyring):
  verifying someone else's signature   -> ERRSIG / NO_PUBKEY
  encrypting to anyone but yourself     -> INV_RECP
  --export-secret-keys                  the seed never leaves the Secure Enclave
  --import / --gen-key / --edit-key / keyservers / trustdb / --symmetric

Notes:
  Signatures are standard OpenPGP and verify under regular gpg.
  Use age (bundled) for general file encryption to other people.
";

/// Entry point: parse gpg-style argv and return a process exit code.
pub fn run(args: &[String]) -> i32 {
    let opts = match Options::parse(args) {
        Ok(opts) => opts,
        Err(error) => {
            eprintln!("gpg: {error:#}");
            return 2;
        }
    };
    match dispatch(&opts) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("gpg: {error:#}");
            2
        }
    }
}

fn dispatch(opts: &Options) -> Result<i32> {
    if opts.help {
        return cmd_help();
    }
    if opts.version {
        return cmd_version();
    }
    if let Some(cmd) = &opts.unsupported {
        bail!("operation '{cmd}' is not supported by Passeport (single-identity, no keyring)");
    }
    if opts.export_secret {
        bail!("exporting secret keys is not allowed — the seed never leaves the Secure Enclave");
    }
    if opts.export {
        return cmd_export(opts);
    }
    if opts.list_secret || opts.list_keys {
        return cmd_list_keys(opts);
    }
    if opts.fingerprint {
        return cmd_fingerprint(opts);
    }
    if opts.verify {
        return cmd_verify(opts);
    }
    if opts.decrypt {
        return cmd_decrypt(opts);
    }
    if opts.encrypt {
        return cmd_encrypt(opts);
    }
    if opts.detach_sign || opts.sign || opts.clearsign {
        return cmd_sign(opts);
    }
    bail!("no operation requested (try --help)");
}

// MARK: - Commands

fn cmd_sign(opts: &Options) -> Result<i32> {
    let pubkey = load_public_key(opts)?;
    let fpr = hex_upper(pubkey.primary_key.fingerprint().as_bytes());

    if let Some(user) = &opts.local_user
        && !key_matches(&pubkey, user)
    {
        opts.status("INV_SGNR 9 ");
        bail!("no matching local user for '{user}'");
    }

    let mut payload = Vec::new();
    std::io::stdin()
        .read_to_end(&mut payload)
        .context("failed to read payload from stdin")?;

    let socket = std::env::var("PASSEPORT_SCD_SOCKET")
        .context("PASSEPORT_SCD_SOCKET is unset — is the Passeport app running?")?;
    let signer = pgp_sign::RemoteSigner::new(
        pubkey.primary_key.clone(),
        Box::new(move |data: &[u8]| bridge_sign(&socket, data)),
    );

    // Detached (git), clear-signed, or inline — all delegate the raw op to the
    // bridge via the same signer.
    let created = now_utc();
    let (sig_type, output) = if opts.detach_sign {
        ("D", pgp_sign::detached_sign(&signer, &payload, created)?)
    } else if opts.clearsign {
        let text = String::from_utf8(payload).context("clear-sign input must be UTF-8 text")?;
        ("C", pgp_sign::clearsign(&signer, &text, created)?)
    } else {
        ("S", pgp_sign::inline_sign(&signer, &payload, "")?)
    };
    write_output(opts, output.as_bytes())?;

    opts.status(&format!("KEY_CONSIDERED {fpr} 2"));
    opts.status("BEGIN_SIGNING H10");
    opts.status(&format!(
        "SIG_CREATED {sig_type} {PK_ALGO_EDDSA} {HASH_ALGO_SHA512} 00 {} {fpr}",
        created.timestamp()
    ));
    Ok(0)
}

fn cmd_encrypt(opts: &Options) -> Result<i32> {
    let pubkey = load_public_key(opts)?;
    // Passeport has one identity; every recipient must resolve to it.
    for recipient in &opts.recipients {
        if !key_matches(&pubkey, recipient) {
            opts.status(&format!("INV_RECP 0 {recipient}"));
            bail!(
                "recipient '{recipient}' is not this identity — Passeport encrypts only to your own key"
            );
        }
    }
    let mut plaintext = Vec::new();
    std::io::stdin()
        .read_to_end(&mut plaintext)
        .context("failed to read plaintext from stdin")?;

    opts.status("BEGIN_ENCRYPTION 2 9");
    let output = pgp_sign::encrypt_to_self(&pubkey, &plaintext, "", opts.armor)?;
    write_output(opts, &output)?;
    opts.status("END_ENCRYPTION");
    Ok(0)
}

fn cmd_decrypt(opts: &Options) -> Result<i32> {
    let ciphertext = match opts.positionals.first() {
        Some(path) => std::fs::read(path).with_context(|| format!("cannot read {path}"))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("failed to read the ciphertext from stdin")?;
            buf
        }
    };

    // Decryption needs the private key, so route it through the app (Touch
    // ID-gated); the seed never enters this process.
    let socket = std::env::var("PASSEPORT_SCD_SOCKET")
        .context("PASSEPORT_SCD_SOCKET is unset — is the Passeport app running?")?;
    let request = crate::ops::Request::PgpDecrypt {
        ciphertext,
        client: Some("gpg (passeport)".to_owned()),
        comment: Some("decrypt an OpenPGP message".to_owned()),
    };
    let plaintext = match crate::ops::call_socket(&socket, &request)? {
        crate::ops::Response::PgpDecrypt { plaintext, .. } => plaintext,
        crate::ops::Response::Error { error, .. } => {
            opts.status("DECRYPTION_FAILED");
            bail!(error);
        }
        other => bail!("unexpected bridge response: {other:?}"),
    };

    opts.status("BEGIN_DECRYPTION");
    opts.status("DECRYPTION_OKAY");
    opts.status("GOODMDC");
    write_output(opts, &plaintext)?;
    opts.status("END_DECRYPTION");
    Ok(0)
}

fn cmd_help() -> Result<i32> {
    print!("{HELP_TEXT}");
    Ok(0)
}

fn cmd_verify(opts: &Options) -> Result<i32> {
    let pubkey = load_public_key(opts)?;

    // git passes: --verify <sigfile> -   (payload on stdin)
    let sigfile = opts
        .positionals
        .first()
        .context("--verify needs a signature file argument")?;
    let sig = std::fs::read(sigfile).with_context(|| format!("cannot read {sigfile}"))?;
    let payload = match opts.positionals.get(1) {
        Some(path) if path != "-" => {
            std::fs::read(path).with_context(|| format!("cannot read {path}"))?
        }
        _ => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("failed to read signed data from stdin")?;
            buf
        }
    };

    let (lines, human, code) = verify_status(&pubkey, &sig, &payload)?;
    for line in lines {
        opts.status(&line);
    }
    eprintln!("gpg: {human}");
    Ok(code)
}

/// Pure verify logic: produce the `[GNUPG:]` status lines, a human message, and
/// the exit code. Split out so it can be unit-tested without a real fd or app.
fn verify_status(
    pubkey: &SignedPublicKey,
    sig: &[u8],
    payload: &[u8],
) -> Result<(Vec<String>, String, i32)> {
    let mut lines = vec!["NEWSIG".to_owned()];
    match pgp_sign::verify_detached(pubkey, sig, payload)? {
        VerifyOutcome::Good {
            key_id,
            fingerprint,
            created,
            user_id,
        } => {
            let ts = created.map(|c| c.timestamp()).unwrap_or(0);
            let date = created
                .map(|c| c.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "1970-01-01".to_owned());
            lines.push(format!("GOODSIG {key_id} {user_id}"));
            lines.push(format!(
                "VALIDSIG {fingerprint} {date} {ts} 0 4 0 {PK_ALGO_EDDSA} {HASH_ALGO_SHA512} 00 {fingerprint}"
            ));
            lines.push("TRUST_ULTIMATE 0 pgp".to_owned());
            Ok((lines, format!("Good signature from \"{user_id}\""), 0))
        }
        VerifyOutcome::Bad { key_id, .. } => {
            lines.push(format!("BADSIG {key_id} Passeport"));
            Ok((lines, "BAD signature".to_owned(), 1))
        }
        VerifyOutcome::ForeignKey { key_id } => {
            lines.push(format!(
                "ERRSIG {key_id} {PK_ALGO_EDDSA} {HASH_ALGO_SHA512} 00 0 9 -"
            ));
            lines.push(format!("NO_PUBKEY {key_id}"));
            Ok((
                lines,
                "Can't check signature: No public key (Passeport verifies only its own identity)"
                    .to_owned(),
                1,
            ))
        }
    }
}

fn cmd_export(opts: &Options) -> Result<i32> {
    let pubkey = load_public_key(opts)?;
    let armored = pubkey
        .to_armored_string(None.into())
        .context("failed to armor the public key")?;
    write_output(opts, armored.as_bytes())?;
    Ok(0)
}

fn cmd_list_keys(opts: &Options) -> Result<i32> {
    let pubkey = load_public_key(opts)?;
    if !opts.with_colons {
        // Human listing is display-only; tools use --with-colons.
        let fpr = hex_upper(pubkey.primary_key.fingerprint().as_bytes());
        println!("pub   ed25519 {fpr}");
        for user in &pubkey.details.users {
            println!("uid   {}", user.id.id());
        }
        return Ok(0);
    }
    print!("{}", colon_listing(&pubkey, opts.list_secret));
    Ok(0)
}

fn cmd_fingerprint(opts: &Options) -> Result<i32> {
    let pubkey = load_public_key(opts)?;
    println!(
        "Primary key fingerprint: {}",
        hex_upper(pubkey.primary_key.fingerprint().as_bytes())
    );
    Ok(0)
}

fn cmd_version() -> Result<i32> {
    // A plausible banner so presence-checks and version greps succeed. Passeport
    // is not GnuPG, but tools key off the "gpg (GnuPG) 2.x" line.
    println!("gpg (GnuPG) 2.4.0");
    println!("This is the Passeport self-contained OpenPGP signer (Mode 2).");
    println!("Home: {}", home_dir_display());
    println!("Supported algorithms:");
    println!("Pubkey: EDDSA, ECDH");
    println!("Hash: SHA256, SHA512");
    Ok(0)
}

// MARK: - Colon listing

fn colon_listing(pubkey: &SignedPublicKey, secret: bool) -> String {
    let mut out = String::new();
    let created = pubkey.primary_key.created_at().timestamp();
    let primary_fpr = hex_upper(pubkey.primary_key.fingerprint().as_bytes());
    let primary_keyid = hex_upper(pubkey.primary_key.key_id().as_ref());

    let (primary_rec, sub_rec) = if secret {
        ("sec", "ssb")
    } else {
        ("pub", "sub")
    };
    // Primary: Ed25519 (algo 22), sign+certify.
    out.push_str(&format!(
        "{primary_rec}:u:255:22:{primary_keyid}:{created}:::u:::scESC:::::ed25519:::0:\n"
    ));
    out.push_str(&format!("fpr:::::::::{primary_fpr}:\n"));
    for user in &pubkey.details.users {
        out.push_str(&format!(
            "uid:u::::{created}::0000000000000000::{}::::::::::0:\n",
            escape_colons(&user.id.id().to_string())
        ));
    }
    for sub in &pubkey.public_subkeys {
        let algo = sub.key.algorithm();
        // ECDH encrypt subkey (18/cv25519) vs Ed25519 auth subkey (22/ed25519).
        let (algo_num, curve, caps) = match algo {
            pgp::crypto::public_key::PublicKeyAlgorithm::ECDH => ("18", "cv25519", "e"),
            _ => ("22", "ed25519", "a"),
        };
        let sub_keyid = hex_upper(sub.key.key_id().as_ref());
        let sub_fpr = hex_upper(sub.key.fingerprint().as_bytes());
        let sub_created = sub.key.created_at().timestamp();
        out.push_str(&format!(
            "{sub_rec}:u:255:{algo_num}:{sub_keyid}:{sub_created}::::::{caps}:::::{curve}::\n"
        ));
        out.push_str(&format!("fpr:::::::::{sub_fpr}:\n"));
    }
    out
}

/// gpg colon field 10 escapes `:` and `\` in user-ID text.
fn escape_colons(text: &str) -> String {
    text.replace('\\', "\\x5c").replace(':', "\\x3a")
}

// MARK: - Helpers

/// Bridge the raw Ed25519 signing op to the running app (Touch ID / audit
/// gated). Returns the 64-byte signature over `data`.
fn bridge_sign(socket: &str, data: &[u8]) -> Result<Vec<u8>> {
    let request = crate::ops::Request::Sign {
        keyref: "OPENPGP.1".to_owned(),
        data: data.to_vec(),
        client: Some("git (passeport gpg)".to_owned()),
        comment: Some("sign a git commit or tag".to_owned()),
    };
    match crate::ops::call_socket(socket, &request)? {
        crate::ops::Response::Sign { sig, .. } => Ok(sig),
        crate::ops::Response::Error { error, .. } => bail!(error),
        other => bail!("unexpected bridge response: {other:?}"),
    }
}

/// Load our public key from `PASSEPORT_PGP_PUBKEY` (armored) or
/// `<GNUPGHOME>/passeport-pubkey.asc`, written by the Mode 2 configurator.
fn load_public_key(opts: &Options) -> Result<SignedPublicKey> {
    if let Ok(armored) = std::env::var("PASSEPORT_PGP_PUBKEY") {
        let (key, _) = SignedPublicKey::from_armor_single(armored.as_bytes())
            .context("PASSEPORT_PGP_PUBKEY is not a valid armored public key")?;
        return Ok(key);
    }
    let home = opts
        .homedir
        .clone()
        .map(PathBuf::from)
        .or_else(|| std::env::var("GNUPGHOME").ok().map(PathBuf::from))
        .context("no --homedir/GNUPGHOME set and PASSEPORT_PGP_PUBKEY is unset")?;
    let path = home.join("passeport-pubkey.asc");
    let armored = std::fs::read(&path)
        .with_context(|| format!("cannot read the Passeport public key at {}", path.display()))?;
    let (key, _) = SignedPublicKey::from_armor_single(armored.as_slice())
        .context("the stored Passeport public key is not valid")?;
    Ok(key)
}

/// Does `spec` (a -u/--local-user value) refer to our single identity? Accepts
/// a 40-hex fingerprint, 16/8-hex key-id, optional `0x` prefix and `!` suffix,
/// or a substring of a user-ID (e.g. an email).
fn key_matches(pubkey: &SignedPublicKey, spec: &str) -> bool {
    let want = spec
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim_end_matches('!')
        .to_ascii_uppercase();
    if want.is_empty() {
        return true;
    }
    let fpr = hex_upper(pubkey.primary_key.fingerprint().as_bytes());
    let keyid = hex_upper(pubkey.primary_key.key_id().as_ref());
    if fpr.ends_with(&want) || keyid.ends_with(&want) {
        return true;
    }
    pubkey
        .details
        .users
        .iter()
        .any(|u| u.id.id().to_string().to_ascii_uppercase().contains(&want))
}

fn write_output(opts: &Options, bytes: &[u8]) -> Result<()> {
    match &opts.output {
        Some(path) if path != "-" => {
            std::fs::write(path, bytes).with_context(|| format!("cannot write {path}"))
        }
        _ => {
            std::io::stdout()
                .write_all(bytes)
                .context("failed to write to stdout")?;
            std::io::stdout().flush().context("failed to flush stdout")
        }
    }
}

fn now_utc() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn home_dir_display() -> String {
    std::env::var("GNUPGHOME").unwrap_or_else(|_| "~/.gnupg".to_owned())
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

// MARK: - Argument parsing

#[derive(Default)]
struct Options {
    detach_sign: bool,
    sign: bool,
    verify: bool,
    export: bool,
    export_secret: bool,
    list_keys: bool,
    list_secret: bool,
    with_colons: bool,
    fingerprint: bool,
    version: bool,
    decrypt: bool,
    encrypt: bool,
    clearsign: bool,
    armor: bool,
    help: bool,
    recipients: Vec<String>,
    local_user: Option<String>,
    status_fd: Option<i32>,
    output: Option<String>,
    homedir: Option<String>,
    /// An explicitly recognized-but-unsupported command (import, edit, …).
    unsupported: Option<String>,
    positionals: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Options::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            if let Some(long) = arg.strip_prefix("--") {
                let (name, inline_val) = match long.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (long, None),
                };
                let mut take_val = |inline: Option<String>| -> Result<String> {
                    if let Some(v) = inline {
                        Ok(v)
                    } else {
                        iter.next()
                            .cloned()
                            .with_context(|| format!("--{name} requires a value"))
                    }
                };
                match name {
                    "detach-sign" => opts.detach_sign = true,
                    "sign" => opts.sign = true,
                    "verify" => opts.verify = true,
                    "armor" => opts.armor = true,
                    "clear-sign" | "clearsign" => opts.clearsign = true,
                    "help" => opts.help = true,
                    "export" => opts.export = true,
                    "export-secret-keys" | "export-secret-subkeys" => opts.export_secret = true,
                    "list-keys" | "list-public-keys" | "list-sigs" => opts.list_keys = true,
                    "list-secret-keys" => opts.list_secret = true,
                    "with-colons" => opts.with_colons = true,
                    "fingerprint" => opts.fingerprint = true,
                    "version" | "dump-options" => opts.version = true,
                    "decrypt" => opts.decrypt = true,
                    "encrypt" => opts.encrypt = true,
                    "local-user" | "default-key" => opts.local_user = Some(take_val(inline_val)?),
                    "recipient" => opts.recipients.push(take_val(inline_val)?),
                    "status-fd" => opts.status_fd = Some(take_val(inline_val)?.parse()?),
                    "output" => opts.output = Some(take_val(inline_val)?),
                    "homedir" => opts.homedir = Some(take_val(inline_val)?),
                    // Value-taking flags we accept and ignore.
                    "keyid-format" | "digest-algo" | "cert-digest-algo" | "compress-algo"
                    | "passphrase" | "passphrase-fd" | "pinentry-mode" | "trust-model"
                    | "display-charset" | "logger-fd" | "attribute-fd" | "status-file" => {
                        let _ = take_val(inline_val)?;
                    }
                    // Recognized-but-unsupported commands: refuse clearly.
                    "import"
                    | "recv-keys"
                    | "receive-keys"
                    | "refresh-keys"
                    | "locate-keys"
                    | "locate-external-keys"
                    | "send-keys"
                    | "edit-key"
                    | "sign-key"
                    | "lsign-key"
                    | "quick-sign-key"
                    | "delete-keys"
                    | "delete-secret-keys"
                    | "gen-key"
                    | "generate-key"
                    | "full-generate-key"
                    | "full-gen-key"
                    | "quick-gen-key"
                    | "quick-generate-key"
                    | "gen-revoke"
                    | "generate-revocation"
                    | "passwd"
                    | "change-passphrase"
                    | "card-status"
                    | "card-edit"
                    | "check-signatures"
                    | "check-sigs"
                    | "update-trustdb"
                    | "symmetric" => {
                        opts.unsupported = Some(name.to_owned());
                    }
                    // Boolean flags accepted as no-ops.
                    "no-tty"
                    | "batch"
                    | "no-batch"
                    | "yes"
                    | "quiet"
                    | "verbose"
                    | "no-verbose"
                    | "no-options"
                    | "utf8-strings"
                    | "no-armor"
                    | "textmode"
                    | "no-emit-version"
                    | "no-comments"
                    | "always-trust"
                    | "no-default-keyring"
                    | "no-auto-check-trustdb"
                    | "lock-never"
                    | "with-fingerprint"
                    | "with-keygrip"
                    | "with-subkey-fingerprint" => {}
                    other => {
                        // Tolerate unknown display-only flags rather than aborting
                        // when git/tooling adds a new one.
                        eprintln!("gpg: ignoring unknown option --{other}");
                    }
                }
            } else if arg.len() > 1 && arg.starts_with('-') && arg != "-" {
                // Clustered short options, e.g. -bsau <KEY>.
                let chars: Vec<char> = arg[1..].chars().collect();
                let mut idx = 0;
                while idx < chars.len() {
                    let c = chars[idx];
                    match c {
                        'b' => opts.detach_sign = true,
                        's' => opts.sign = true,
                        'a' => opts.armor = true,
                        'h' => opts.help = true,
                        'v' | 'q' => {}
                        'k' => opts.list_keys = true,
                        'K' => opts.list_secret = true,
                        'd' => opts.decrypt = true,
                        'e' => opts.encrypt = true,
                        'u' | 'r' | 'o' => {
                            // Option-argument: rest of the cluster, else next arg.
                            let rest: String = chars[idx + 1..].iter().collect();
                            let value = if !rest.is_empty() {
                                rest
                            } else {
                                iter.next()
                                    .cloned()
                                    .with_context(|| format!("-{c} requires a value"))?
                            };
                            match c {
                                'u' => opts.local_user = Some(value),
                                'o' => opts.output = Some(value),
                                'r' => opts.recipients.push(value),
                                _ => {}
                            }
                            break; // consumed the rest of the cluster
                        }
                        _ => {}
                    }
                    idx += 1;
                }
            } else {
                opts.positionals.push(arg.clone());
            }
        }
        Ok(opts)
    }

    /// Emit one `[GNUPG:] <msg>` line to the configured status fd, if any.
    fn status(&self, msg: &str) {
        let Some(fd) = self.status_fd else { return };
        let line = format!("[GNUPG:] {msg}\n");
        match fd {
            1 => {
                print!("{line}");
                let _ = std::io::stdout().flush();
            }
            2 => eprint!("{line}"),
            other => {
                // Write without taking ownership of the fd (don't close it).
                let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(other) });
                let _ = file.write_all(line.as_bytes());
                let _ = file.flush();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{self, SlotRole, SlotSecret};
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_pubkey_and_sig(message: &[u8]) -> (SignedPublicKey, String) {
        let uid = "Passeport Test <test@example.invalid>";
        let pgp_seed = *identity::derive_pgp_seed(&[7u8; 32]).unwrap();
        let materials = identity::slot_materials(&pgp_seed, uid).unwrap();
        let primary_seed = match &materials
            .iter()
            .find(|m| m.role == SlotRole::Sign)
            .unwrap()
            .secret
        {
            SlotSecret::Ed25519(seed) => **seed,
            _ => panic!("not ed25519"),
        };
        let public: SignedPublicKey = identity::generate_signed_key(&pgp_seed, uid)
            .unwrap()
            .into();
        let signer = pgp_sign::RemoteSigner::new(
            public.primary_key.clone(),
            Box::new(move |d: &[u8]| {
                Ok(SigningKey::from_bytes(&primary_seed)
                    .sign(d)
                    .to_bytes()
                    .to_vec())
            }),
        );
        let armored = pgp_sign::detached_sign(
            &signer,
            message,
            chrono::DateTime::from_timestamp(1_767_300_000, 0).unwrap(),
        )
        .unwrap();
        (public, armored)
    }

    #[test]
    fn verify_status_good_signature() {
        let message = b"a signed commit";
        let (pubkey, sig) = signed_pubkey_and_sig(message);
        let (lines, human, code) = verify_status(&pubkey, sig.as_bytes(), message).unwrap();
        assert_eq!(code, 0);
        assert_eq!(lines[0], "NEWSIG");
        assert!(lines.iter().any(|l| l.starts_with("GOODSIG ")));
        assert!(lines.iter().any(|l| l.starts_with("VALIDSIG ")));
        assert!(lines.iter().any(|l| l == "TRUST_ULTIMATE 0 pgp"));
        assert!(human.starts_with("Good signature"));
    }

    #[test]
    fn verify_status_bad_signature() {
        let (pubkey, sig) = signed_pubkey_and_sig(b"the original");
        let (lines, _human, code) = verify_status(&pubkey, sig.as_bytes(), b"tampered").unwrap();
        assert_eq!(code, 1);
        assert!(lines.iter().any(|l| l.starts_with("BADSIG ")));
        assert!(!lines.iter().any(|l| l.starts_with("GOODSIG ")));
    }

    #[test]
    fn parses_git_sign_cluster() {
        let args: Vec<String> = ["--status-fd=2", "-bsau", "0xDEADBEEF"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let opts = Options::parse(&args).unwrap();
        assert!(opts.detach_sign && opts.sign);
        assert_eq!(opts.status_fd, Some(2));
        assert_eq!(opts.local_user.as_deref(), Some("0xDEADBEEF"));
    }

    #[test]
    fn parses_git_verify() {
        let args: Vec<String> = [
            "--keyid-format=long",
            "--status-fd=1",
            "--verify",
            "sig.asc",
            "-",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = Options::parse(&args).unwrap();
        assert!(opts.verify);
        assert_eq!(opts.status_fd, Some(1));
        assert_eq!(
            opts.positionals,
            vec!["sig.asc".to_string(), "-".to_string()]
        );
    }

    #[test]
    fn key_matches_by_fingerprint_suffix_and_email() {
        let (pubkey, _) = signed_pubkey_and_sig(b"x");
        let fpr = hex_upper(pubkey.primary_key.fingerprint().as_bytes());
        assert!(key_matches(&pubkey, &fpr));
        assert!(key_matches(
            &pubkey,
            &format!("0x{}", &fpr[fpr.len() - 16..])
        ));
        assert!(key_matches(&pubkey, "test@example.invalid"));
        assert!(!key_matches(&pubkey, "someone-else@nowhere"));
    }

    #[test]
    fn refuses_secret_export_and_import() {
        let opts = Options::parse(&["--export-secret-keys".to_string()]).unwrap();
        assert!(opts.export_secret);
        assert!(dispatch(&opts).is_err());
        let opts = Options::parse(&["--import".to_string()]).unwrap();
        assert_eq!(opts.unsupported.as_deref(), Some("import"));
        assert!(dispatch(&opts).is_err());
    }
}

//! `age-plugin-passeport`: the age plugin v1 state machine.
//!
//! Two phases. `recipient-v1` (encryption) is self-contained — it wraps each
//! file key to the recipient's public key with no seed access. `identity-v1`
//! (decryption) asks the Passeport app bridge to perform the X25519 ECDH on
//! the encryption subkey (OPENPGP.2), which is Touch ID-gated, then opens the
//! file key locally.
//!
//! Wire format is age's stanza framing: `-> command args\n` followed by
//! base64 body wrapped at 64 columns and terminated by a short (<64) line.

use std::io::{BufRead, BufReader, Write};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use crate::age;
use crate::ops;

/// The stanza type this plugin emits and recognizes. Distinct from age's
/// native `X25519` so age routes decryption to us rather than trying it
/// itself (it can't — the scalar lives in the Secure Enclave).
const STANZA_TYPE: &str = "passeport-x25519";

pub fn run(mode: &str) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut io = StanzaIo::new(BufReader::new(stdin.lock()), stdout.lock());
    match mode {
        "recipient-v1" => recipient_v1(&mut io),
        // In production, decryption's ECDH goes to the app bridge (Touch
        // ID-gated). The function is injected so tests can exercise the full
        // protocol with a local scalar instead of the socket.
        "identity-v1" => identity_v1(&mut io, bridge_ecdh),
        other => bail!("unknown age-plugin state machine: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Encryption

fn recipient_v1<R: BufRead, W: Write>(io: &mut StanzaIo<R, W>) -> Result<()> {
    let mut recipients: Vec<[u8; 32]> = Vec::new();
    let mut file_keys: Vec<Vec<u8>> = Vec::new();

    loop {
        let stanza = io.read()?;
        match stanza.command.as_str() {
            "add-recipient" => {
                let arg = stanza.first_arg()?;
                recipients.push(age::decode_recipient(arg)?);
            }
            "add-identity" => {
                let arg = stanza.first_arg()?;
                // An identity used as a recipient encrypts to its own key.
                recipients.push(age::decode_identity(arg)?);
            }
            "wrap-file-key" => file_keys.push(stanza.body),
            "extension-labels" => {}
            "done" => break,
            // Unknown / grease commands: forward-compat requires ignoring them.
            _ => {}
        }
    }

    if recipients.is_empty() {
        io.write(&Stanza::message("error", &["internal"], b"no recipients"))?;
        io.write(&Stanza::done())?;
        return Ok(());
    }

    for (file_index, file_key) in file_keys.iter().enumerate() {
        for recipient in &recipients {
            let (share, body) = age::wrap_file_key(recipient, file_key)?;
            let share_b64 = STANDARD_NO_PAD.encode(share);
            let stanza = Stanza::message(
                "recipient-stanza",
                &[&file_index.to_string(), STANZA_TYPE, &share_b64],
                &body,
            );
            io.write(&stanza)?;
            io.expect_ok()?;
        }
    }
    io.write(&Stanza::done())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Decryption

fn identity_v1<R: BufRead, W: Write>(
    io: &mut StanzaIo<R, W>,
    ecdh: impl Fn(&[u8; 32]) -> Result<[u8; 32]>,
) -> Result<()> {
    let mut identities: Vec<[u8; 32]> = Vec::new();
    // Collected stanzas: (file_index, ephemeral_share, body).
    let mut stanzas: Vec<(usize, [u8; 32], Vec<u8>)> = Vec::new();

    loop {
        let stanza = io.read()?;
        match stanza.command.as_str() {
            "add-identity" => identities.push(age::decode_identity(stanza.first_arg()?)?),
            "recipient-stanza" => {
                if let Some(parsed) = parse_recipient_stanza(&stanza) {
                    stanzas.push(parsed);
                }
            }
            "done" => break,
            _ => {}
        }
    }

    if identities.is_empty() {
        io.write(&Stanza::message("error", &["identity", "0"], b"no identity"))?;
        io.write(&Stanza::done())?;
        return Ok(());
    }

    // First stanza we can open wins for each file index; age only needs one.
    let mut solved: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (file_index, share, body) in &stanzas {
        if solved.contains(file_index) {
            continue;
        }
        // One ECDH per stanza — the shared secret depends only on the share —
        // then try each identity: its public key salts the HKDF wrap key, so
        // a stanza encrypted to any of them must find its match here.
        let Ok(shared) = ecdh(share) else { continue };
        for recipient_public in &identities {
            let Ok(file_key) = age::unwrap_file_key(recipient_public, share, &shared, body) else {
                continue;
            };
            io.write(&Stanza::message("file-key", &[&file_index.to_string()], &file_key))?;
            io.expect_ok()?;
            solved.insert(*file_index);
            break;
        }
        // Unsolved stanzas are left silent; age reports "no identity matched"
        // if nothing opens. A per-stanza error would abort the other files.
    }
    io.write(&Stanza::done())?;
    Ok(())
}

fn parse_recipient_stanza(stanza: &Stanza) -> Option<(usize, [u8; 32], Vec<u8>)> {
    // args: <file_index> <type> <ephemeral_share_b64>
    if stanza.args.len() < 3 || stanza.args[1] != STANZA_TYPE {
        return None;
    }
    let file_index: usize = stanza.args[0].parse().ok()?;
    let share_bytes = STANDARD_NO_PAD.decode(&stanza.args[2]).ok()?;
    let share: [u8; 32] = share_bytes.try_into().ok()?;
    Some((file_index, share, stanza.body.clone()))
}

/// Ask the app bridge for `scalar · share` on OPENPGP.2. The bridge gates the
/// ECDH behind Touch ID / approval; the shared secret is all the plugin needs
/// to open the file key locally.
fn bridge_ecdh(share: &[u8; 32]) -> Result<[u8; 32]> {
    let path = std::env::var("PASSEPORT_SCD_SOCKET").unwrap_or_else(|_| default_socket_path());
    let request = ops::Request::Ecdh {
        keyref: "OPENPGP.2".to_owned(),
        point: share.to_vec(),
        client: Some("age (age-plugin-passeport)".to_owned()),
        comment: Some("decrypt an age file".to_owned()),
    };
    match ops::call_socket(&path, &request)? {
        ops::Response::Ecdh { shared, .. } => shared
            .try_into()
            .map_err(|_| anyhow::anyhow!("shared secret not 32 bytes")),
        ops::Response::Error { error, .. } => bail!(error),
        other => bail!("unexpected ecdh response: {other:?}"),
    }
}

fn default_socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/Library/Application Support/Passeport/scd.sock")
}

// ---------------------------------------------------------------------------
// Stanza framing

struct Stanza {
    command: String,
    args: Vec<String>,
    body: Vec<u8>,
}

impl Stanza {
    fn message(command: &str, args: &[&str], body: &[u8]) -> Stanza {
        Stanza {
            command: command.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            body: body.to_vec(),
        }
    }

    fn done() -> Stanza {
        Stanza::message("done", &[], &[])
    }

    fn first_arg(&self) -> Result<&str> {
        self.args.first().map(String::as_str).context("stanza missing argument")
    }
}

struct StanzaIo<R: BufRead, W: Write> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> StanzaIo<R, W> {
    fn new(reader: R, writer: W) -> Self {
        StanzaIo { reader, writer }
    }

    fn read(&mut self) -> Result<Stanza> {
        let mut header = String::new();
        if self.reader.read_line(&mut header)? == 0 {
            bail!("unexpected end of input from age");
        }
        let header = header.trim_end_matches(['\r', '\n']);
        let header = header.strip_prefix("-> ").unwrap_or(header);
        let mut parts = header.split(' ').map(str::to_owned);
        let command = parts.next().unwrap_or_default();
        let args: Vec<String> = parts.collect();

        // Body: full 64-char base64 lines until a line shorter than 64.
        let mut encoded = String::new();
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            encoded.push_str(line);
            if line.len() < 64 {
                break;
            }
        }
        let body = if encoded.is_empty() {
            Vec::new()
        } else {
            STANDARD_NO_PAD.decode(&encoded).context("invalid base64 body from age")?
        };
        Ok(Stanza { command, args, body })
    }

    fn write(&mut self, stanza: &Stanza) -> Result<()> {
        let mut line = String::from("-> ");
        line.push_str(&stanza.command);
        for arg in &stanza.args {
            line.push(' ');
            line.push_str(arg);
        }
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;

        let encoded = STANDARD_NO_PAD.encode(&stanza.body);
        // Wrap at 64 columns; a body whose length is a multiple of 64 needs a
        // trailing empty line so the reader sees a terminating short line.
        let mut wrote_short = false;
        for chunk in encoded.as_bytes().chunks(64) {
            self.writer.write_all(chunk)?;
            self.writer.write_all(b"\n")?;
            wrote_short = chunk.len() < 64;
        }
        if !wrote_short {
            self.writer.write_all(b"\n")?;
        }
        self.writer.flush()?;
        Ok(())
    }

    /// Read the client's acknowledgment of a response stanza.
    fn expect_ok(&mut self) -> Result<()> {
        let stanza = self.read()?;
        match stanza.command.as_str() {
            "ok" => Ok(()),
            "fail" => bail!("age rejected a stanza"),
            other => bail!("unexpected response from age: {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use x25519_dalek::{PublicKey, StaticSecret};

    /// Drive both phases end-to-end, simulating age's side of the protocol,
    /// with a local scalar standing in for the Touch ID-gated bridge ECDH.
    #[test]
    fn full_encrypt_then_decrypt_roundtrip() {
        let scalar = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&scalar).to_bytes();
        let recipient = age::encode_recipient(&recipient_public).unwrap();
        let identity = age::encode_identity(&recipient_public).unwrap();
        let file_key = [0x11u8; age::FILE_KEY_LEN];

        // --- recipient-v1: age asks the plugin to wrap the file key ---
        let mut enc_input = String::new();
        enc_input.push_str(&format!("-> add-recipient {recipient}\n\n"));
        enc_input.push_str("-> wrap-file-key\n");
        enc_input.push_str(&STANDARD_NO_PAD.encode(file_key));
        enc_input.push('\n');
        // age acks the plugin's recipient-stanza with `ok`.
        enc_input.push_str("-> done\n\n-> ok\n\n");

        let mut enc_output: Vec<u8> = Vec::new();
        {
            let mut io = StanzaIo::new(BufReader::new(enc_input.as_bytes()), &mut enc_output);
            recipient_v1(&mut io).unwrap();
        }

        // Pull the emitted stanza back out to feed the decrypt phase.
        let mut reader = StanzaIo::new(BufReader::new(&enc_output[..]), Vec::new());
        let stanza = reader.read().unwrap();
        assert_eq!(stanza.command, "recipient-stanza");
        assert_eq!(stanza.args[1], STANZA_TYPE);
        let share_b64 = stanza.args[2].clone();
        let body_b64 = STANDARD_NO_PAD.encode(&stanza.body);

        // --- identity-v1: age hands the stanza back to the plugin ---
        let mut dec_input = String::new();
        dec_input.push_str(&format!("-> add-identity {identity}\n\n"));
        dec_input.push_str(&format!("-> recipient-stanza 0 {STANZA_TYPE} {share_b64}\n"));
        dec_input.push_str(&body_b64);
        dec_input.push('\n');
        dec_input.push_str("-> done\n\n-> ok\n\n");

        let mut dec_output: Vec<u8> = Vec::new();
        {
            let mut io = StanzaIo::new(BufReader::new(dec_input.as_bytes()), &mut dec_output);
            // Local stand-in for the bridge: scalar · share.
            let ecdh = |share: &[u8; 32]| {
                Ok(scalar.diffie_hellman(&PublicKey::from(*share)).to_bytes())
            };
            identity_v1(&mut io, ecdh).unwrap();
        }

        let mut out_reader = StanzaIo::new(BufReader::new(&dec_output[..]), Vec::new());
        let file_key_stanza = out_reader.read().unwrap();
        assert_eq!(file_key_stanza.command, "file-key");
        assert_eq!(file_key_stanza.args[0], "0");
        assert_eq!(file_key_stanza.body, file_key, "recovered file key must match");
    }

    /// A stanza encrypted to the *second* identity must still unwrap — the
    /// recipient public key salts the HKDF, so pinning identities[0] would
    /// make every other identity undecryptable.
    #[test]
    fn identity_v1_tries_every_identity() {
        let scalar = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let recipient_public = PublicKey::from(&scalar).to_bytes();
        let other_public =
            PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
        let file_key = [0x22u8; age::FILE_KEY_LEN];

        let (share, body) = age::wrap_file_key(&recipient_public, &file_key).unwrap();
        let share_b64 = STANDARD_NO_PAD.encode(share);
        let body_b64 = STANDARD_NO_PAD.encode(&body);

        let mut input = String::new();
        let decoy = age::encode_identity(&other_public).unwrap();
        let matching = age::encode_identity(&recipient_public).unwrap();
        input.push_str(&format!("-> add-identity {decoy}\n\n"));
        input.push_str(&format!("-> add-identity {matching}\n\n"));
        input.push_str(&format!("-> recipient-stanza 0 {STANZA_TYPE} {share_b64}\n"));
        input.push_str(&body_b64);
        input.push('\n');
        input.push_str("-> done\n\n-> ok\n\n");

        let mut output: Vec<u8> = Vec::new();
        {
            let mut io = StanzaIo::new(BufReader::new(input.as_bytes()), &mut output);
            let ecdh = |share: &[u8; 32]| {
                Ok(scalar.diffie_hellman(&PublicKey::from(*share)).to_bytes())
            };
            identity_v1(&mut io, ecdh).unwrap();
        }

        let mut reader = StanzaIo::new(BufReader::new(&output[..]), Vec::new());
        let stanza = reader.read().unwrap();
        assert_eq!(stanza.command, "file-key");
        assert_eq!(stanza.args[0], "0");
        assert_eq!(stanza.body, file_key, "recovered file key must match");
    }

    #[test]
    fn stanza_roundtrips_empty_and_multiple_of_64() {
        // 48 raw bytes -> 64 base64 chars, exercising the trailing-empty-line
        // rule; plus an empty body.
        for len in [0usize, 16, 48, 100] {
            let body: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let stanza = Stanza::message("recipient-stanza", &["0", STANZA_TYPE, "abc"], &body);
            let mut buffer: Vec<u8> = Vec::new();
            {
                let mut io = StanzaIo::new(&b""[..], &mut buffer);
                io.write(&stanza).unwrap();
            }
            let mut io = StanzaIo::new(BufReader::new(&buffer[..]), Vec::new());
            let parsed = io.read().unwrap();
            assert_eq!(parsed.command, "recipient-stanza");
            assert_eq!(parsed.args, vec!["0", STANZA_TYPE, "abc"]);
            assert_eq!(parsed.body, body, "body mismatch at len {len}");
        }
    }
}

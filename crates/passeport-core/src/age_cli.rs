//! Small, self-contained age CLI backed by the upstream `age` crate.
//!
//! Encryption uses only public recipients. Decryption sends the complete age
//! file to Passeport's bridge, where a short-lived gated op process derives the
//! cv25519 scalar and returns only plaintext.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::handoff::{DecryptHandoff, join_reader};
use crate::ops;

const HELP: &str = "\
Usage:
  age -e -r RECIPIENT [-r RECIPIENT ...] [-a] [-o OUTPUT] [INPUT]
  age -d [-i IDENTITY] [-o OUTPUT] [INPUT]

Options:
  -e, --encrypt              Encrypt to one or more standard age recipients
  -d, --decrypt              Decrypt through the running Passeport app
  -r, --recipient RECIPIENT  Standard X25519 recipient (age1...)
  -a, --armor                ASCII armor encrypted output
  -i, --identity PATH        Accepted for age compatibility; Passeport holds the identity
  -o, --output PATH          Write output to PATH (created without overwriting)
  -V, --version              Show the Passeport age CLI version
  -h, --help                 Show this help

INPUT and OUTPUT default to standard input and standard output. Use - explicitly
for either stream.
";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

struct Options {
    mode: Mode,
    recipients: Vec<String>,
    armor: bool,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
}

pub fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("age: {error:#}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-V" | "--version"))
    {
        println!("age (Passeport) {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        print!("{HELP}");
        return Ok(());
    }
    let options = parse_args(args)?;
    let input = read_input(options.input.as_ref())?;

    // Finish the crypto operation before creating a named output file, so a
    // bad recipient, corrupt ciphertext, or denied approval leaves no empty or
    // partial file behind.
    let result = match options.mode {
        Mode::Encrypt => {
            let mut ciphertext = Vec::new();
            encrypt(&options.recipients, options.armor, &input, &mut ciphertext)?;
            ciphertext
        }
        Mode::Decrypt => {
            if options.armor {
                bail!("--armor can only be used with --encrypt");
            }
            decrypt_via_bridge(&input)?
        }
    };
    let mut output = open_output(options.output.as_ref())?;
    output
        .write_all(&result)
        .context("failed to write output")?;
    output.flush().context("failed to flush output")?;
    Ok(())
}

fn parse_args(args: &[String]) -> Result<Options> {
    let mut mode = None;
    let mut recipients = Vec::new();
    let mut armor = false;
    let mut input = None;
    let mut output = None;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "-e" | "--encrypt" => set_mode(&mut mode, Mode::Encrypt)?,
            "-d" | "--decrypt" => set_mode(&mut mode, Mode::Decrypt)?,
            "-a" | "--armor" => armor = true,
            "-r" | "--recipient" => {
                index += 1;
                recipients.push(take_value(args, index, "recipient")?.to_owned());
            }
            "-o" | "--output" => {
                index += 1;
                let value = take_value(args, index, "output path")?;
                output = (value != "-").then(|| PathBuf::from(value));
            }
            "-i" | "--identity" => {
                // Passeport's secret identity is never stored in this file;
                // consume the conventional argument for drop-in compatibility.
                index += 1;
                let _ = take_value(args, index, "identity path")?;
            }
            "--" => {
                index += 1;
                while index < args.len() {
                    set_input(&mut input, &args[index])?;
                    index += 1;
                }
                break;
            }
            value if value.starts_with('-') && value != "-" => bail!("unknown option: {value}"),
            value => set_input(&mut input, value)?,
        }
        index += 1;
    }

    let mode = mode.context("choose exactly one of --encrypt or --decrypt")?;
    match mode {
        Mode::Encrypt if recipients.is_empty() => bail!("encryption requires --recipient"),
        Mode::Decrypt if !recipients.is_empty() => {
            bail!("--recipient cannot be used with --decrypt")
        }
        _ => {}
    }
    Ok(Options {
        mode,
        recipients,
        armor,
        input,
        output,
    })
}

fn set_mode(mode: &mut Option<Mode>, new_mode: Mode) -> Result<()> {
    if mode.replace(new_mode).is_some() {
        bail!("choose exactly one of --encrypt or --decrypt");
    }
    Ok(())
}

fn set_input(input: &mut Option<PathBuf>, value: &str) -> Result<()> {
    if input.is_some() {
        bail!("only one input file is supported");
    }
    if value != "-" {
        *input = Some(PathBuf::from(value));
    }
    Ok(())
}

fn take_value<'a>(args: &'a [String], index: usize, what: &str) -> Result<&'a str> {
    args.get(index)
        .map(String::as_str)
        .with_context(|| format!("missing {what}"))
}

fn read_input(path: Option<&PathBuf>) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    match path {
        Some(path) => File::open(path)
            .with_context(|| format!("cannot open input {}", path.display()))?
            .read_to_end(&mut data)
            .context("failed to read input")?,
        None => io::stdin()
            .lock()
            .read_to_end(&mut data)
            .context("failed to read standard input")?,
    };
    Ok(data)
}

fn open_output(path: Option<&PathBuf>) -> Result<Box<dyn Write>> {
    match path {
        Some(path) => Ok(Box::new(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("cannot create output {}", path.display()))?,
        )),
        None => Ok(Box::new(io::stdout())),
    }
}

fn encrypt(
    encoded_recipients: &[String],
    armor: bool,
    plaintext: &[u8],
    output: &mut dyn Write,
) -> Result<()> {
    let recipients: Vec<age_lib::x25519::Recipient> = encoded_recipients
        .iter()
        .map(|encoded| {
            encoded
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid recipient {encoded:?}: {error}"))
        })
        .collect::<Result<_>>()?;
    let encryptor = age_lib::Encryptor::with_recipients(
        recipients
            .iter()
            .map(|recipient| recipient as &dyn age_lib::Recipient),
    )
    .context("failed to initialize age encryption")?;

    if armor {
        let armored =
            age_lib::armor::ArmoredWriter::wrap_output(output, age_lib::armor::Format::AsciiArmor)?;
        let mut writer = encryptor.wrap_output(armored)?;
        writer.write_all(plaintext)?;
        writer.finish()?.finish()?;
    } else {
        let mut writer = encryptor.wrap_output(output)?;
        writer.write_all(plaintext)?;
        writer.finish()?;
    }
    Ok(())
}

fn decrypt_via_bridge(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let handoff = DecryptHandoff::create("passeport-age-", ciphertext)?;
    let reader = handoff.start_reader();

    let path = std::env::var("PASSEPORT_SCD_SOCKET").unwrap_or_else(|_| default_socket_path());
    let request = ops::Request::AgeDecrypt {
        ciphertext_path: handoff.ciphertext_path(),
        plaintext_path: handoff.plaintext_path(),
        client: Some("age (Passeport native CLI)".to_owned()),
        comment: Some("decrypt an age file".to_owned()),
    };
    match ops::call_socket(&path, &request) {
        Ok(ops::Response::AgeDecrypt { .. }) => join_reader(reader),
        Ok(ops::Response::Error { error, .. }) => {
            handoff.cancel_reader();
            let _ = join_reader(reader);
            bail!(error)
        }
        Ok(other) => {
            handoff.cancel_reader();
            let _ = join_reader(reader);
            bail!("unexpected age decrypt response: {other:?}")
        }
        Err(error) => {
            handoff.cancel_reader();
            let _ = join_reader(reader);
            Err(error)
        }
    }
}

fn default_socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/Library/Application Support/Passeport/scd.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_is_standard_age_and_supports_armor() {
        let identity = age_lib::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        for armor in [false, true] {
            let mut ciphertext = Vec::new();
            encrypt(
                std::slice::from_ref(&recipient),
                armor,
                b"passeport age test",
                &mut ciphertext,
            )
            .unwrap();
            let plaintext = age_lib::decrypt(&identity, &ciphertext).unwrap();
            assert_eq!(plaintext, b"passeport age test");
        }
    }

    #[test]
    fn parser_requires_one_mode_and_recipient_for_encrypt() {
        assert!(parse_args(&["-e".into()]).is_err());
        assert!(parse_args(&["-d".into(), "-e".into(), "-r".into(), "age1bad".into()]).is_err());
        assert!(parse_args(&["-d".into(), "-i".into(), "identity.txt".into()]).is_ok());
    }
}

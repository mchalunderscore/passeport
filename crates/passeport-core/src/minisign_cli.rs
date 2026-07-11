//! A self-contained `minisign` CLI for the Passeport identity — one command for
//! both signing and verifying.
//!
//! Signing uses the seed-derived minisign key and is delegated to the app over
//! the bridge (approval-controlled); verification is fully public and works on ANY
//! minisign/rsign signature, not just ours. There is no key generation: the key
//! is derived from the Passeport seed (use `-R` to print your public key).

use anyhow::{Context, Result, bail};

use crate::minisign;

const HELP_TEXT: &str = "\
Passeport minisign — sign and verify with your seed-derived minisign key.

  -S -m FILE [-x SIG] [-c COMMENT] [-t TRUSTED]   sign FILE (app-approved)
  -V -m FILE [-x SIG] [-p PUBKEY | -P PUBKEYSTR]  verify a signature
  -R [-p OUT]                                     print your public key

Notes:
  Verification works on any minisign/rsign signature.
  Key generation (-G) is unavailable: your key comes from your Passeport seed.
";

/// Entry point: parse minisign-style argv and return a process exit code.
pub fn run(args: &[String]) -> i32 {
    match dispatch(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("minisign: {error:#}");
            1
        }
    }
}

fn dispatch(args: &[String]) -> Result<i32> {
    let opts = Options::parse(args)?;
    if opts.help {
        print!("{HELP_TEXT}");
        return Ok(0);
    }
    if opts.generate {
        bail!(
            "key generation is not supported — your minisign key is derived from your Passeport seed (use -R to print your public key)"
        );
    }
    if opts.sign {
        return cmd_sign(&opts);
    }
    if opts.verify {
        return cmd_verify(&opts);
    }
    if opts.recreate {
        return cmd_recreate(&opts);
    }
    bail!(
        "no operation — use -S to sign, -V to verify, -R to show your public key, or -h for help"
    );
}

fn cmd_sign(opts: &Options) -> Result<i32> {
    let path = opts
        .input_file()
        .context("signing needs a file: minisign -Sm <file>")?;
    let data = std::fs::read(&path).with_context(|| format!("cannot read {path}"))?;
    let prehash = minisign::prehash(&data);

    let socket = std::env::var("PASSEPORT_SCD_SOCKET")
        .context("PASSEPORT_SCD_SOCKET is unset — is the Passeport app running?")?;
    let request = crate::ops::Request::MinisignSign {
        prehash: prehash.to_vec(),
        trusted_comment: opts
            .trusted_comment
            .clone()
            .unwrap_or_else(|| default_trusted(&path)),
        untrusted_comment: opts
            .untrusted_comment
            .clone()
            .unwrap_or_else(|| "signature from passeport".to_owned()),
        client: Some("minisign (passeport)".to_owned()),
        comment: Some("create a minisign signature".to_owned()),
    };
    let signature_file = match crate::ops::call_socket(&socket, &request)? {
        crate::ops::Response::Minisign { signature_file, .. } => signature_file,
        crate::ops::Response::Error { error, .. } => bail!(error),
        other => bail!("unexpected bridge response: {other:?}"),
    };

    let out = opts
        .sigfile
        .clone()
        .unwrap_or_else(|| format!("{path}.minisig"));
    std::fs::write(&out, signature_file).with_context(|| format!("cannot write {out}"))?;
    if !opts.quiet {
        eprintln!("wrote {out}");
    }
    Ok(0)
}

fn cmd_verify(opts: &Options) -> Result<i32> {
    let path = opts
        .input_file()
        .context("verification needs a file: minisign -Vm <file>")?;
    let data = std::fs::read(&path).with_context(|| format!("cannot read {path}"))?;
    let sigfile = opts
        .sigfile
        .clone()
        .unwrap_or_else(|| format!("{path}.minisig"));
    let signature =
        std::fs::read_to_string(&sigfile).with_context(|| format!("cannot read {sigfile}"))?;

    let public_key = if let Some(file) = &opts.pubkey_file {
        std::fs::read_to_string(file).with_context(|| format!("cannot read {file}"))?
    } else if let Some(key) = &opts.pubkey_str {
        // -P gives the bare base64 public key; wrap it as a public-key file.
        format!("untrusted comment: minisign public key\n{}\n", key.trim())
    } else {
        stored_public_key()
            .context("no public key given (-p FILE or -P KEY) and no Passeport public key found")?
    };

    minisign::verify(&public_key, &signature, &data)?;
    if !opts.quiet {
        eprintln!("Signature and comment signature verified");
        if let Some(trusted) = trusted_comment_of(&signature) {
            eprintln!("Trusted comment: {trusted}");
        }
    }
    Ok(0)
}

fn cmd_recreate(opts: &Options) -> Result<i32> {
    let public_key = stored_public_key()
        .context("no Passeport public key found — set up minisign signing in the app first")?;
    match &opts.pubkey_file {
        Some(path) => {
            std::fs::write(path, &public_key).with_context(|| format!("cannot write {path}"))?
        }
        None => print!("{public_key}"),
    }
    Ok(0)
}

/// Our own public key, written by the app and pointed at by the wrapper.
fn stored_public_key() -> Option<String> {
    let path = std::env::var("PASSEPORT_MINISIGN_PUBKEY").ok()?;
    std::fs::read_to_string(path).ok()
}

fn default_trusted(path: &str) -> String {
    let file = std::path::Path::new(path)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("timestamp:{ts}\tfile:{file}")
}

fn trusted_comment_of(signature: &str) -> Option<&str> {
    signature
        .lines()
        .find_map(|l| l.strip_prefix("trusted comment: "))
}

#[derive(Default)]
struct Options {
    sign: bool,
    verify: bool,
    recreate: bool,
    generate: bool,
    help: bool,
    quiet: bool,
    message: Option<String>,
    sigfile: Option<String>,
    pubkey_file: Option<String>,
    pubkey_str: Option<String>,
    untrusted_comment: Option<String>,
    trusted_comment: Option<String>,
    positionals: Vec<String>,
}

impl Options {
    fn input_file(&self) -> Option<String> {
        self.message
            .clone()
            .or_else(|| self.positionals.first().cloned())
    }

    fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Options::default();
        let mut iter = args.iter().peekable();
        while let Some(arg) = iter.next() {
            if arg == "--help" {
                opts.help = true;
                continue;
            }
            if let Some(long) = arg.strip_prefix("--") {
                match long {
                    "quiet" => opts.quiet = true,
                    other => eprintln!("minisign: ignoring unknown option --{other}"),
                }
                continue;
            }
            let Some(short) = arg.strip_prefix('-') else {
                opts.positionals.push(arg.clone());
                continue;
            };
            if short.is_empty() {
                opts.positionals.push(arg.clone());
                continue;
            }
            let chars: Vec<char> = short.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                let c = chars[i];
                match c {
                    'S' => opts.sign = true,
                    'V' => opts.verify = true,
                    'R' => opts.recreate = true,
                    'G' => opts.generate = true,
                    'h' => opts.help = true,
                    'q' | 'Q' => opts.quiet = true,
                    'H' | 'o' => {} // prehash / older-format: accepted, no-op
                    // Value-taking options: value is the rest of the cluster or the next arg.
                    'm' | 'x' | 'p' | 'P' | 's' | 'c' | 't' => {
                        let rest: String = chars[i + 1..].iter().collect();
                        let value = if rest.is_empty() {
                            iter.next()
                                .cloned()
                                .with_context(|| format!("-{c} requires a value"))?
                        } else {
                            rest
                        };
                        match c {
                            'm' => opts.message = Some(value),
                            'x' => opts.sigfile = Some(value),
                            'p' => opts.pubkey_file = Some(value),
                            'P' => opts.pubkey_str = Some(value),
                            's' => {} // secret-key file: the key lives in the app, ignore
                            'c' => opts.untrusted_comment = Some(value),
                            't' => opts.trusted_comment = Some(value),
                            _ => {}
                        }
                        break; // consumed the rest of the cluster as the value
                    }
                    other => eprintln!("minisign: ignoring unknown flag -{other}"),
                }
                i += 1;
            }
        }
        Ok(opts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sign_cluster() {
        let opts =
            Options::parse(&["-Sm".into(), "file.txt".into(), "-t".into(), "hi".into()]).unwrap();
        assert!(opts.sign);
        assert_eq!(opts.message.as_deref(), Some("file.txt"));
        assert_eq!(opts.trusted_comment.as_deref(), Some("hi"));
    }

    #[test]
    fn parses_verify_with_pubkey() {
        let opts = Options::parse(&[
            "-V".into(),
            "-m".into(),
            "f".into(),
            "-p".into(),
            "key.pub".into(),
        ])
        .unwrap();
        assert!(opts.verify);
        assert_eq!(opts.pubkey_file.as_deref(), Some("key.pub"));
    }

    #[test]
    fn generate_is_refused() {
        assert!(dispatch(&["-G".into()]).is_err());
    }

    #[test]
    fn value_flags_require_values() {
        for flag in ["-m", "-x", "-p", "-P", "-c", "-t"] {
            assert!(
                Options::parse(&[flag.into()]).is_err(),
                "{flag} accepted no value"
            );
        }
    }

    #[test]
    fn input_prefers_explicit_message_over_positional() {
        let opts = Options::parse(&["positional".into(), "-m".into(), "explicit".into()]).unwrap();
        assert_eq!(opts.input_file().as_deref(), Some("explicit"));
    }

    #[test]
    fn trusted_comment_parser_ignores_untrusted_and_malformed_lines() {
        assert_eq!(
            trusted_comment_of("untrusted comment: x\ntrusted comment: safe\nabc"),
            Some("safe")
        );
        assert_eq!(trusted_comment_of("trusted comment:safe"), None);
    }
}

//! Virtual OpenPGP smartcard speaking the scdaemon Assuan protocol.
//!
//! gpg-agent spawns this (via `scdaemon-program`) and talks Assuan over
//! stdio. We present a card whose three slots hold the Passeport identity:
//! OPENPGP.1 = primary (sign+certify), OPENPGP.2 = encryption subkey,
//! OPENPGP.3 = authentication subkey.
//!
//! Private operations are delegated to a [`CryptoBackend`]. In production the
//! backend is a Unix socket to the running Passeport app, which owns the seed
//! and applies the app's approval policy — the shim never sees key material. For
//! development, `PASSEPORT_SCD_PRF` selects an in-process backend.

use std::cell::Cell;
use std::io::{BufRead, BufReader, Write};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::identity::{self, KEY_CREATION_EPOCH, SlotRole};
use crate::ops::{self, Request, Response, SlotPublic};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// gpg-error style codes: GPG_ERR_SOURCE_SCD (6) << 24 | code. Numeric values
// verified with the gpg-error(1) tool.
const ERR_UNKNOWN_COMMAND: u32 = (6 << 24) | 275; // GPG_ERR_ASS_UNKNOWN_CMD
const ERR_NOT_SUPPORTED: u32 = (6 << 24) | 60;
const ERR_INV_DATA: u32 = (6 << 24) | 79;
const ERR_NO_SECKEY: u32 = (6 << 24) | 17;
const ERR_NOT_FOUND: u32 = (6 << 24) | 27;

pub fn serve() -> Result<()> {
    let backend = backend_from_env()?;
    let card = Card::build(backend)?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve_io(&card, BufReader::new(stdin.lock()), stdout.lock())
}

fn backend_from_env() -> Result<Box<dyn CryptoBackend>> {
    if let Ok(path) = std::env::var("PASSEPORT_SCD_SOCKET") {
        return Ok(Box::new(SocketBackend { path }));
    }
    if let Ok(prf_b64) = std::env::var("PASSEPORT_SCD_PRF") {
        let user_id = std::env::var("PASSEPORT_SCD_USER_ID")
            .unwrap_or_else(|_| "Passeport <passeport@localhost>".to_owned());
        let prf = identity::decode_prf(&prf_b64)?;
        let seed = identity::derive_pgp_seed(&prf)?;
        return Ok(Box::new(LocalBackend { seed, user_id }));
    }
    bail!("no key source: set PASSEPORT_SCD_SOCKET (app bridge) or PASSEPORT_SCD_PRF (dev)")
}

// ---------------------------------------------------------------------------
// Crypto backends

/// The source of private-key operations behind the card.
trait CryptoBackend {
    fn slots(&self) -> Result<Vec<SlotPublic>>;
    fn sign(&self, keyref: &str, data: &[u8]) -> Result<Vec<u8>>;
    fn ecdh(&self, keyref: &str, point: &[u8]) -> Result<Vec<u8>>;
}

/// In-process backend for development: holds the seed and derives on demand.
struct LocalBackend {
    seed: Zeroizing<[u8; 32]>,
    user_id: String,
}

impl LocalBackend {
    fn client_name() -> &'static str {
        "passeport-scd local"
    }

    fn request_comment(op: &str) -> &'static str {
        match op {
            "pubkeys" => "public card metadata",
            "sign" => "openpgp signature",
            "ecdh" => "ecdh session key exchange",
            _ => "private card operation",
        }
    }

    fn call(&self, request: &Request) -> Result<Response> {
        ops::handle(&self.seed, &self.user_id, request)
    }
}

impl CryptoBackend for LocalBackend {
    fn slots(&self) -> Result<Vec<SlotPublic>> {
        match self.call(&Request::Pubkeys {
            client: Some(Self::client_name().to_owned()),
            comment: Some(Self::request_comment("pubkeys").to_owned()),
        })? {
            Response::Pubkeys { slots, .. } => Ok(slots),
            other => bail!("unexpected pubkeys response: {other:?}"),
        }
    }

    fn sign(&self, keyref: &str, data: &[u8]) -> Result<Vec<u8>> {
        match self.call(&Request::Sign {
            keyref: keyref.to_owned(),
            data: data.to_vec(),
            client: Some(Self::client_name().to_owned()),
            comment: Some(match keyref {
                "OPENPGP.3" => "ssh authentication".to_owned(),
                _ => Self::request_comment("sign").to_owned(),
            }),
        })? {
            Response::Sign { sig, .. } => Ok(sig),
            Response::Error { error, .. } => bail!(error),
            other => bail!("unexpected sign response: {other:?}"),
        }
    }

    fn ecdh(&self, keyref: &str, point: &[u8]) -> Result<Vec<u8>> {
        match self.call(&Request::Ecdh {
            keyref: keyref.to_owned(),
            point: point.to_vec(),
            client: Some(Self::client_name().to_owned()),
            comment: Some(Self::request_comment("ecdh").to_owned()),
        })? {
            Response::Ecdh { shared, .. } => Ok(shared),
            Response::Error { error, .. } => bail!(error),
            other => bail!("unexpected ecdh response: {other:?}"),
        }
    }
}

/// Production backend: newline-delimited JSON over a Unix socket to the app.
struct SocketBackend {
    path: String,
}

impl SocketBackend {
    fn client_name() -> &'static str {
        "gpg-agent"
    }

    fn request_comment(op: &str) -> &'static str {
        match op {
            "pubkeys" => "public card metadata",
            "sign" => "openpgp signature",
            "ecdh" => "ecdh session key exchange",
            _ => "private card operation",
        }
    }

    fn call(&self, request: &Request) -> Result<Response> {
        ops::call_socket(&self.path, request)
    }
}

impl CryptoBackend for SocketBackend {
    fn slots(&self) -> Result<Vec<SlotPublic>> {
        match self.call(&Request::Pubkeys {
            client: Some(Self::client_name().to_owned()),
            comment: Some(Self::request_comment("pubkeys").to_owned()),
        })? {
            Response::Pubkeys { slots, .. } => Ok(slots),
            Response::Error { error, .. } => bail!(error),
            other => bail!("unexpected pubkeys response: {other:?}"),
        }
    }

    fn sign(&self, keyref: &str, data: &[u8]) -> Result<Vec<u8>> {
        match self.call(&Request::Sign {
            keyref: keyref.to_owned(),
            data: data.to_vec(),
            client: Some(Self::client_name().to_owned()),
            comment: Some(
                match keyref {
                    "OPENPGP.3" => "ssh authentication",
                    _ => Self::request_comment("sign"),
                }
                .to_owned(),
            ),
        })? {
            Response::Sign { sig, .. } => Ok(sig),
            Response::Error { error, .. } => bail!(error),
            other => bail!("unexpected sign response: {other:?}"),
        }
    }

    fn ecdh(&self, keyref: &str, point: &[u8]) -> Result<Vec<u8>> {
        match self.call(&Request::Ecdh {
            keyref: keyref.to_owned(),
            point: point.to_vec(),
            client: Some(Self::client_name().to_owned()),
            comment: Some(Self::request_comment("ecdh").to_owned()),
        })? {
            Response::Ecdh { shared, .. } => Ok(shared),
            Response::Error { error, .. } => bail!(error),
            other => bail!("unexpected ecdh response: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Card model

#[derive(Clone, Copy)]
enum CurveKind {
    Ed25519,
    Curve25519,
}

struct Slot {
    role: SlotRole,
    curve: CurveKind,
    fingerprint: Vec<u8>,
    keygrip: [u8; 20],
    /// Compressed public point, 0x40-prefixed (33 bytes).
    q: Vec<u8>,
}

impl Slot {
    fn keyref(&self) -> &'static str {
        self.role.keyref()
    }
}

struct Card {
    aid: Vec<u8>,
    slots: Vec<Slot>,
    backend: Box<dyn CryptoBackend>,
    /// Whether [`Card::slot_is_current`] has already confirmed the backend
    /// against this model. One check per session; see there for the tradeoff.
    verified: Cell<bool>,
}

impl Card {
    fn build(backend: Box<dyn CryptoBackend>) -> Result<Self> {
        let publics = backend.slots()?;
        let mut slots = Vec::with_capacity(publics.len());
        for public in &publics {
            let role = match public.role.as_str() {
                "sign" => SlotRole::Sign,
                "decrypt" => SlotRole::Decrypt,
                "auth" => SlotRole::Auth,
                other => bail!("unknown slot role: {other}"),
            };
            if public.q.len() != 33 || public.q[0] != 0x40 {
                bail!("bad public point for {}", public.keyref);
            }
            let raw = point32(&public.q)?;
            let (curve, keygrip) = match role {
                SlotRole::Decrypt => (CurveKind::Curve25519, keygrip::cv25519(&raw)),
                _ => (CurveKind::Ed25519, keygrip::ed25519(&raw)),
            };
            slots.push(Slot {
                role,
                curve,
                fingerprint: public.fpr.clone(),
                keygrip,
                q: public.q.clone(),
            });
        }
        let sign_fpr = &slots
            .iter()
            .find(|slot| matches!(slot.role, SlotRole::Sign))
            .context("no sign slot")?
            .fingerprint;

        // OpenPGP card AID: RID D276000124, app 01, version 3.4,
        // manufacturer 0xFFFE (test range), 4-byte serial, 2 reserved bytes.
        // The serial derives from the primary fingerprint, so every device
        // presents the same card.
        let mut aid = vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0xFF, 0xFE];
        let digest = Sha256::digest(sign_fpr);
        aid.extend_from_slice(&digest[..4]);
        aid.extend_from_slice(&[0x00, 0x00]);

        Ok(Card {
            aid,
            slots,
            backend,
            verified: Cell::new(false),
        })
    }

    fn aid_hex(&self) -> String {
        hex::encode_upper(&self.aid)
    }

    fn slot(&self, role: SlotRole) -> &Slot {
        self.slots
            .iter()
            .find(|slot| slot.role == role)
            .expect("all three slots exist")
    }

    /// Confirm the live backend still serves the keys this card model
    /// advertises. The model is a snapshot from startup, and the identity can
    /// change underneath it (seed reset/restore in the app); signing with a
    /// different key than the agent was promised produces signatures that can
    /// never verify.
    ///
    /// The check costs a full backend round trip (a fresh socket connect plus
    /// an audit-log write in the app, or a complete re-derivation locally), so
    /// it runs once per session and the verdict is memoized: the seed cannot
    /// change without the app restarting its bridge, which drops the socket
    /// and ends this session anyway. Nothing within a session re-reads the
    /// slot model, so there is no event to invalidate on.
    fn slot_is_current(&self, _role: SlotRole) -> Result<()> {
        if self.verified.get() {
            return Ok(());
        }
        // The fresh response carries every slot, so verify the whole model —
        // the memoized verdict then covers any role's later operation.
        let fresh = self.backend.slots()?;
        let all_current = self.slots.iter().all(|snapshot| {
            fresh
                .iter()
                .any(|public| public.keyref == snapshot.keyref() && public.q == snapshot.q)
        });
        if !all_current {
            bail!(
                "card identity changed since gpg-agent started; run `gpgconf --kill all` to reload"
            );
        }
        self.verified.set(true);
        Ok(())
    }

    fn find(&self, spec: &str) -> Option<&Slot> {
        let upper = spec.to_ascii_uppercase();
        self.slots.iter().find(|slot| {
            slot.keyref() == upper
                || hex::encode_upper(slot.keygrip) == upper
                || hex::encode_upper(&slot.fingerprint) == upper
        })
    }
}

fn point32(q: &[u8]) -> Result<[u8; 32]> {
    if q.len() != 33 || q[0] != 0x40 {
        bail!("unexpected compressed point encoding");
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&q[1..]);
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Keygrips (libgcrypt gcry_pk_get_keygrip for ECC keys)
//
// SHA-1 over the curve parameters and public point, each framed as an
// S-expression fragment "(1:<letter><len>:<raw bytes>)", in the order
// p, a, b, g, n, q. Values are MPI magnitudes (signs dropped, leading zeros
// stripped); g is the uncompressed point; q is the raw 32-byte point WITHOUT
// its 0x40 prefix for both Ed25519 and Curve25519. Verified byte-for-byte
// against `gpg --with-keygrip` (GnuPG 2.5.20 / libgcrypt 1.12.2).

mod keygrip {
    use sha1::{Digest, Sha1};

    struct CurveParams {
        p: &'static str,
        a: &'static str,
        b: &'static str,
        g: &'static str,
        n: &'static str,
    }

    // libgcrypt's Ed25519 table entry stores a = -0x01 and b = -d; keygrip
    // hashing uses the magnitudes.
    const ED25519: CurveParams = CurveParams {
        p: "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
        a: "01",
        b: "2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",
        g: "04\
            216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A\
            6666666666666666666666666666666666666666666666666666666666666658",
        n: "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
    };

    const CV25519: CurveParams = CurveParams {
        p: "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
        a: "01DB41",
        b: "01",
        g: "04\
            0000000000000000000000000000000000000000000000000000000000000009\
            20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
        n: "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
    };

    pub fn ed25519(public: &[u8; 32]) -> [u8; 20] {
        of(&ED25519, public)
    }

    pub fn cv25519(public: &[u8; 32]) -> [u8; 20] {
        of(&CV25519, public)
    }

    fn of(curve: &CurveParams, public: &[u8; 32]) -> [u8; 20] {
        let mut hasher = Sha1::new();
        for (letter, value) in [
            ('p', hex::decode(curve.p).unwrap()),
            ('a', hex::decode(curve.a).unwrap()),
            ('b', hex::decode(curve.b).unwrap()),
            ('g', hex::decode(curve.g).unwrap()),
            ('n', hex::decode(curve.n).unwrap()),
            ('q', public.to_vec()),
        ] {
            hasher.update(format!("(1:{}{}:", letter, value.len()).as_bytes());
            hasher.update(&value);
            hasher.update(b")");
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Assuan server

struct Session<'a, W: Write> {
    card: &'a Card,
    out: W,
    data: Vec<u8>,
}

fn serve_io<R: BufRead, W: Write>(card: &Card, input: R, out: W) -> Result<()> {
    let mut session = Session {
        card,
        out,
        data: Vec::new(),
    };
    session.line("OK Pleased to meet you")?;

    for line in input.lines() {
        let line = line.context("failed to read command")?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (command, args) = match line.split_once(' ') {
            Some((c, a)) => (c.to_ascii_uppercase(), a.trim()),
            None => (line.to_ascii_uppercase(), ""),
        };
        if command == "BYE" {
            session.line("OK closing connection")?;
            return Ok(());
        }
        session.dispatch(&command, args)?;
    }
    Ok(())
}

impl<W: Write> Session<'_, W> {
    fn dispatch(&mut self, command: &str, args: &str) -> Result<()> {
        match command {
            "NOP" | "RESET" | "RESTART" | "OPTION" | "CHECKPIN" | "SETATTR" => self.ok(),
            "GETINFO" => self.getinfo(args),
            "SERIALNO" => {
                let aid = self.card.aid_hex();
                self.status("SERIALNO", &aid)?;
                self.ok()
            }
            "LEARN" => self.learn(),
            "GETATTR" => self.getattr(args),
            "READKEY" => self.readkey(args),
            "KEYINFO" => self.keyinfo(args),
            "SETDATA" => self.setdata(args),
            "PKSIGN" => self.pksign(args),
            "PKAUTH" => self.pkauth(args),
            "PKDECRYPT" => self.pkdecrypt(args),
            // No certificate data objects on this card; the agent probes for
            // them during LEARN and treats Not-Found as benign.
            "READCERT" => self.err(ERR_NOT_FOUND, "No certificate"),
            "PASSWD" | "GENKEY" | "RANDOM" | "APDU" | "LOCK" | "UNLOCK" | "DISCONNECT" => {
                self.err(ERR_NOT_SUPPORTED, "Not supported")
            }
            _ => self.err(ERR_UNKNOWN_COMMAND, "Unknown command"),
        }
    }

    fn getinfo(&mut self, args: &str) -> Result<()> {
        match args {
            "version" => {
                self.data(format!("passeport-scd {APP_VERSION}").as_bytes())?;
                self.ok()
            }
            "pid" => {
                self.data(std::process::id().to_string().as_bytes())?;
                self.ok()
            }
            "status" => {
                self.data(b"u")?;
                self.ok()
            }
            "card_list" | "all_active_apps" => {
                let aid = self.card.aid_hex();
                self.status("SERIALNO", &aid)?;
                self.ok()
            }
            "apptype" | "active_apps" => {
                self.data(b"openpgp")?;
                self.ok()
            }
            _ => self.ok(),
        }
    }

    fn learn(&mut self) -> Result<()> {
        let aid = self.card.aid_hex();
        self.status("SERIALNO", &aid)?;
        self.status("APPTYPE", "openpgp")?;
        self.status(
            "EXTCAP",
            "gc=0+ki=0+fc=0+pd=0+mcl3=2560+aac=0+sm=0+si=0+dec=0+bt=0+kdf=0",
        )?;
        self.status("DISP-NAME", "Passeport")?;
        self.status("CHV-STATUS", "1 127 127 127 3 0 3")?;
        self.status("SIG-COUNTER", "0")?;

        for (index, slot) in self.card.slots.iter().enumerate() {
            let n = index + 1;
            self.status(
                "KEY-FPR",
                &format!("{n} {}", hex::encode_upper(&slot.fingerprint)),
            )?;
            self.status("KEY-TIME", &format!("{n} {KEY_CREATION_EPOCH}"))?;
            let (algo_id, algo_str) = match slot.curve {
                CurveKind::Curve25519 => (18, "cv25519"),
                CurveKind::Ed25519 => (22, "ed25519"),
            };
            self.status("KEY-ATTR", &format!("{n} {algo_id} {algo_str}"))?;
            let usage = match slot.role {
                SlotRole::Sign => "sc",
                SlotRole::Decrypt => "e",
                SlotRole::Auth => "a",
            };
            self.status(
                "KEYPAIRINFO",
                &format!(
                    "{} {} {usage} {KEY_CREATION_EPOCH} {algo_str}",
                    hex::encode_upper(slot.keygrip),
                    slot.keyref(),
                ),
            )?;
        }
        self.ok()
    }

    fn getattr(&mut self, args: &str) -> Result<()> {
        let aid = self.card.aid_hex();
        // Special $-attributes may carry a trailing keygrip argument.
        let attr = args.split_whitespace().next().unwrap_or("");
        match attr {
            "$DISPSERIALNO" => {
                let display = hex::encode_upper(&self.card.aid[10..14]);
                self.status("$DISPSERIALNO", &display)?;
                return self.ok();
            }
            "$SIGNKEYID" => {
                self.status("$SIGNKEYID", "OPENPGP.1")?;
                return self.ok();
            }
            "$ENCRKEYID" => {
                self.status("$ENCRKEYID", "OPENPGP.2")?;
                return self.ok();
            }
            "$AUTHKEYID" => {
                self.status("$AUTHKEYID", "OPENPGP.3")?;
                return self.ok();
            }
            _ => {}
        }
        match args {
            "SERIALNO" => self.status("SERIALNO", &aid)?,
            "APPTYPE" => self.status("APPTYPE", "openpgp")?,
            "EXTCAP" => self.status(
                "EXTCAP",
                "gc=0+ki=0+fc=0+pd=0+mcl3=2560+aac=0+sm=0+si=0+dec=0+bt=0+kdf=0",
            )?,
            "DISP-NAME" => self.status("DISP-NAME", "Passeport")?,
            "MANUFACTURER" => self.status("MANUFACTURER", "65534 unmanaged S/N range")?,
            "CHV-STATUS" => self.status("CHV-STATUS", "1 127 127 127 3 0 3")?,
            "SIG-COUNTER" => self.status("SIG-COUNTER", "0")?,
            "KEY-FPR" => {
                for (index, slot) in self.card.slots.iter().enumerate() {
                    let value = format!("{} {}", index + 1, hex::encode_upper(&slot.fingerprint));
                    self.status("KEY-FPR", &value)?;
                }
            }
            "KEY-TIME" => {
                for index in 0..self.card.slots.len() {
                    self.status("KEY-TIME", &format!("{} {KEY_CREATION_EPOCH}", index + 1))?;
                }
            }
            "KEY-ATTR" => {
                self.status("KEY-ATTR", "1 22 ed25519")?;
                self.status("KEY-ATTR", "2 18 cv25519")?;
                self.status("KEY-ATTR", "3 22 ed25519")?;
            }
            _ => {}
        }
        self.ok()
    }

    fn readkey(&mut self, args: &str) -> Result<()> {
        // Accept: READKEY [--format=advanced|--advanced] [--] <keyref|grip|fpr>
        let spec = args
            .split_whitespace()
            .find(|word| !word.starts_with("--"))
            .unwrap_or("");
        let Some(slot) = self.card.find(spec) else {
            return self.err(ERR_NO_SECKEY, "No such key");
        };
        let sexp = public_key_sexp(slot);
        self.data(&sexp)?;
        self.ok()
    }

    fn keyinfo(&mut self, args: &str) -> Result<()> {
        let aid = self.card.aid_hex();
        let list_arg = args
            .split_whitespace()
            .find(|word| word.starts_with("--list"));

        // `KEYINFO --list=<usage>` filters by capability. gpg-agent uses
        // `--list=auth` to enumerate ssh keys, so honoring it means only the
        // authentication key is offered over ssh — matching a real card,
        // instead of every signing-capable key.
        if let Some(arg) = list_arg {
            let role_filter: Option<SlotRole> = match arg.strip_prefix("--list=") {
                Some("sign") => Some(SlotRole::Sign),
                Some("encr") | Some("decrypt") => Some(SlotRole::Decrypt),
                Some("auth") | Some("ssh") => Some(SlotRole::Auth),
                _ => None, // bare `--list` or unknown filter: all keys
            };
            for slot in &self.card.slots {
                if role_filter.is_none_or(|role| slot.role == role) {
                    self.status(
                        "KEYINFO",
                        &format!(
                            "{} T {aid} {}",
                            hex::encode_upper(slot.keygrip),
                            slot.keyref()
                        ),
                    )?;
                }
            }
            return self.ok();
        }

        // No `--list`: look up a single key by keygrip.
        let spec = args
            .split_whitespace()
            .find(|word| !word.starts_with("--"))
            .unwrap_or("")
            .to_ascii_uppercase();
        let mut found = false;
        for slot in &self.card.slots {
            if hex::encode_upper(slot.keygrip) == spec {
                found = true;
                self.status(
                    "KEYINFO",
                    &format!(
                        "{} T {aid} {}",
                        hex::encode_upper(slot.keygrip),
                        slot.keyref()
                    ),
                )?;
            }
        }
        if !found {
            return self.err(ERR_NO_SECKEY, "No such key");
        }
        self.ok()
    }

    fn setdata(&mut self, args: &str) -> Result<()> {
        let (append, hex_data) = match args.strip_prefix("--append ") {
            Some(rest) => (true, rest.trim()),
            None => (false, args),
        };
        let Ok(bytes) = hex::decode(hex_data) else {
            return self.err(ERR_INV_DATA, "Invalid hex in SETDATA");
        };
        if !append {
            self.data.clear();
        }
        self.data.extend_from_slice(&bytes);
        self.ok()
    }

    fn pksign(&mut self, args: &str) -> Result<()> {
        let spec = args
            .split_whitespace()
            .find(|word| !word.starts_with("--"))
            .unwrap_or("");
        // A named key must exist on this card; silently falling back to the
        // sign slot would produce a signature by a key the agent never asked
        // for. No argument means the default sign slot.
        let role = if spec.is_empty() {
            SlotRole::Sign
        } else {
            match self.card.find(spec) {
                Some(slot) => slot.role,
                None => return self.err(ERR_NO_SECKEY, "No such key on this card"),
            }
        };
        // The decrypt slot is X25519 and cannot sign. Refuse here with the
        // same error as an unknown key, before the backend prompts the user
        // to approve an operation that can only fail.
        if role == SlotRole::Decrypt {
            return self.err(ERR_NO_SECKEY, "Key cannot sign");
        }
        self.sign_with(role)
    }

    fn pkauth(&mut self, _args: &str) -> Result<()> {
        self.sign_with(SlotRole::Auth)
    }

    fn sign_with(&mut self, role: SlotRole) -> Result<()> {
        if self.data.is_empty() {
            return self.err(ERR_INV_DATA, "No data to sign (SETDATA first)");
        }
        if let Err(error) = self.card.slot_is_current(role) {
            return self.err(ERR_NO_SECKEY, &format!("{error:#}"));
        }
        let keyref = self.card.slot(role).keyref();
        let message = strip_digestinfo(&self.data).to_vec();
        match self.card.backend.sign(keyref, &message) {
            Ok(signature) => {
                self.data.clear();
                self.data(&signature)?;
                self.ok()
            }
            Err(error) => self.err(ERR_INV_DATA, &format!("sign failed: {error:#}")),
        }
    }

    fn pkdecrypt(&mut self, _args: &str) -> Result<()> {
        // The ephemeral point arrives via SETDATA, 0x40-prefixed (33 bytes).
        let point = match self.data.len() {
            33 if self.data[0] == 0x40 => self.data[1..].to_vec(),
            32 => self.data.clone(),
            _ => return self.err(ERR_INV_DATA, "Unexpected ECDH input length"),
        };
        if let Err(error) = self.card.slot_is_current(SlotRole::Decrypt) {
            return self.err(ERR_NO_SECKEY, &format!("{error:#}"));
        }
        let keyref = self.card.slot(SlotRole::Decrypt).keyref();
        match self.card.backend.ecdh(keyref, &point) {
            Ok(shared) => {
                self.data.clear();
                self.status("PADDING", "0")?;
                self.data(&shared)?;
                self.ok()
            }
            Err(error) => self.err(ERR_INV_DATA, &format!("decrypt failed: {error:#}")),
        }
    }

    // -- protocol plumbing ---------------------------------------------------

    fn ok(&mut self) -> Result<()> {
        self.line("OK")
    }

    fn err(&mut self, code: u32, message: &str) -> Result<()> {
        self.line(&format!("ERR {code} {message} <Passeport>"))
    }

    fn status(&mut self, keyword: &str, value: &str) -> Result<()> {
        self.line(&format!("S {keyword} {value}"))
    }

    fn data(&mut self, bytes: &[u8]) -> Result<()> {
        // Percent-escape and chunk to stay within Assuan line limits.
        let mut escaped = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            match byte {
                b'%' => escaped.extend_from_slice(b"%25"),
                b'\r' => escaped.extend_from_slice(b"%0D"),
                b'\n' => escaped.extend_from_slice(b"%0A"),
                other => escaped.push(other),
            }
        }
        for chunk in escaped.chunks(900) {
            self.out.write_all(b"D ")?;
            self.out.write_all(chunk)?;
            self.out.write_all(b"\n")?;
        }
        self.out.flush()?;
        Ok(())
    }

    fn line(&mut self, text: &str) -> Result<()> {
        self.out.write_all(text.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        Ok(())
    }
}

/// gpg-agent hands EdDSA card operations an ASN.1 DigestInfo *prefix* followed
/// by the bytes to sign, and expects the card to strip the prefix and sign the
/// remainder with a bare EdDSA (no additional hashing). Two shapes occur:
///
///   * PKSIGN: a well-formed DigestInfo whose trailing OCTET STRING is the
///     message digest (e.g. SHA-512 prefix + 64 bytes).
///   * PKAUTH (ssh): a fixed 15-byte SHA-1 DigestInfo prefix followed by the
///     full SSHSIG blob, whose length does NOT match the prefix's declared
///     20-byte digest — so we must strip by recognizing the prefix, not by
///     trusting its length.
///
/// Known standard prefixes are stripped; anything else is signed as-is.
fn strip_digestinfo(data: &[u8]) -> &[u8] {
    const PREFIXES: &[&[u8]] = &[
        // SHA-1
        &[
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
            0x14,
        ],
        // SHA-224
        &[
            0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x04, 0x05, 0x00, 0x04, 0x1C,
        ],
        // SHA-256
        &[
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        // SHA-384
        &[
            0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        // SHA-512
        &[
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    ];
    for prefix in PREFIXES {
        if let Some(rest) = data.strip_prefix(*prefix) {
            return rest;
        }
    }
    data
}

/// Canonical S-expression of a slot's public key, as gpg-agent expects from
/// READKEY.
fn public_key_sexp(slot: &Slot) -> Vec<u8> {
    let (curve, flags) = match slot.curve {
        CurveKind::Ed25519 => ("Ed25519", "eddsa"),
        CurveKind::Curve25519 => ("Curve25519", "djb-tweak"),
    };
    let mut out = Vec::new();
    out.extend_from_slice(b"(10:public-key(3:ecc(5:curve");
    out.extend_from_slice(format!("{}:{curve})(5:flags", curve.len()).as_bytes());
    out.extend_from_slice(format!("{}:{flags})(1:q{}:", flags.len(), slot.q.len()).as_bytes());
    out.extend_from_slice(&slot.q);
    out.extend_from_slice(b")))");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

    fn test_card() -> Card {
        let prf = [7u8; 32];
        let seed = identity::derive_pgp_seed(&prf).unwrap();
        let backend = Box::new(LocalBackend {
            seed,
            user_id: "Passeport Test <test@example.invalid>".to_owned(),
        });
        Card::build(backend).unwrap()
    }

    /// A [`LocalBackend`] that counts calls, to pin down how often the card
    /// actually reaches the backend (each call is a prompt-and-audit event in
    /// production).
    struct CountingBackend {
        inner: LocalBackend,
        slots_calls: Rc<Cell<usize>>,
        sign_calls: Rc<Cell<usize>>,
    }

    impl CryptoBackend for CountingBackend {
        fn slots(&self) -> Result<Vec<SlotPublic>> {
            self.slots_calls.set(self.slots_calls.get() + 1);
            self.inner.slots()
        }

        fn sign(&self, keyref: &str, data: &[u8]) -> Result<Vec<u8>> {
            self.sign_calls.set(self.sign_calls.get() + 1);
            self.inner.sign(keyref, data)
        }

        fn ecdh(&self, keyref: &str, point: &[u8]) -> Result<Vec<u8>> {
            self.inner.ecdh(keyref, point)
        }
    }

    fn counting_card() -> (Card, Rc<Cell<usize>>, Rc<Cell<usize>>) {
        let prf = [7u8; 32];
        let seed = identity::derive_pgp_seed(&prf).unwrap();
        let slots_calls = Rc::new(Cell::new(0));
        let sign_calls = Rc::new(Cell::new(0));
        let backend = Box::new(CountingBackend {
            inner: LocalBackend {
                seed,
                user_id: "Passeport Test <test@example.invalid>".to_owned(),
            },
            slots_calls: Rc::clone(&slots_calls),
            sign_calls: Rc::clone(&sign_calls),
        });
        (Card::build(backend).unwrap(), slots_calls, sign_calls)
    }

    fn talk(card: &Card, commands: &str) -> Vec<u8> {
        let mut output = Vec::new();
        serve_io(card, commands.as_bytes(), &mut output).unwrap();
        output
    }

    fn text(reply: &[u8]) -> String {
        String::from_utf8_lossy(reply).into_owned()
    }

    fn data_bytes(reply: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in reply.split(|&byte| byte == b'\n') {
            if let Some(rest) = line.strip_prefix(b"D ") {
                let mut bytes = rest.iter().copied();
                while let Some(byte) = bytes.next() {
                    if byte == b'%' {
                        let hi = bytes.next().unwrap();
                        let lo = bytes.next().unwrap();
                        let hex = [hi, lo];
                        out.push(
                            u8::from_str_radix(std::str::from_utf8(&hex).unwrap(), 16).unwrap(),
                        );
                    } else {
                        out.push(byte);
                    }
                }
            }
        }
        out
    }

    fn slot_q(card: &Card, role: SlotRole) -> Vec<u8> {
        card.slot(role).q.clone()
    }

    #[test]
    fn pksign_unknown_key_errors_instead_of_falling_back() {
        let card = test_card();
        let commands = format!(
            "SETDATA {}\nPKSIGN {}\nBYE\n",
            hex::encode([0xABu8; 32]),
            "0000000000000000000000000000000000000000"
        );
        let reply = text(&talk(&card, &commands));
        assert!(reply.contains("No such key"), "got: {reply}");
        assert!(!reply.contains("\nD "), "must not return a signature");
    }

    #[test]
    fn pksign_with_decrypt_key_refuses_without_touching_backend() {
        // The decrypt slot is X25519; a PKSIGN naming its keygrip must fail
        // up front — not after the backend has prompted for approval.
        let (card, slots_calls, sign_calls) = counting_card();
        let build_calls = slots_calls.get();
        let decrypt_grip = hex::encode_upper(card.slot(SlotRole::Decrypt).keygrip);
        let commands = format!(
            "SETDATA {}\nPKSIGN {decrypt_grip}\nBYE\n",
            hex::encode([0xABu8; 32])
        );
        let reply = text(&talk(&card, &commands));
        assert!(reply.contains("Key cannot sign"), "got: {reply}");
        assert!(!reply.contains("\nD "), "must not return a signature");
        assert_eq!(sign_calls.get(), 0, "backend sign must not be reached");
        assert_eq!(slots_calls.get(), build_calls, "no staleness round trip");
    }

    #[test]
    fn staleness_check_hits_backend_once_per_session() {
        let (card, slots_calls, sign_calls) = counting_card();
        assert_eq!(slots_calls.get(), 1, "Card::build fetches the slots once");
        let digest = hex::encode([0xABu8; 32]);
        let commands = format!(
            "SETDATA {digest}\nPKSIGN OPENPGP.1\nSETDATA {digest}\nPKSIGN OPENPGP.3\nBYE\n"
        );
        talk(&card, &commands);
        assert_eq!(sign_calls.get(), 2, "both signatures reach the backend");
        assert_eq!(
            slots_calls.get(),
            2,
            "one staleness check for the whole session"
        );
    }

    #[test]
    fn sign_refuses_when_card_identity_changed_under_the_model() {
        // Build the model from one identity, then swap the backend to a
        // different one — as happens when the seed is reset/restored while
        // gpg-agent keeps its shim alive.
        let mut card = test_card();
        let other_prf = [9u8; 32];
        let other_seed = identity::derive_pgp_seed(&other_prf).unwrap();
        card.backend = Box::new(LocalBackend {
            seed: other_seed,
            user_id: "Passeport Test <test@example.invalid>".to_owned(),
        });
        let commands = format!(
            "SETDATA {}\nPKSIGN OPENPGP.1\nBYE\n",
            hex::encode([0xABu8; 32])
        );
        let reply = text(&talk(&card, &commands));
        assert!(reply.contains("identity changed"), "got: {reply}");
        assert!(!reply.contains("\nD "), "must not return a signature");
    }

    #[test]
    fn keygrips_match_gpg() {
        // Ground truth from `gpg --with-keygrip` (GnuPG 2.5.20, libgcrypt
        // 1.12.2) for the identity derived from PRF = [7u8; 32].
        let card = test_card();
        let grips: Vec<String> = card
            .slots
            .iter()
            .map(|slot| hex::encode_upper(slot.keygrip))
            .collect();
        assert_eq!(grips[0], "4AAD2F00F6F14F683A596A84BEF45A40ED954524");
        assert_eq!(grips[1], "692543C522505139F137354AF27C5A0448EF0220");
        assert_eq!(grips[2], "CF3A027C373CCF7EC0D8AA9605C3E5255E8D429F");
    }

    #[test]
    fn serialno_is_stable_and_wellformed() {
        let first = test_card();
        let second = test_card();
        assert_eq!(first.aid_hex(), second.aid_hex());
        assert!(first.aid_hex().starts_with("D27600012401"));
        assert_eq!(first.aid.len(), 16);
    }

    #[test]
    fn learn_reports_three_keypairs() {
        let card = test_card();
        let reply = text(&talk(&card, "LEARN --force\nBYE\n"));
        assert_eq!(reply.matches("S KEYPAIRINFO").count(), 3);
        assert_eq!(reply.matches("S KEY-FPR").count(), 3);
        assert!(reply.contains("OPENPGP.1 sc"));
        assert!(reply.contains("OPENPGP.2 e"));
        assert!(reply.contains("OPENPGP.3 a"));
        assert!(reply.contains("S APPTYPE openpgp"));
    }

    #[test]
    fn readkey_returns_wellformed_sexp() {
        let card = test_card();
        let reply = talk(&card, "READKEY OPENPGP.3\nBYE\n");
        let sexp = data_bytes(&reply);
        assert!(sexp.starts_with(b"(10:public-key(3:ecc(5:curve7:Ed25519)"));
        let needle = slot_q(&card, SlotRole::Auth);
        assert!(
            sexp.windows(needle.len()).any(|window| window == needle),
            "sexp must embed the auth subkey point"
        );
    }

    #[test]
    fn pksign_produces_verifiable_signature() {
        let card = test_card();
        let digest = [0xABu8; 32];
        let commands = format!("SETDATA {}\nPKSIGN OPENPGP.1\nBYE\n", hex::encode(digest));
        let reply = talk(&card, &commands);
        let sig_bytes = data_bytes(&reply);
        assert_eq!(sig_bytes.len(), 64);

        let public =
            VerifyingKey::from_bytes(&point32(&slot_q(&card, SlotRole::Sign)).unwrap()).unwrap();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        public.verify(&digest, &signature).unwrap();
    }

    #[test]
    fn pksign_strips_digestinfo_wrapper() {
        let card = test_card();
        let digest = [0xB8u8; 64];
        let mut wrapped = hex::decode("3051300D060960864801650304020305000440").unwrap();
        wrapped.extend_from_slice(&digest);
        let commands = format!(
            "SETDATA {}\nPKSIGN --hash=sha512 OPENPGP.1\nBYE\n",
            hex::encode(wrapped)
        );
        let reply = talk(&card, &commands);
        let sig_bytes = data_bytes(&reply);

        let public =
            VerifyingKey::from_bytes(&point32(&slot_q(&card, SlotRole::Sign)).unwrap()).unwrap();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        public.verify(&digest, &signature).unwrap();
    }

    #[test]
    fn pkauth_signs_with_auth_key() {
        let card = test_card();
        let digest = [0x11u8; 32];
        let commands = format!("SETDATA {}\nPKAUTH OPENPGP.3\nBYE\n", hex::encode(digest));
        let reply = talk(&card, &commands);
        let sig_bytes = data_bytes(&reply);

        let public =
            VerifyingKey::from_bytes(&point32(&slot_q(&card, SlotRole::Auth)).unwrap()).unwrap();
        let signature = Signature::from_bytes(&sig_bytes.try_into().unwrap());
        public.verify(&digest, &signature).unwrap();
    }

    #[test]
    fn pkdecrypt_matches_direct_x25519() {
        let card = test_card();
        let ephemeral_secret = StaticSecret::from([0x42u8; 32]);
        let ephemeral_public = X25519Public::from(&ephemeral_secret);

        let mut setdata = vec![0x40u8];
        setdata.extend_from_slice(ephemeral_public.as_bytes());
        let commands = format!(
            "SETDATA {}\nPKDECRYPT OPENPGP.2\nBYE\n",
            hex::encode(setdata)
        );
        let reply = talk(&card, &commands);
        let shared = data_bytes(&reply);
        assert!(text(&reply).contains("S PADDING 0"));

        // Recompute the shared secret from the card's public encryption point.
        let card_public = point32(&slot_q(&card, SlotRole::Decrypt)).unwrap();
        let expected = ephemeral_secret.diffie_hellman(&X25519Public::from(card_public));
        assert_eq!(shared, expected.as_bytes());
    }

    #[test]
    fn keyinfo_list_auth_returns_only_auth_key() {
        let card = test_card();
        let auth_grip = hex::encode_upper(card.slot(SlotRole::Auth).keygrip);
        let sign_grip = hex::encode_upper(card.slot(SlotRole::Sign).keygrip);

        // gpg-agent's ssh enumeration query.
        let reply = text(&talk(&card, "KEYINFO --list=auth\nBYE\n"));
        assert_eq!(
            reply.matches("KEYINFO").count(),
            1,
            "only one key for --list=auth"
        );
        assert!(reply.contains(&auth_grip));
        assert!(
            !reply.contains(&sign_grip),
            "the signing key must not be offered to ssh"
        );

        // A bare --list still enumerates everything (used elsewhere).
        let all = text(&talk(&card, "KEYINFO --list\nBYE\n"));
        assert_eq!(all.matches("KEYINFO").count(), 3);
    }

    #[test]
    fn unknown_command_errors_politely() {
        let card = test_card();
        let reply = text(&talk(&card, "FROBNICATE\nBYE\n"));
        assert!(reply.contains("ERR"));
        assert!(reply.contains("OK closing connection"));
    }
}

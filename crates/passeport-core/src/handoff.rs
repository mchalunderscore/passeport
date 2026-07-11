//! Private file-to-app decryption handoff.
//!
//! Ciphertext is staged in a 0700 temporary directory. Plaintext crosses a
//! named FIFO and is drained concurrently, so it is never stored in a named
//! regular file and cannot fill the helper's stdout/JSON bridge.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result, bail};

const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
const PREFIXES: [&str; 2] = ["passeport-age-", "passeport-pgp-"];

pub struct DecryptHandoff {
    directory: PathBuf,
    ciphertext_path: PathBuf,
    plaintext_fifo: PathBuf,
}

impl DecryptHandoff {
    pub fn create(prefix: &str, ciphertext: &[u8]) -> Result<Self> {
        validate_prefix(prefix)?;
        cleanup_stale();
        let base = std::env::temp_dir();
        let directory = (0..16)
            .find_map(|_| {
                let path = base.join(format!(
                    "{prefix}{}-{:016x}",
                    std::process::id(),
                    rand::random::<u64>()
                ));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => Some(Ok(path)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .transpose()
            .context("failed to create decrypt handoff directory")?
            .context("failed to create a unique decrypt handoff directory")?;

        let ciphertext_path = directory.join("ciphertext");
        let mut input = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&ciphertext_path)
            .context("failed to stage ciphertext")?;
        input
            .write_all(ciphertext)
            .context("failed to stage ciphertext")?;

        let plaintext_fifo = directory.join("plaintext.fifo");
        let path = CString::new(plaintext_fifo.as_os_str().as_bytes())?;
        if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
            let error = std::io::Error::last_os_error();
            let _ = std::fs::remove_dir_all(&directory);
            return Err(error).context("failed to create plaintext FIFO");
        }

        Ok(Self {
            directory,
            ciphertext_path,
            plaintext_fifo,
        })
    }

    pub fn ciphertext_path(&self) -> String {
        self.ciphertext_path.to_string_lossy().into_owned()
    }

    pub fn plaintext_path(&self) -> String {
        self.plaintext_fifo.to_string_lossy().into_owned()
    }

    pub fn start_reader(&self) -> JoinHandle<Result<Vec<u8>>> {
        let path = self.plaintext_fifo.clone();
        std::thread::spawn(move || {
            let mut plaintext = Vec::new();
            File::open(&path)
                .context("failed to open plaintext FIFO")?
                .read_to_end(&mut plaintext)
                .context("failed to read plaintext FIFO")?;
            Ok(plaintext)
        })
    }

    /// Unblock a reader when approval or the bridge fails before the helper
    /// opens the FIFO. Opening and immediately closing the write end yields EOF.
    pub fn cancel_reader(&self) {
        let _ = OpenOptions::new().write(true).open(&self.plaintext_fifo);
    }
}

impl Drop for DecryptHandoff {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub fn write_plaintext(path: &str, plaintext: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("failed to open plaintext FIFO at {path}"))?
        .write_all(plaintext)
        .context("failed to stream decrypted plaintext")
}

fn cleanup_stale() {
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|elapsed| elapsed >= STALE_AFTER);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

pub fn join_reader(reader: JoinHandle<Result<Vec<u8>>>) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("plaintext reader panicked"))?
}

pub fn validate_prefix(prefix: &str) -> Result<()> {
    if PREFIXES.contains(&prefix) {
        Ok(())
    } else {
        bail!("unsupported decrypt handoff prefix")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_streams_large_plaintext_without_regular_output_file() {
        validate_prefix("passeport-age-").unwrap();
        let handoff = DecryptHandoff::create("passeport-age-", b"ciphertext").unwrap();
        let reader = handoff.start_reader();
        let path = handoff.plaintext_path();
        let payload = vec![0x5a; 2_000_000];
        let expected = payload.clone();
        let writer = std::thread::spawn(move || write_plaintext(&path, &payload));
        writer.join().unwrap().unwrap();
        assert_eq!(join_reader(reader).unwrap(), expected);
        assert!(!std::path::Path::new(&handoff.plaintext_path()).is_file());
    }
}

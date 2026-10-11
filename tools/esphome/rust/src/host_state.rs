//! Shared host-only private credential and exclusive security-record adapter.
//!
//! The caller supplies a protected private directory. Durable sync and HMAC
//! readback qualify process recovery, not hostile rollback or flash power loss.
#![forbid(unsafe_code)]
use crate::security_state::{Credentials, Error, RECORD_BYTES, Store};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
type Result<T> = std::result::Result<T, &'static str>;

/// Exclusive fixed OSCORE record. Creation is an explicit offline operation.
pub struct FileStore {
    file: File,
    initializing: bool,
}
impl FileStore {
    pub fn open(path: &Path, initializing: bool) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(initializing);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|_| "state open refused")?;
        file.try_lock()
            .map_err(|_| "state exclusively owned elsewhere")?;
        Ok(Self { file, initializing })
    }
}
impl Drop for FileStore {
    fn drop(&mut self) {
        // Explicitly release ownership even if a fork inherited the open file
        // description. No further store operations can follow this drop.
        let _ = self.file.unlock();
    }
}
impl Store for FileStore {
    fn read(&mut self) -> std::result::Result<Option<[u8; RECORD_BYTES]>, Error> {
        let length = self.file.metadata().map_err(|_| Error::Unavailable)?.len();
        if self.initializing && length == 0 {
            return Ok(None);
        }
        if length != RECORD_BYTES as u64 {
            return Err(Error::Corrupt);
        }
        let mut bytes = [0; RECORD_BYTES];
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Unavailable)?;
        self.file
            .read_exact(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        Ok(Some(bytes))
    }
    fn commit(&mut self, bytes: &[u8; RECORD_BYTES]) -> std::result::Result<(), Error> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Error::Unavailable)?;
        self.file.write_all(bytes).map_err(|_| Error::Unavailable)?;
        self.file.sync_all().map_err(|_| Error::Unavailable)?;
        self.initializing = false;
        Ok(())
    }
}

/// Load the exact private pairwise credential record without logging its bytes.
pub fn credentials(path: &Path) -> Result<Credentials> {
    let mut file = File::open(path).map_err(|_| "credentials unavailable")?;
    if file.metadata().map_err(|_| "credential metadata")?.len() != 66 {
        return Err("credential length");
    }
    let mut bytes = [0; 66];
    file.read_exact(&mut bytes)
        .map_err(|_| "credentials read")?;
    let c = Credentials {
        secret: bytes[..32].try_into().unwrap(),
        salt: bytes[32..48].try_into().unwrap(),
        context: bytes[48..64].try_into().unwrap(),
        sender: bytes[64],
        recipient: bytes[65],
    };
    bytes.fill(0);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_store_refuses_concurrent_owner_truncation_and_implicit_creation() {
        let root = std::env::temp_dir().join(format!("coaptic-state-proof-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("state");
        assert!(FileStore::open(&path, false).is_err());
        let mut first = FileStore::open(&path, true).unwrap();
        assert!(FileStore::open(&path, false).is_err());
        assert!(first.read().unwrap().is_none());
        first.commit(&[0x39; RECORD_BYTES]).unwrap();
        assert_eq!(first.read().unwrap(), Some([0x39; RECORD_BYTES]));
        assert!(FileStore::open(&path, true).is_err());
        first.file.set_len(99).unwrap();
        assert_eq!(first.read(), Err(Error::Corrupt));
        let inherited = first.file.try_clone().unwrap();
        drop(first);
        let mut reopened = FileStore::open(&path, false).unwrap();
        assert_eq!(reopened.read(), Err(Error::Corrupt));
        drop(inherited);
        drop(reopened);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}

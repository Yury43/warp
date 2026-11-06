use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

pub fn root() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("WARP_SSH_SESSION_DIR") {
        let path = PathBuf::from(path);
        private_dir(&path)?;
        return Ok(path);
    }
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is missing")?);
    let warp = home.join(".warp");
    create_dir(&warp)?;
    let info = fs::symlink_metadata(&warp)?;
    ensure!(
        info.is_dir() && info.uid() == unsafe { libc::getuid() } && info.mode() & 0o022 == 0,
        "Unsafe remote session directory"
    );
    let sessions = warp.join("ssh-sessions");
    private_dir(&sessions)?;
    let root = sessions.join("v1");
    private_dir(&root)?;
    Ok(root)
}

fn create_dir(path: &Path) -> Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn private_dir(path: &Path) -> Result<()> {
    create_dir(path)?;
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir() && info.uid() == unsafe { libc::getuid() } && info.mode() & 0o077 == 0,
        "Session directory must be owned by the current user with mode 0700, without symlinks"
    );
    Ok(())
}

pub fn session_path(root: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)),
        "Session names must be 1–64 letters, digits, dots, colons, underscores or hyphens"
    );
    let digest = format!("{:x}", Sha256::digest(name.as_bytes()));
    Ok(root.join(&digest[..24]))
}

pub fn secure_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.uid() == unsafe { libc::getuid() } && info.nlink() == 1,
        "Unsafe session file"
    );
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file)
}

pub fn try_lock(file: &File) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error.into())
    }
}

pub fn identity() -> Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;

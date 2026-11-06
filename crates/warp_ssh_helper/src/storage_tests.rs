use std::os::unix::fs::symlink;

use super::*;

#[test]
fn session_names_cannot_escape_storage_directory() {
    assert!(session_path(Path::new("/tmp"), "../../elsewhere").is_err());
    assert!(session_path(Path::new("/tmp"), "").is_err());
}

#[test]
fn timestamp_names_are_valid_and_distinct() {
    let root = Path::new("/tmp");
    let first = session_path(root, "2026.11.06-19:05:09").unwrap();
    let second = session_path(root, "2026.11.06-19:05:10").unwrap();
    assert_eq!(first.parent(), Some(root));
    assert_ne!(first, second);
}

#[test]
fn output_symlink_is_not_followed() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::write(&target, b"keep me").unwrap();
    let link = directory.path().join("output");
    symlink(&target, &link).unwrap();
    assert!(secure_file(&link).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep me");
}

#[test]
fn hardlinked_output_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::write(&target, b"keep me").unwrap();
    let link = directory.path().join("output");
    fs::hard_link(&target, &link).unwrap();
    assert!(secure_file(&link).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep me");
}

#[test]
fn storage_directory_rejects_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("link");
    symlink(directory.path(), &link).unwrap();
    assert!(private_dir(&link).is_err());
}

#[test]
fn storage_directory_rejects_public_permissions() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), Permissions::from_mode(0o755)).unwrap();
    assert!(private_dir(directory.path()).is_err());
}

#[test]
fn session_lock_excludes_other_openers() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lock");
    let first = secure_file(&path).unwrap();
    let second = secure_file(&path).unwrap();
    assert!(try_lock(&first).unwrap());
    assert!(!try_lock(&second).unwrap());
    drop(first);
    assert!(try_lock(&second).unwrap());
}

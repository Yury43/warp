use std::os::unix::net::{UnixListener, UnixStream};

use super::*;

#[test]
fn existing_socket_path_connects_to_the_new_agent_after_reconnect() {
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let first_path = directory.path().join("first");
    let second_path = directory.path().join("second");
    let first = UnixListener::bind(&first_path).unwrap();
    let second = UnixListener::bind(&second_path).unwrap();
    first.set_nonblocking(true).unwrap();
    second.set_nonblocking(true).unwrap();
    let stable_path = directory.path().join("agent");

    update(directory.path(), Some(&first_path)).unwrap();
    let connection = UnixStream::connect(&stable_path).unwrap();
    assert!(first.accept().is_ok());
    drop(connection);
    update(directory.path(), Some(&second_path)).unwrap();
    let connection = UnixStream::connect(&stable_path).unwrap();
    assert!(second.accept().is_ok());
    assert!(first.accept().is_err());
    drop(connection);
}

#[test]
fn disabling_forwarding_removes_access_through_the_session_path() {
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let target = directory.path().join("target");
    let listener = UnixListener::bind(&target).unwrap();
    update(directory.path(), Some(&target)).unwrap();
    update(directory.path(), None).unwrap();
    assert!(UnixStream::connect(directory.path().join("agent")).is_err());
    assert!(UnixStream::connect(&target).is_ok());
    drop(listener);
}

#[test]
fn invalid_agent_target_does_not_replace_the_current_agent() {
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let target = directory.path().join("target");
    let listener = UnixListener::bind(&target).unwrap();
    listener.set_nonblocking(true).unwrap();
    update(directory.path(), Some(&target)).unwrap();
    let regular_file = directory.path().join("file");
    fs::write(&regular_file, b"not a socket").unwrap();
    assert!(update(directory.path(), Some(&regular_file)).is_err());
    let connection = UnixStream::connect(directory.path().join("agent")).unwrap();
    assert!(listener.accept().is_ok());
    drop(connection);
}

#[test]
fn agent_target_cannot_be_a_symlink() {
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let target = directory.path().join("target");
    let listener = UnixListener::bind(&target).unwrap();
    let indirect = directory.path().join("indirect");
    symlink(&target, &indirect).unwrap();
    assert!(update(directory.path(), Some(&indirect)).is_err());
    drop(listener);
}

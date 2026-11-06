#[cfg(unix)]
mod agent;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod server;
#[cfg(unix)]
mod storage;

#[cfg(unix)]
fn main() {
    // Supervisors outlive the SSH transport; broken pipes must remain ordinary I/O errors.
    unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    if let Err(error) = server::run() {
        use std::io::Write;
        let _ = std::io::stdout().write_all(&protocol::json_frame(b'E', &error.to_string()));
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("The SSH session supervisor requires Unix");
    std::process::exit(1);
}

#![expect(
    clippy::disallowed_types,
    reason = "This standalone Unix supervisor requires pre_exec and exec"
)]

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde_json::json;

use crate::agent;
use crate::protocol::{
    Action, CHUNK, Decoder, MAX_FRAME, Request, SessionInfo, SessionState, ShellIntegration, frame,
    json_frame, read_frame, read_request,
};
use crate::storage::{identity, private_dir, root, secure_file, session_path, try_lock};

fn syscall(result: libc::c_int) -> io::Result<libc::c_int> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn poll(fds: &mut [libc::pollfd], timeout: i32) -> io::Result<()> {
    match syscall(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) }) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
        Err(error) => Err(error),
    }
}

fn poll_fd(fd: RawFd, events: i16) -> libc::pollfd {
    libc::pollfd {
        fd,
        events,
        revents: 0,
    }
}

pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version") => println!("warp-ssh-helper 1"),
        Some("proxy") => proxy()?,
        Some("daemon") => {
            ensure!(args.len() == 5, "Invalid daemon arguments");
            let lock_fd: RawFd = args[2].parse()?;
            let ready_fd: RawFd = args[3].parse()?;
            ensure!(
                lock_fd > 2 && ready_fd > 2 && lock_fd != ready_fd,
                "Invalid inherited descriptors"
            );
            let lock = unsafe { File::from_raw_fd(lock_fd) };
            let mut ready = unsafe { File::from_raw_fd(ready_fd) };
            syscall(unsafe { libc::fcntl(lock_fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
            syscall(unsafe { libc::fcntl(ready_fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
            let request = serde_json::from_str(&args[4])?;
            let mut supervisor = Supervisor::new(lock, &request)?;
            ready.write_all(b"1")?;
            drop(ready);
            supervisor.run()?;
        }
        Some(_) | None => bail!("Expected proxy or daemon"),
    }
    Ok(())
}

fn connect(request: &mut Request) -> Result<UnixStream> {
    let directory = session_path(&root()?, &request.name)?;
    private_dir(&directory)?;
    let lock = secure_file(&directory.join("lock"))?;
    if try_lock(&lock)? {
        ensure!(
            request.generation.is_none()
                && !request.existing_only
                && request.action == Action::Attach,
            "Session no longer exists; it was not silently replaced"
        );
        ensure!(request.term.len() <= 128, "Invalid terminal type");
        request.created = true;
        let (mut reader, writer) = UnixStream::pair()?;
        reader.set_read_timeout(Some(Duration::from_secs(10)))?;
        let lock_fd = lock.as_raw_fd();
        let ready_fd = writer.as_raw_fd();
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "daemon",
                &lock_fd.to_string(),
                &ready_fd.to_string(),
                &serde_json::to_string(request)?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                syscall(libc::setsid())?;
                syscall(libc::fcntl(lock_fd, libc::F_SETFD, 0))?;
                syscall(libc::fcntl(ready_fd, libc::F_SETFD, 0))?;
                Ok(())
            });
        }
        let mut daemon = command.spawn()?;
        drop(writer);
        let mut ready = [0];
        if reader.read_exact(&mut ready).is_err() || ready != *b"1" {
            let _ = daemon.kill();
            let _ = daemon.wait();
            bail!("Remote session supervisor failed to start");
        }
    } else {
        ensure!(
            !request.create_only,
            "A session with this timestamp already exists; retry to create a new session"
        );
    }
    Ok(UnixStream::connect(directory.join("socket"))?)
}

fn proxy() -> Result<()> {
    let root = root()?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut request = read_request(&mut input)?;
    request.agent_socket = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
    if request.action == Action::List {
        let mut names = Vec::new();
        let mut sessions = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            private_dir(&entry.path())?;
            let lock = secure_file(&entry.path().join("lock"))?;
            if !try_lock(&lock)? {
                match fs::read_to_string(entry.path().join("name")) {
                    Ok(name) => {
                        if request.details {
                            request.name.clone_from(&name);
                            sessions.push(session_info(&entry.path(), &request));
                        }
                        names.push(name);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        names.sort();
        if request.details {
            sessions.sort_by(|a, b| a.name.cmp(&b.name));
            let response = json_frame(b'L', &sessions);
            ensure!(response.len() <= MAX_FRAME + 5, "Too many sessions to list");
            output.write_all(&response)?;
        } else {
            output.write_all(&json_frame(b'L', &names))?;
        }
        return Ok(());
    }
    let mut stream = connect(&mut request)?;
    stream.write_all(&json_frame(b'H', &request))?;
    let (kind, payload) = read_frame(&mut stream)?;
    if kind == b'H' && request.agent_socket.is_some() {
        let hello: serde_json::Value = serde_json::from_slice(&payload)?;
        ensure!(
            hello["agent_forwarding"] == true,
            "This session predates agent forwarding; create a new named session to use -A"
        );
    }
    output.write_all(&frame(kind, &payload))?;
    output.flush()?;
    // Backpressure stalls only this proxy; the supervisor keeps draining the PTY to disk.
    let mut buffer = [0; CHUNK];
    loop {
        let mut fds = [
            poll_fd(0, libc::POLLIN),
            poll_fd(stream.as_raw_fd(), libc::POLLIN),
        ];
        poll(&mut fds, -1)?;
        if fds[1].revents != 0 {
            let count = stream.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
            output.flush()?;
        }
        if fds[0].revents != 0 {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            stream.write_all(&buffer[..count])?;
        }
    }
    Ok(())
}

fn session_info(directory: &Path, request: &Request) -> SessionInfo {
    let query = || -> Result<SessionInfo> {
        let mut stream = UnixStream::connect(directory.join("socket"))?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;
        let mut status = serde_json::to_value(request)?;
        status["action"] = json!("status");
        stream.write_all(&json_frame(b'H', &status))?;
        let (kind, payload) = read_frame(&mut stream)?;
        ensure!(kind == b'S', "Session statistics are unavailable");
        Ok(serde_json::from_slice(&payload)?)
    };
    query().unwrap_or_else(|_| SessionInfo {
        name: request.name.clone(),
        created_at: fs::metadata(directory.join("name"))
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|time| time.as_secs()),
        created_at_estimated: true,
        last_interaction_at: None,
        state: SessionState::Unknown,
        shell_pid: None,
        output_bytes: fs::metadata(directory.join("output")).map_or(0, |metadata| metadata.len()),
        generation: None,
    })
}

struct Peer {
    stream: UnixStream,
    decoder: Decoder,
    output: Vec<u8>,
    client: Option<String>,
    offset: u64,
    closing: bool,
    deadline: Option<Instant>,
}

impl Peer {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            decoder: Decoder::default(),
            output: Vec::new(),
            client: None,
            offset: 0,
            closing: false,
            deadline: Some(Instant::now() + Duration::from_secs(10)),
        }
    }

    fn finish(&mut self, kind: u8, value: &impl serde::Serialize) {
        self.output.extend(json_frame(kind, value));
        self.closing = true;
        self.deadline = Some(Instant::now() + Duration::from_secs(10));
    }
}

struct Supervisor {
    name: String,
    created_at: u64,
    last_interaction_at: u64,
    directory: PathBuf,
    // The lock must outlive both the listener and its cleanup.
    lock: File,
    generation: String,
    listener: UnixListener,
    peers: HashMap<u64, Peer>,
    next_peer: u64,
    active: Option<u64>,
    accepted: HashMap<String, u64>,
    detached: HashSet<String>,
    input: Vec<u8>,
    log: File,
    length: u64,
    master: File,
    child: Child,
    status: Option<i32>,
    eof: bool,
    stopping: bool,
    size: [u16; 2],
    integration: Option<ShellIntegration>,
}

fn spawn_shell(request: &Request, directory: &Path) -> Result<(File, Child)> {
    ensure!(
        request.size.iter().all(|value| *value != 0),
        "Invalid terminal size"
    );
    let mut master = -1;
    let mut slave = -1;
    let mut size = libc::winsize {
        ws_row: request.size[0],
        ws_col: request.size[1],
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    syscall(unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut size,
        )
    })?;
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    syscall(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
    syscall(unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) })?;
    syscall(unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let basename = shell.rsplit('/').next().context("Invalid shell")?;
    let mut command = Command::new(&shell);
    if let Some(integration) = &request.integration {
        ensure!(
            basename == "bash",
            "Shell integration currently requires Bash"
        );
        ensure!(
            integration.session_id != 0,
            "Invalid shell integration identity"
        );
        ensure!(
            integration.bootstrap.len() == 64
                && integration
                    .bootstrap
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "Invalid bootstrap digest"
        );
        let bootstrap = root()?.join(format!("bootstrap-{}", integration.bootstrap));
        // The installer checks ownership and digest before publishing this immutable script.
        ensure!(bootstrap.is_file(), "Shell bootstrap is missing");
        command
            .args(["--noprofile", "--rcfile"])
            .arg(bootstrap)
            .arg("-i");
        command
            .env("WARP_SESSION_ID", integration.session_id.to_string())
            .env("WARP_IS_SSH", "1")
            .env_remove("WARP_BOOTSTRAPPED");
    } else {
        command.arg0(format!("-{basename}"));
    }
    command
        .env("TERM", &request.term)
        .env("TERM_PROGRAM", "WarpTerminal")
        .env("WARP_PERSISTENT_SSH_SESSION", &request.name)
        .env("SSH_AUTH_SOCK", directory.join("agent"))
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_CLIENT")
        .env_remove("SSH_TTY")
        .stdin(slave.try_clone()?)
        .stdout(slave.try_clone()?)
        .stderr(slave);
    unsafe {
        command.pre_exec(|| {
            syscall(libc::setsid())?;
            syscall(libc::ioctl(0, libc::TIOCSCTTY as _, 0))?;
            Ok(())
        });
    }
    Ok((master, command.spawn()?))
}

impl Supervisor {
    fn new(lock: File, request: &Request) -> Result<Self> {
        let directory = session_path(&root()?, &request.name)?;
        let generation = identity()?;
        let log = secure_file(&directory.join("output"))?;
        log.set_len(0)?;
        let mut metadata = secure_file(&directory.join("name"))?;
        metadata.set_len(0)?;
        metadata.write_all(request.name.as_bytes())?;
        let socket = directory.join("socket");
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(socket, Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        agent::update(&directory, request.agent_socket.as_deref())?;
        let (master, child) = spawn_shell(request, &directory)?;
        let created_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(Self {
            name: request.name.clone(),
            created_at,
            last_interaction_at: created_at,
            directory,
            lock,
            generation,
            listener,
            peers: HashMap::new(),
            next_peer: 0,
            active: None,
            accepted: HashMap::new(),
            detached: HashSet::new(),
            input: Vec::new(),
            log,
            length: 0,
            master,
            child,
            status: None,
            eof: false,
            stopping: false,
            size: request.size,
            integration: request.integration.clone(),
        })
    }

    fn handle(&mut self, id: u64, peer: &mut Peer, kind: u8, payload: &[u8]) -> Result<()> {
        if kind == b'H' && peer.client.is_none() {
            let request: Request = serde_json::from_slice(payload)?;
            ensure!(request.name == self.name, "Session name mismatch");
            ensure!(
                request
                    .generation
                    .as_ref()
                    .is_none_or(|generation| generation == &self.generation),
                "Session was replaced; refusing to act on another shell"
            );
            match request.action {
                Action::Status => {
                    peer.finish(
                        b'S',
                        &SessionInfo {
                            name: self.name.clone(),
                            created_at: Some(self.created_at),
                            created_at_estimated: false,
                            last_interaction_at: Some(self.last_interaction_at),
                            state: if self.status.is_some() {
                                SessionState::Exited
                            } else if self.active.is_some() {
                                SessionState::Attached
                            } else {
                                SessionState::Detached
                            },
                            shell_pid: self.status.is_none().then(|| self.child.id()),
                            output_bytes: self.length,
                            generation: Some(self.generation.clone()),
                        },
                    );
                    return Ok(());
                }
                Action::Detach | Action::Kill => {
                    agent::clear(&self.directory)?;
                    self.detached.extend(self.accepted.keys().cloned());
                    if let Some(active) = self.active.take().and_then(|id| self.peers.get_mut(&id))
                    {
                        active.finish(b'D', &request.action);
                    }
                    peer.finish(b'D', &request.action);
                    self.stopping = request.action == Action::Kill;
                    return Ok(());
                }
                Action::List => bail!("Unexpected list request"),
                Action::Attach => {}
            }
            if self.detached.contains(&request.client) {
                peer.finish(b'D', &"detach");
                return Ok(());
            }
            ensure!(
                request.client.len() == 32
                    && request
                        .client
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "Invalid client identity"
            );
            ensure!(request.offset <= self.length, "Invalid output cursor");
            ensure!(
                self.integration.is_none() || request.integration.is_some(),
                "This session requires shell integration; attach from the updated Warp app"
            );
            if let Some(active) = self.active.and_then(|id| self.peers.get(&id)) {
                ensure!(
                    active.client.as_ref() == Some(&request.client),
                    "Session already attached; detach it explicitly before taking over"
                );
            }
            ensure!(
                self.accepted.contains_key(&request.client) || self.accepted.len() < 1024,
                "Session attachment limit reached; start a new named session"
            );
            agent::update(&self.directory, request.agent_socket.as_deref())?;
            if let Some(old) = self.active.take() {
                self.peers.remove(&old);
            }
            let accepted = self.accepted.entry(request.client.clone()).or_insert(0);
            peer.client = Some(request.client);
            peer.offset = request.offset;
            peer.deadline = None;
            peer.output.extend(json_frame(
                b'H',
                &json!({
                    "generation": self.generation, "accepted": accepted,
                    "replay_until": self.length, "size": self.size, "replay": !request.created,
                    "agent_forwarding": true,
                    "integration": self.integration,
                }),
            ));
            self.active = Some(id);
            self.last_interaction_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        } else if self.active == Some(id) && kind == b'I' {
            ensure!(payload.len() >= 8, "Invalid input frame");
            let sequence = u64::from_be_bytes(payload[..8].try_into()?);
            let accepted = self
                .accepted
                .get_mut(peer.client.as_ref().context("Missing client")?)
                .context("Missing input sequence")?;
            if accepted.checked_add(1) == Some(sequence) {
                ensure!(
                    self.input.len() + payload.len() - 8 <= MAX_FRAME,
                    "Remote input queue is full"
                );
                self.input.extend_from_slice(&payload[8..]);
                *accepted = sequence;
                if payload.len() > 8 {
                    self.last_interaction_at =
                        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                }
            } else {
                ensure!(sequence <= *accepted, "Input sequence has a gap");
            }
            peer.output.extend(frame(b'A', &accepted.to_be_bytes()));
        } else if self.active == Some(id) && kind == b'R' {
            let size: [u16; 2] = serde_json::from_slice(payload)?;
            ensure!(
                size.iter().all(|value| *value != 0),
                "Invalid terminal size"
            );
            self.size = size;
            if !self.eof {
                let size = libc::winsize {
                    ws_row: size[0],
                    ws_col: size[1],
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                syscall(unsafe {
                    libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ as _, &size)
                })?;
                let foreground = unsafe { libc::tcgetpgrp(self.master.as_raw_fd()) };
                if foreground > 0 {
                    unsafe {
                        libc::killpg(foreground, libc::SIGWINCH);
                    }
                }
            }
        } else {
            bail!("Unexpected session message");
        }
        Ok(())
    }

    fn pump(&mut self) -> Result<()> {
        let previous_active = self.active;
        for (id, peer) in &mut self.peers {
            if Some(*id) == self.active && peer.output.len() < CHUNK {
                let mut buffer = [0; CHUNK];
                let count = self.log.read_at(&mut buffer, peer.offset)?;
                if count > 0 {
                    let mut data = peer.offset.to_be_bytes().to_vec();
                    data.extend_from_slice(&buffer[..count]);
                    peer.output.extend(frame(b'O', &data));
                    peer.offset += count as u64;
                } else if let Some(status) = self.status.filter(|_| self.eof) {
                    peer.finish(b'X', &status);
                    self.active = None;
                    self.stopping = true;
                }
            }
        }
        self.peers.retain(|_, peer| {
            !(peer.closing && peer.output.is_empty())
                && peer.output.len() <= MAX_FRAME
                && peer
                    .deadline
                    .is_none_or(|deadline| Instant::now() <= deadline)
        });
        if self.active.is_some_and(|id| !self.peers.contains_key(&id)) {
            self.active = None;
        }
        if previous_active.is_some() && self.active.is_none() {
            agent::clear(&self.directory)?;
        }
        Ok(())
    }

    fn peer_event(&mut self, id: u64, events: i16) -> Result<()> {
        let Some(mut peer) = self.peers.remove(&id) else {
            return Ok(());
        };
        let mut connected = true;
        if events & libc::POLLOUT != 0 && !peer.output.is_empty() {
            match peer.stream.write(&peer.output) {
                Ok(count) => {
                    peer.output.drain(..count);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => connected = false,
            }
        }
        if connected
            && !peer.closing
            && events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
        {
            let mut data = [0; CHUNK];
            match peer.stream.read(&mut data) {
                Ok(0) => connected = false,
                Ok(count) => {
                    let result = peer.decoder.feed(&data[..count]).and_then(|messages| {
                        for (kind, payload) in messages {
                            self.handle(id, &mut peer, kind, &payload)?;
                            if peer.closing {
                                break;
                            }
                        }
                        Ok(())
                    });
                    if let Err(error) = result {
                        peer.finish(b'E', &error.to_string());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => connected = false,
            }
        }
        if (!connected || peer.closing) && self.active == Some(id) {
            self.active = None;
            agent::clear(&self.directory)?;
        }
        if connected {
            self.peers.insert(id, peer);
        }
        Ok(())
    }

    fn pty_event(&mut self, events: i16) -> Result<()> {
        if events & libc::POLLOUT != 0 && !self.input.is_empty() {
            match self.master.write(&self.input) {
                Ok(count) => {
                    self.input.drain(..count);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => self.input.clear(),
                Err(error) => return Err(error.into()),
            }
        }
        if events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut buffer = [0; CHUNK];
            match self.master.read(&mut buffer) {
                Ok(0) => self.eof = true,
                Ok(count) => {
                    self.log.write_all(&buffer[..count])?;
                    self.length += count as u64;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => self.eof = true,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        loop {
            self.pump()?;
            if self.stopping && self.peers.is_empty() {
                return Ok(());
            }
            if self.status.is_none() {
                self.status = self.child.try_wait()?.map(|status| {
                    status
                        .code()
                        .unwrap_or_else(|| -status.signal().unwrap_or(1))
                });
            }
            let ids: Vec<_> = self.peers.keys().copied().collect();
            let mut fds = vec![
                poll_fd(self.listener.as_raw_fd(), libc::POLLIN),
                poll_fd(
                    if self.eof {
                        -1
                    } else {
                        self.master.as_raw_fd()
                    },
                    libc::POLLIN
                        | if self.input.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                ),
            ];
            for id in &ids {
                let peer = &self.peers[id];
                fds.push(poll_fd(
                    peer.stream.as_raw_fd(),
                    if peer.closing { 0 } else { libc::POLLIN }
                        | if peer.output.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                ));
            }
            poll(&mut fds, 250)?;
            if fds[0].revents & libc::POLLIN != 0 {
                match self.listener.accept() {
                    Ok((stream, _)) if self.peers.len() < 16 && !self.stopping => {
                        stream.set_nonblocking(true)?;
                        self.next_peer += 1;
                        self.peers.insert(self.next_peer, Peer::new(stream));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            self.pty_event(fds[1].revents)?;
            for (id, fd) in ids.into_iter().zip(&fds[2..]) {
                if fd.revents != 0 {
                    self.peer_event(id, fd.revents)?;
                }
            }
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let foreground = unsafe { libc::tcgetpgrp(self.master.as_raw_fd()) };
        if foreground > 0 {
            unsafe {
                libc::killpg(foreground, libc::SIGHUP);
            }
        }
        if self.status.is_none() {
            unsafe {
                libc::killpg(self.child.id() as _, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
        for name in ["socket", "output", "name", "agent", "agent.next"] {
            let _ = fs::remove_file(self.directory.join(name));
        }
        unsafe {
            libc::flock(self.lock.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

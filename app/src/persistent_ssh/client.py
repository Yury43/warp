"""Local SSH transport for Warp's bundled native PTY supervisor."""

import argparse
import collections
import fcntl
import functools
import hashlib
import json
import os
import re
import select
import selectors
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import tty
import uuid
from pathlib import Path

HEADER = struct.Struct("!cI")
NUMBER = struct.Struct("!Q")
CHUNK = 32768
MAX_FRAME = 1024 * 1024


def frame(kind, payload=b""):
    return HEADER.pack(kind, len(payload)) + payload


def json_frame(kind, value):
    return frame(kind, json.dumps(value).encode())


class Decoder:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        messages = []
        while len(self.buffer) >= HEADER.size:
            kind, size = HEADER.unpack_from(self.buffer)
            if size > MAX_FRAME:
                raise ValueError("Invalid SSH session protocol; check remote shell startup output")
            end = HEADER.size + size
            if len(self.buffer) < end:
                break
            messages.append((kind, bytes(self.buffer[HEADER.size : end])))
            del self.buffer[:end]
        return messages


class ReplayFilter:
    """Suppress historical terminal queries and OSC/DCS side effects during a fresh attach."""

    def __init__(self, session_id=None):
        self.sequence = bytearray()
        self.state = "text"
        self.previous_escape = False
        self.session_id = session_id
        self.hooks = {}
        self.in_generator_output = False

    def remember_hook(self):
        sequence = bytes(self.sequence)
        if sequence.startswith(b"\x1b]9278;d;"):
            encoded = sequence[9:-1] if sequence.endswith(b"\x07") else sequence[9:-2]
        elif sequence.startswith(b"\x1bP$d"):
            encoded = sequence[4:-2]
        else:
            return
        try:
            hook = json.loads(bytes.fromhex(encoded.decode()))
            name, value = hook["hook"], hook["value"]
            if not self.session_id or value.get("session_id") != self.session_id:
                return
            if name in ("InitShell", "Bootstrapped", "Precmd", "Preexec", "CommandFinished"):
                if name == "Precmd" and value.get("is_after_in_band_command"):
                    if "Precmd" in self.hooks:
                        self.hooks["Precmd"]["next_block_id"] = value["next_block_id"]
                else:
                    self.hooks[name] = value
                if name in ("CommandFinished", "Precmd"):
                    self.hooks.pop("Preexec", None)
        except (ValueError, KeyError, TypeError, AttributeError):
            pass

    def restore_hooks(self):
        output = b"".join(
            shell_hook(name, self.hooks[name])
            for name in ("InitShell", "Bootstrapped", "CommandFinished", "Precmd")
            if name in self.hooks
        )
        if "Preexec" in self.hooks:
            value = dict(self.hooks["Preexec"], restore_command=True)
            command = value.get("command", "")
            if isinstance(command, str):
                value["command"] = "".join(c for c in command if c.isprintable() or c in "\n\t")
            output += shell_hook("Preexec", value)
        return output

    def finish_replay(self, data):
        prefix = bytearray()
        consumed = 0
        while self.state != "text" and consumed < len(data):
            prefix.extend(self.feed(data[consumed : consumed + 1], False))
            consumed += 1
        if self.state != "text":
            return bytes(prefix), False
        return bytes(prefix) + self.restore_hooks() + self.feed(data[consumed:], False), True

    def feed(self, data, replay):
        result = bytearray()
        for value in data:
            if self.state == "text":
                if value == 27 and (replay or self.in_generator_output):
                    self.sequence = bytearray([value])
                    self.state = "escape"
                elif not self.in_generator_output:
                    result.append(value)
                continue
            if len(self.sequence) < MAX_FRAME:
                self.sequence.append(value)
            if self.state == "escape":
                if value == ord("["):
                    self.state = "csi"
                elif value in (ord("]"), ord("P"), ord("_"), ord("^"), ord("X")):
                    self.state = "string"
                    self.previous_escape = False
                else:
                    result.extend(self.sequence)
                    self.state = "text"
            elif self.state == "csi" and 0x40 <= value <= 0x7E:
                if value not in (ord("n"), ord("c"), ord("t")):
                    result.extend(self.sequence)
                self.state = "text"
            elif self.state == "string":
                if value == 7 or (self.previous_escape and value == ord("\\")):
                    self.remember_hook()
                    if self.sequence in (b"\x1b]9277;A\x07", b"\x1b]9277;A\x1b\\"):
                        self.in_generator_output = True
                    elif self.sequence in (b"\x1b]9277;B\x07", b"\x1b]9277;B\x1b\\"):
                        self.in_generator_output = False
                    # Hyperlinks are presentation; clipboard writes and shell hooks are not.
                    if self.sequence.startswith(b"\x1b]8;") and len(self.sequence) < 4096:
                        result.extend(self.sequence)
                    self.state = "text"
                self.previous_escape = value == 27
        return bytes(result)


def write_all(fd, data):
    while data:
        count = os.write(fd, data)
        data = data[count:]


def terminal_size():
    rows, cols, _, _ = struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))
    return [max(rows, 1), max(cols, 1)]


def ssh_command(args, remote_command, reconnect=False, session=False):
    # Protocol bytes must never go through an SSH PTY or an inherited ControlMaster.
    command = [
        "ssh",
        "-T",
        "-o",
        "RequestTTY=no",
        "-o",
        "RemoteCommand=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ConnectTimeout=10",
    ]
    if reconnect:
        command.extend(["-o", "BatchMode=yes"])
    if not session or args.no_forward_agent:
        command.append("-a")
    elif args.forward_agent:
        command.append("-A")
    for flag, value in (("-p", args.port), ("-i", args.identity), ("-J", args.jump)):
        if value is not None:
            command.extend([flag, str(value)])
    for value in args.ssh_options:
        command.extend(["-o", value])
    command.extend(["--", args.destination, remote_command])
    return command


INSTALLER = r"""
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
digest=$1
artifact=$2
directory=$HOME
owner=$(id -u)
for part in .warp ssh-sessions v1; do
    directory=$directory/$part
    if [ ! -e "$directory" ] && [ ! -L "$directory" ]; then
        mkdir -m 700 "$directory" || [ -d "$directory" ]
    fi
    [ ! -L "$directory" ] && [ -d "$directory" ] || fail 'Unsafe remote session directory'
    [ "$(stat -c %u "$directory")" = "$owner" ] || fail 'Session directory has a different owner'
    mode=$(stat -c %a "$directory")
    [ "$((0$mode & 0022))" = 0 ] || fail 'Session directory is writable by other users'
    if [ "$part" != .warp ]; then
        [ "$((0$mode & 0077))" = 0 ] || fail 'Session directory must have mode 0700'
    fi
done
temporary=$(mktemp "$directory/.upload.XXXXXXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
cat > "$temporary"
actual=$(sha256sum "$temporary")
[ "${actual%% *}" = "$digest" ] || fail 'Incomplete session helper upload'
chmod 700 "$temporary"
if [ "$artifact" = helper ]; then
    "$temporary" --version >/dev/null || fail 'Cannot execute the native SSH helper on this host'
fi
mv -f "$temporary" "$directory/$artifact-$digest"
"""


@functools.lru_cache(maxsize=1)
def bundled_files():
    descriptors = json.loads(os.environ.pop("WARP_SSH_HELPER_FDS", "{}"))
    if descriptors:
        try:
            result = {}
            for key, descriptor in descriptors.items():
                with os.fdopen(int(descriptor), "rb", closefd=False) as source:
                    result[key] = source.read()
            return result
        finally:
            for descriptor in descriptors.values():
                os.close(int(descriptor))
    return {}


def bundled_bytes(architecture):
    sources = bundled_files()
    if sources:
        return sources
    directory = os.environ.get("WARP_SSH_HELPER_DIR")
    if directory:
        result = {
            architecture: (Path(directory) / ("warp-ssh-helper-" + architecture)).read_bytes()
        }
        bootstrap = Path(directory) / "bash-bootstrap.sh"
        if bootstrap.exists():
            result["bash"] = bootstrap.read_bytes()
        return result
    raise ValueError("Native SSH helpers are missing; build them with script/build-ssh-helpers")


def install(args):
    detected = subprocess.run(
        ssh_command(args, 'uname -s; uname -m; printf "%s\\n" "${SHELL##*/}"'),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    if detected.returncode:
        sys.stderr.buffer.write(detected.stderr)
        raise ValueError("Could not detect the SSH host platform")
    platform = detected.stdout.decode().splitlines()
    if len(platform) != 3 or platform[0] != "Linux":
        raise ValueError("Persistent SSH sessions require a Linux host")
    architecture = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(platform[1])
    if architecture is None:
        raise ValueError("Supported Linux host architectures are x86-64 and ARM64")
    sources = bundled_bytes(architecture)

    def upload(source, artifact):
        digest = hashlib.sha256(source).hexdigest()
        command = "sh -c " + shlex.quote(INSTALLER) + " sh " + digest + " " + artifact
        result = subprocess.run(
            ssh_command(args, command), input=source, stdout=subprocess.DEVNULL, check=False
        )
        if result.returncode:
            raise ValueError("Could not install the session " + artifact)
        return digest

    digest = upload(sources[architecture], "helper")
    args.helper_digest = digest
    args.integration = None
    if parent_session_id() and platform[2] == "bash" and "bash" in sources:
        args.integration = {
            "session_id": (uuid.uuid4().int & ((1 << 64) - 1)) or 1,
            "bootstrap": upload(sources["bash"], "bootstrap"),
        }
    return '"$HOME/.warp/ssh-sessions/v1/helper-' + digest + '" proxy'


def parent_session_id():
    value = os.environ.get("WARP_SESSION_ID", "")
    return int(value) if value.isdecimal() and 0 < int(value) < (1 << 64) else None


def shell_hook(name, value):
    data = json.dumps({"hook": name, "value": value}).encode().hex().encode()
    return b"\x1b]9278;d;" + data + b"\x07"


class Client:
    def __init__(self, args, remote_command):
        self.args = args
        self.remote_command = remote_command
        self.client = uuid.uuid4().hex
        self.generation = None
        self.offset = 0
        self.next_input = 1
        self.pending = collections.OrderedDict()
        self.pending_bytes = 0
        self.original_termios = None
        self.saved_flags = None
        self.replay_filter = ReplayFilter()
        self.fresh = True
        self.restoring_integration = False

    def raw(self):
        if self.original_termios is None:
            self.original_termios = termios.tcgetattr(0)
            self.saved_flags = fcntl.fcntl(0, fcntl.F_GETFL)
            tty.setraw(0, termios.TCSANOW)

    def restore(self):
        if self.original_termios is not None:
            termios.tcsetattr(0, termios.TCSANOW, self.original_termios)
            fcntl.fcntl(0, fcntl.F_SETFL, self.saved_flags)
            self.original_termios = None

    def acknowledge(self, accepted):
        if type(accepted) is not int or accepted >= self.next_input or accepted < 0:
            raise ValueError("Invalid input acknowledgement")
        while self.pending and next(iter(self.pending)) <= accepted:
            _, data = self.pending.popitem(last=False)
            self.pending_bytes -= len(data)

    def request(self):
        action = (
            "list"
            if self.args.list
            else "kill"
            if self.args.kill
            else "detach"
            if self.args.detach
            else "attach"
        )
        return {
            "name": self.args.name or "",
            "action": action,
            "client": self.client,
            "generation": self.generation or getattr(self.args, "selected_generation", None),
            "existing_only": getattr(self.args, "existing_only", False),
            "create_only": self.args.generated_name and self.generation is None,
            "offset": self.offset,
            "size": terminal_size() if action == "attach" else [24, 80],
            "term": os.environ.get("TERM", "xterm-256color"),
            "integration": getattr(self.args, "integration", None),
        }

    def connection(self):
        request = self.request()
        reconnect = self.generation is not None
        process = subprocess.Popen(
            ssh_command(self.args, self.remote_command, reconnect, session=True),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if reconnect else None,
        )
        selector = selectors.DefaultSelector()
        decoder = Decoder()
        outgoing = bytearray(json_frame(b"H", request))
        attached = False
        reading_input = False
        replay_until = 0
        last_size = None
        try:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "remote")
            selector.register(process.stdin, selectors.EVENT_WRITE, "send")
            sending = True
            while True:
                if attached and self.offset >= replay_until:
                    if self.restoring_integration and self.replay_filter.state == "text":
                        write_all(1, self.replay_filter.restore_hooks())
                        self.restoring_integration = False
                    size = terminal_size()
                    if size != last_size:
                        outgoing.extend(json_frame(b"R", size))
                        last_size = size
                    self.fresh = False
                can_read = attached and not self.fresh and self.pending_bytes <= MAX_FRAME - CHUNK
                if can_read and not reading_input:
                    selector.register(0, selectors.EVENT_READ, "input")
                    reading_input = True
                elif not can_read and reading_input:
                    selector.unregister(0)
                    reading_input = False
                if outgoing and not sending:
                    selector.register(process.stdin, selectors.EVENT_WRITE, "send")
                    sending = True
                if not outgoing and sending:
                    selector.unregister(process.stdin)
                    sending = False
                for key, _ in selector.select(0.2):
                    if key.data == "send":
                        try:
                            count = os.write(process.stdin.fileno(), outgoing)
                            del outgoing[:count]
                        except BlockingIOError:
                            pass
                        except BrokenPipeError:
                            return None
                    elif key.data == "input":
                        data = os.read(0, CHUNK)
                        if not data:
                            return 0
                        size = terminal_size()
                        if size != last_size:
                            outgoing.extend(json_frame(b"R", size))
                            last_size = size
                        self.pending[self.next_input] = data
                        self.pending_bytes += len(data)
                        outgoing.extend(frame(b"I", NUMBER.pack(self.next_input) + data))
                        self.next_input += 1
                    else:
                        data = os.read(process.stdout.fileno(), CHUNK)
                        if not data:
                            return None
                        for kind, payload in decoder.feed(data):
                            if kind == b"H" and not attached:
                                hello = json.loads(payload)
                                if self.generation and self.generation != hello["generation"]:
                                    raise ValueError("Remote session identity changed")
                                self.generation = hello["generation"]
                                self.acknowledge(hello["accepted"])
                                replay_until = hello["replay_until"]
                                if not hello["replay"]:
                                    self.fresh = False
                                for sequence, pending in self.pending.items():
                                    outgoing.extend(frame(b"I", NUMBER.pack(sequence) + pending))
                                self.raw()
                                if not reconnect:
                                    integration = hello.get("integration")
                                    if integration:
                                        if not parent_session_id():
                                            raise ValueError(
                                                "This session uses Warp shell integration; attach from a new pane in the updated Warp app"
                                            )
                                        write_all(
                                            1,
                                            shell_hook(
                                                "SSH",
                                                {
                                                    "session_id": parent_session_id(),
                                                    "remote_session_id": integration["session_id"],
                                                    "remote_shell": "bash",
                                                    "socket_path": "",
                                                    "persistent_session": True,
                                                },
                                            ),
                                        )
                                        self.replay_filter.session_id = integration["session_id"]
                                        self.restoring_integration = hello["replay"]
                                    elif getattr(self.args, "integration", None):
                                        write_all(
                                            2,
                                            b"\r\nWarp SSH: this session predates shell integration; start a new named session to enable it.\r\n",
                                        )
                                if reconnect:
                                    termios.tcflush(0, termios.TCIFLUSH)
                                attached = True
                            elif kind == b"O" and attached:
                                if len(payload) < NUMBER.size:
                                    raise ValueError("Invalid output frame")
                                offset = NUMBER.unpack_from(payload)[0]
                                if offset != self.offset:
                                    raise ValueError("Remote output is not contiguous")
                                data = payload[NUMBER.size :]
                                boundary = (
                                    max(0, min(len(data), replay_until - offset))
                                    if self.fresh
                                    else 0
                                )
                                output = self.replay_filter.feed(data[:boundary], True)
                                if self.restoring_integration and offset + boundary >= replay_until:
                                    tail, restored = self.replay_filter.finish_replay(
                                        data[boundary:]
                                    )
                                    output += tail
                                    self.restoring_integration = not restored
                                else:
                                    output += self.replay_filter.feed(data[boundary:], False)
                                write_all(1, output)
                                self.offset += len(data)
                            elif kind == b"A" and attached:
                                self.acknowledge(NUMBER.unpack(payload)[0])
                            elif kind == b"L":
                                for name in json.loads(payload):
                                    print(name)
                                return 0
                            elif kind == b"D":
                                return 0
                            elif kind == b"X":
                                status = json.loads(payload)
                                return status if status >= 0 else 128 - status
                            elif kind == b"E":
                                raise ValueError(json.loads(payload))
                            else:
                                raise ValueError("Unexpected session protocol message")
        finally:
            selector.close()
            process.stdin.close()
            process.stdout.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def run(self):
        delay = 1
        try:
            while True:
                result = self.connection()
                if result is not None:
                    return result
                if self.generation is None:
                    raise ValueError("SSH disconnected before attaching to the session")
                # Disconnected keystrokes are discarded, never executed later in a different context.
                selector = selectors.DefaultSelector()
                try:
                    selector.register(0, selectors.EVENT_READ)
                    deadline = time.monotonic() + delay
                    while time.monotonic() < deadline:
                        if selector.select(max(0, deadline - time.monotonic())) and not os.read(
                            0, CHUNK
                        ):
                            return 0
                finally:
                    selector.close()
                delay = min(delay * 2, 10)
        finally:
            try:
                if self.original_termios is not None:
                    write_all(
                        1,
                        b"\x1b[?1049l\x1b[?2004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[0m\x1b[?25h",
                    )
            finally:
                self.restore()


def management_request(action, session=None):
    return {
        "name": session["name"] if session else "",
        "action": action,
        "client": uuid.uuid4().hex,
        "generation": session.get("generation") if session else None,
        "size": [24, 80],
        "term": "xterm-256color",
        "details": True,
        "existing_only": True,
    }


def management_response(returncode, output, action):
    for kind, payload in Decoder().feed(output):
        if kind == b"E":
            raise ValueError(json.loads(payload))
        if kind == (b"L" if action == "list" else b"D") and not returncode:
            return json.loads(payload)
    raise ValueError("Could not " + action + " sessions; check the SSH connection")


def manage_sessions(args, remote_command, action, session=None):
    try:
        result = subprocess.run(
            ssh_command(args, remote_command),
            input=json_frame(b"H", management_request(action, session)),
            stdout=subprocess.PIPE,
            timeout=40,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("Session query timed out") from error
    return management_response(result.returncode, result.stdout, action)


def normalize_sessions(sessions):
    # Previous proxies may only provide names; never infer attachment state from that.
    return [{"name": session} if isinstance(session, str) else session for session in sessions]


def hosts_file():
    return Path(os.environ.get("WARP_SSH_HOSTS_FILE", Path.home() / ".warp/ssh-session-hosts.json"))


def read_hosts():
    try:
        records = json.loads(hosts_file().read_text())
    except FileNotFoundError:
        return []
    if not isinstance(records, list):
        raise TypeError("Invalid saved SSH hosts file")
    return records


def connection_arguments(args):
    arguments = [args.destination]
    for flag, value in (("-p", args.port), ("-i", args.identity), ("-J", args.jump)):
        if value is not None:
            arguments.extend([flag, str(value)])
    for value in args.ssh_options:
        arguments.extend(["-o", value])
    if args.forward_agent:
        arguments.append("-A")
    if args.no_forward_agent:
        arguments.append("-a")
    return arguments


def host_identity(args):
    routing = [args.destination, args.port, args.identity, args.jump, args.ssh_options]
    return hashlib.sha256(json.dumps(routing).encode()).hexdigest()


def saved_host(record):
    if not isinstance(record, dict) or not isinstance(record.get("arguments"), list):
        raise TypeError("Invalid saved SSH host")
    if not all(isinstance(argument, str) for argument in record["arguments"]):
        raise ValueError("Invalid saved SSH arguments")
    digest = record.get("helper")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Invalid saved SSH helper")
    try:
        args = parse_args(record["arguments"])
    except SystemExit as error:
        raise ValueError("Invalid saved SSH arguments") from error
    if (
        not args.destination
        or args.list
        or args.select
        or args.detach
        or args.kill
        or not args.generated_name
    ):
        raise ValueError("Invalid saved SSH connection")
    args.name = None
    args.generated_name = False
    args.select = True
    command = '"$HOME/.warp/ssh-sessions/v1/helper-' + digest + '" proxy'
    return args, command


def remember_host(args):
    path = hosts_file()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        records = [
            record
            for record in read_hosts()
            if host_identity(saved_host(record)[0]) != host_identity(args)
        ]
        records.append({"arguments": connection_arguments(args), "helper": args.helper_digest})
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", dir=path.parent, prefix=".ssh-hosts-", delete=False
            ) as output:
                temporary = Path(output.name)
                json.dump(records, output)
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def remember_host_if_possible(args):
    try:
        remember_host(args)
    except (OSError, TypeError, ValueError) as error:
        print(f"Warp SSH: could not remember this host: {error}", file=sys.stderr)


class SessionRefresh:
    def __init__(self, args, remote_command):
        self.command = ssh_command(args, remote_command, reconnect=True)
        self.process = None
        self.output = bytearray()
        self.next_update = time.monotonic() + 5
        self.started = 0

    def poll(self):
        try:
            if self.process is None:
                if time.monotonic() < self.next_update:
                    return None
                self.process = subprocess.Popen(
                    self.command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                self.started = time.monotonic()
                self.output.clear()
                self.process.stdin.write(json_frame(b"H", management_request("list")))
                self.process.stdin.close()
                os.set_blocking(self.process.stdout.fileno(), False)
            returncode = self.process.poll()
            while True:
                try:
                    chunk = os.read(self.process.stdout.fileno(), CHUNK)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                self.output.extend(chunk)
                if len(self.output) > MAX_FRAME + HEADER.size:
                    raise ValueError("Session list is too large")
            if time.monotonic() - self.started > 40:
                raise ValueError("Session query timed out")
            if returncode is None:
                return None
            result = normalize_sessions(management_response(returncode, self.output, "list"))
            self.close()
            return result
        except (OSError, ValueError):
            self.close()
            raise

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
            self.process.stdout.close()
            self.process = None
        self.next_update = time.monotonic() + 5


class HostsRefresh:
    def __init__(self, records, overrides):
        self.hosts = {}
        self.sessions = {}
        self.unavailable = set()
        self.pending = set()
        for record in records:
            args, command = saved_host(record)
            if overrides.forward_agent or overrides.no_forward_agent:
                args.forward_agent = overrides.forward_agent
                args.no_forward_agent = overrides.no_forward_agent
            identity = host_identity(args)
            refresh = SessionRefresh(args, command)
            refresh.next_update = 0
            self.hosts[identity] = (args, command, refresh)
            self.pending.add(identity)

    @property
    def status(self):
        if self.unavailable:
            names = sorted(self.hosts[identity][0].destination for identity in self.unavailable)
            return "Unavailable: " + ", ".join(names)
        if self.pending:
            return f"Checking {len(self.pending)} hosts…"
        return None

    def poll(self):
        changed = False
        active = sum(refresh.process is not None for _, _, refresh in self.hosts.values())
        for identity, (args, _, refresh) in self.hosts.items():
            if refresh.process is None and active >= 4:
                continue
            was_active = refresh.process is not None
            try:
                updated = refresh.poll()
                if updated is not None:
                    session_rows(updated)
                    host = args.destination + (f":{args.port}" if args.port else "")
                    self.sessions[identity] = [
                        dict(session, host=host, host_id=identity) for session in updated
                    ]
                    self.unavailable.discard(identity)
                    self.pending.discard(identity)
                    changed = True
            except (OSError, ValueError):
                self.sessions.pop(identity, None)
                self.unavailable.add(identity)
                self.pending.discard(identity)
                changed = True
            active += int(refresh.process is not None) - int(was_active)
        if changed:
            return sorted(
                [session for sessions in self.sessions.values() for session in sessions],
                key=lambda session: (session["host"], session["name"], session["host_id"]),
            )
        return None

    def close(self):
        for _, _, refresh in self.hosts.values():
            refresh.close()


def session_rows(sessions):
    rows = []
    for index, session in enumerate(sessions, 1):
        name = session["name"]
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", name):
            raise ValueError("Invalid session name in remote session list")
        state = session.get("state", "unknown")
        if state not in ("attached", "detached", "exited"):
            state = "unknown (older or unavailable supervisor)"
        label = f"{session['host']} / {name}" if session.get("host") else name
        rows.append(f"{index:>2}. {label} — {state}")
    return rows


def host_rows(hosts):
    rows = []
    for index, host in enumerate(hosts, 1):
        rows.extend(
            [
                f"{index:>2}. {host['host']}",
                f"    Jump host: {host.get('jump') or 'SSH config default'}",
                f"    Identity: {host.get('identity') or 'SSH config default'}",
            ]
        )
    return [
        "".join(character if character.isprintable() else "?" for character in row) for row in rows
    ]


def picker_screen(sessions, destination, selected, typed, size, error=None, host_selection=False):
    width, height = max(1, size.columns or 80), max(4, size.lines or 24)
    row_stride = 3 if host_selection else 1
    row_height = row_stride if height >= 8 else 1
    visible = max(1, (height - 4) // row_height)
    start = (max(0, selected) // visible) * visible
    rows = host_rows(sessions) if host_selection else [" 0. NEW"] + session_rows(sessions)
    count = len(sessions) + int(not host_selection)
    title = (
        "New session — choose a host" if host_selection else f"Warp SSH sessions on {destination}"
    )
    lines = [title[:width]]
    if height >= 5:
        lines.append("")
    for index in range(start, min(start + visible, count)):
        for offset in range(row_height):
            line = rows[index * row_stride + offset][:width]
            if index == selected and offset == 0:
                line = "\x1b[7m" + line + "\x1b[0m"
            lines.append(line)
    if not count:
        lines.append("No remembered hosts."[:width])
    if host_selection:
        actions = "Enter: create session"
    elif selected == 0:
        actions = "Enter: choose host"
    else:
        actions = "Enter: take over | A: attach | D: detach | K: kill"
    lines.append(actions[:width])
    position = typed or (str(selected + int(host_selection)) if selected >= 0 else "—")
    kind = "Host" if host_selection else "Session"
    status = f"{kind} number: {position} / {len(sessions)}"
    if error:
        status = (
            error if isinstance(error, str) else "Connection unavailable; retrying automatically."
        )
    lines.append(status[:width])
    return "\x1b[H\x1b[2J" + "\r\n".join(lines)


def read_picker_key():
    key = os.read(0, 1)
    if key == b"\x1b":
        while len(key) < 8 and select.select([0], [], [], 0.1)[0]:
            next_byte = os.read(0, 1)
            if not next_byte:
                break
            key += next_byte
            if len(key) >= 3 and 0x40 <= key[-1] <= 0x7E:
                break
    return key


def pick_session(sessions, destination, refresh=None, *, host_selection=False):
    offset = int(not host_selection)
    if not (sys.stdin.isatty() and sys.stdout.isatty()) or os.environ.get("TERM") == "dumb":
        rows = host_rows(sessions) if host_selection else [" 0. NEW"] + session_rows(sessions)
        print("\n".join(rows) if rows else "No entries found.")
        prompt = (
            "\nHost number to create a session: "
            if host_selection
            else "\nSelection number, or A/D/K followed by a session number: "
        )
        choice = input(prompt).strip().lower()
        if choice in ("q", "\x1b", ""):
            return "q", None
        parts = choice.split()
        action, number = ("t", parts[0]) if len(parts) == 1 else (parts[0], parts[-1])
        if (
            action in ("a", "t", "d", "k")
            and number.isdecimal()
            and int(host_selection) <= int(number) <= len(sessions)
        ):
            if host_selection:
                return ("n", sessions[int(number) - 1]) if action == "t" else ("b", None)
            if int(number) == 0:
                return ("n", None) if action == "t" else ("b", None)
            return action, sessions[int(number) - 1]
        return "b", None
    original = termios.tcgetattr(0)
    selected = 0 if sessions or offset else -1
    typed = ""
    error = None
    try:
        tty.setraw(0)
        write_all(1, b"\x1b[?1049h\x1b[?25l")
        while True:
            if refresh is not None:
                try:
                    updated = refresh.poll()
                    if updated is not None:
                        session_rows(updated)
                        new_selected = bool(offset and selected == 0)
                        previous = sessions[selected - offset] if selected >= offset else None
                        selected = (
                            0
                            if new_selected
                            else next(
                                (
                                    i + offset
                                    for i, session in enumerate(updated)
                                    if previous
                                    and session.get("host_id") == previous.get("host_id")
                                    and session["name"] == previous["name"]
                                    and session.get("generation") == previous.get("generation")
                                ),
                                -1,
                            )
                        )
                        if [(s.get("host_id"), s["name"]) for s in sessions] != [
                            (s.get("host_id"), s["name"]) for s in updated
                        ] or selected < 0:
                            typed = ""
                        sessions = updated
                        error = None
                except (OSError, ValueError) as failure:
                    error = failure
            screen = picker_screen(
                sessions,
                destination,
                selected,
                typed,
                os.get_terminal_size(1),
                error or getattr(refresh, "status", None),
                host_selection,
            )
            write_all(1, screen.encode())
            if not select.select([0], [], [], 1)[0]:
                continue
            key = read_picker_key()
            if key in (b"q", b"Q", b"\x1b", b"\x04", b""):
                return "q", None
            if key == b"\x03":
                raise KeyboardInterrupt
            if key in (b"\x1b[A", b"\x1bOA"):
                selected = max(0, selected - 1) if sessions or offset else -1
                typed = ""
            elif key in (b"\x1b[B", b"\x1bOB"):
                selected = min(len(sessions) + offset - 1, selected + 1)
                typed = ""
            elif key in (b"\r", b"\n", b"a", b"A", b"t", b"T", b"d", b"D", b"k", b"K"):
                if selected >= 0 and (
                    not typed or int(host_selection) <= int(typed) <= len(sessions)
                ):
                    action = "t" if key in (b"\r", b"\n") else key.decode().lower()
                    if host_selection:
                        if key not in (b"\r", b"\n"):
                            continue
                        return "n", sessions[selected]
                    if selected == 0:
                        if key in (b"\r", b"\n"):
                            return "n", None
                        continue
                    return action, sessions[selected - offset]
            elif key in (b"\x7f", b"\x08"):
                typed = typed[:-1]
            elif key in b"0123456789" and len(typed) < len(str(len(sessions))):
                typed += key.decode()
            if typed and int(host_selection) <= int(typed) <= len(sessions):
                selected = int(typed) - int(host_selection)
    finally:
        try:
            write_all(1, b"\x1b[0m\x1b[?25h\x1b[?1049l")
        finally:
            termios.tcsetattr(0, termios.TCSADRAIN, original)


def session_action(args, remote_command, action, session):
    label = f"{args.destination} / {session['name']}"
    print(f"\nSelected: {label}")
    if action == "k":
        confirm = input(f"Kill {label} and delete its retained output? Type kill to confirm: ")
        if confirm.strip() != "kill":
            print("Cancelled.")
            return None
        manage_sessions(args, remote_command, "kill", session)
        print(f"Killed {session['name']}.")
        return None
    if action in ("d", "t"):
        manage_sessions(args, remote_command, "detach", session)
        if action == "d":
            return None
    if action in ("a", "t"):
        args.name = session["name"]
        args.existing_only = True
        args.selected_generation = session.get("generation")
        return Client(args, remote_command).run()
    return None


def new_session(overrides):
    profiles = {}
    hosts = []
    for record in read_hosts():
        args, _ = saved_host(record)
        if overrides.forward_agent or overrides.no_forward_agent:
            args.forward_agent = overrides.forward_agent
            args.no_forward_agent = overrides.no_forward_agent
        identity = host_identity(args)
        if identity in profiles:
            continue
        profiles[identity] = args
        hosts.append(
            {
                "name": identity,
                "host": args.destination + (f":{args.port}" if args.port else ""),
                "jump": args.jump,
                "identity": args.identity,
            }
        )
    if not hosts:
        print("No remembered hosts yet. Run ssh-session HOST --list once to add a host.")
        return None
    hosts.sort(key=lambda host: (host["host"], host["name"]))
    action, selected = pick_session(hosts, "", host_selection=True)
    if action != "n" or selected is None:
        return None
    args = profiles[selected["name"]]
    args.select = False
    args.name = time.strftime("%Y.%m.%d-%H:%M:%S", time.localtime())
    args.generated_name = True
    command = install(args)
    remember_host_if_possible(args)
    print(f"Warp SSH session: {args.name} (reattach with --name {args.name})", file=sys.stderr)
    return Client(args, command).run()


def select_all_hosts(overrides):
    while True:
        records = read_hosts()
        if not records:
            print(
                "No remembered hosts yet. Run warp-oss ssh-session HOST --list once to add a host."
            )
            return 0
        refresh = HostsRefresh(records, overrides)
        try:
            action, session = pick_session([], "all remembered hosts", refresh)
        finally:
            refresh.close()
        if action == "q":
            return 0
        try:
            if action == "n":
                result = new_session(overrides)
                if result is not None:
                    return result
                continue
            if session is None:
                continue
            args, command, _ = refresh.hosts[session["host_id"]]
            if action in ("a", "t"):
                command = install(args)
                remember_host_if_possible(args)
            result = session_action(args, command, action, session)
            if result is not None:
                return result
        except EOFError:
            return 0
        except (OSError, ValueError) as error:
            print(f"Warp SSH session: {error}")


def select_session(args, remote_command):
    while True:
        print(f"\nWarp SSH sessions on {args.destination}")
        try:
            sessions = manage_sessions(args, remote_command, "list")
            sessions = normalize_sessions(sessions)
        except (OSError, ValueError) as error:
            print(str(error))
            sessions = []
        try:
            refresh = SessionRefresh(args, remote_command)
            try:
                action, session = pick_session(sessions, args.destination, refresh)
            finally:
                refresh.close()
            if action == "q":
                return 0
            if action == "n":
                result = new_session(args)
                if result is not None:
                    return result
                continue
            if session is None:
                continue
            result = session_action(args, remote_command, action, session)
            if result is not None:
                return result
        except EOFError:
            return 0
        except (OSError, ValueError) as error:
            print(f"Warp SSH session: {error}")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Warp persistent SSH sessions")
    parser.add_argument("destination", nargs="?")
    parser.add_argument("--name", help="Session name (creation timestamp when omitted)")
    operations = parser.add_mutually_exclusive_group()
    for operation in ("list", "select", "detach", "kill"):
        operations.add_argument("--" + operation, action="store_true")
    parser.add_argument("-p", "--port", type=int)
    parser.add_argument("-i", "--identity")
    parser.add_argument("-J", "--jump")
    forwarding = parser.add_mutually_exclusive_group()
    forwarding.add_argument("-A", "--forward-agent", action="store_true")
    forwarding.add_argument("-a", "--no-forward-agent", action="store_true")
    parser.add_argument("-o", dest="ssh_options", action="append", default=[])
    args = parser.parse_args(argv)
    if args.destination is None:
        if (
            args.name is not None
            or args.list
            or args.detach
            or args.kill
            or args.port is not None
            or args.identity is not None
            or args.jump is not None
            or args.ssh_options
        ):
            parser.error(
                "A host is required for named sessions, management operations and connection options"
            )
        args.select = True
        args.generated_name = False
        return args
    if (
        not args.destination
        or args.destination.startswith("-")
        or any(not c.isprintable() for c in args.destination)
    ):
        parser.error("Invalid SSH destination")
    if (args.detach or args.kill) and args.name is None:
        parser.error("--detach and --kill require --name")
    if args.select and args.name is not None:
        parser.error("--select cannot be combined with --name")
    if args.name is not None and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", args.name):
        parser.error(
            "Invalid session name: use 1–64 letters, digits, dots, colons, underscores or hyphens"
        )
    args.generated_name = args.name is None and not (args.list or args.select)
    if args.generated_name:
        args.name = time.strftime("%Y.%m.%d-%H:%M:%S", time.localtime())
    return args


def main():
    args = parse_args()
    if not (args.list or args.detach or args.kill) and not (os.isatty(0) and os.isatty(1)):
        raise ValueError("Attaching requires an interactive terminal")
    if args.generated_name:
        print(f"Warp SSH session: {args.name} (reattach with --name {args.name})", file=sys.stderr)
    if not (args.list or args.detach or args.kill) and not parent_session_id():
        print(
            "Warp SSH: shell integration requires a new pane in the updated Warp app; continuing with native shell input.",
            file=sys.stderr,
        )
    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, lambda number, _frame: sys.exit(128 + number))
    if args.destination is None:
        return select_all_hosts(args)
    remote_command = install(args)
    remember_host_if_possible(args)
    if args.select:
        return select_session(args, remote_command)
    client = Client(args, remote_command)
    return client.run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, TypeError, ValueError, KeyboardInterrupt) as error:
        print("Warp SSH session: " + str(error), file=sys.stderr)
        sys.exit(1)

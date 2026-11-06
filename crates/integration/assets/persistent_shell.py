"""Launch the supervisor's Bash bootstrap in a hermetic GUI test."""

import fcntl
import json
import os
import pty
import select
import signal
import sys
import termios
import time
import tty
from pathlib import Path

from persistent_client import ReplayFilter

hook = {
    "hook": "SSH",
    "value": {
        "session_id": int(os.environ["WARP_SESSION_ID"]),
        "remote_session_id": 424242,
        "remote_shell": "bash",
        "socket_path": "",
        "persistent_session": True,
    },
}
registration = b"\x1b]9278;d;" + json.dumps(hook).encode().hex().encode() + b"\x07"
os.environ["WARP_SESSION_ID"] = "424242"
os.environ["WARP_IS_SSH"] = "1"
os.environ.pop("WARP_BOOTSTRAPPED", None)
os.environ["WARP_INITIAL_WORKING_DIR"] = str(Path.home() / "remote-files")
command = ["bash", "--noprofile", "--rcfile", str(Path.home() / "persistent-bootstrap.sh"), "-i"]
if "--resume" not in sys.argv:
    os.write(1, registration)
    os.execv("/bin/bash", command)

pid, master = pty.fork()
if pid == 0:
    os.execv("/bin/bash", command)

saved_tty = termios.tcgetattr(0)
fcntl.ioctl(master, termios.TIOCSWINSZ, fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))
signal.signal(signal.SIGHUP, lambda *_: sys.exit(1))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
try:
    snapshot = ReplayFilter(session_id=424242)
    deadline = time.monotonic() + 20

    def receive():
        if not select.select([master], [], [], max(0, deadline - time.monotonic()))[0]:
            raise RuntimeError("Timed out starting detached Bash")
        data = os.read(master, 65536)
        snapshot.feed(data, True)
        return data

    while "Bootstrapped" not in snapshot.hooks or "Precmd" not in snapshot.hooks:
        receive()
    os.write(
        master,
        b"saved=preserved; printf '\\nWAITING\\n'; read -r restored_input; printf '\\nRESUMED:%s:%s\\n' \"$saved\" \"$restored_input\"\n",
    )
    output = bytearray()
    while b"\r\nWAITING\r\n" not in output:
        output.extend(receive())
    tty.setraw(0)
    os.write(1, registration + snapshot.restore_hooks())
    while True:
        ready, _, _ = select.select([0, master], [], [])
        for fd in ready:
            data = os.read(fd, 65536)
            if not data:
                sys.exit(0)
            os.write(master if fd == 0 else 1, data)
finally:
    termios.tcsetattr(0, termios.TCSANOW, saved_tty)
    os.close(master)
    os.kill(pid, signal.SIGHUP)
    os.waitpid(pid, 0)

"""Protocol and real-PTY lifecycle tests; no account or SSH host is required."""

import collections
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import pty
import select
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


client = load("client")
HELPER = os.environ.get(
    "WARP_SSH_HELPER_BINARY",
    str(Path(__file__).resolve().parents[3] / "target/debug/warp_ssh_helper"),
)


class Proxy:
    def __init__(self, env, request):
        self.process = subprocess.Popen(
            [HELPER, "proxy"],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.decoder = client.Decoder()
        self.messages = collections.deque()
        self.cursor = request.get("offset", 0)
        self.sequence = 1
        self.send(b"H", json.dumps(request).encode())

    def send(self, kind, data):
        self.process.stdin.write(client.frame(kind, data))
        self.process.stdin.flush()

    def input(self, data):
        self.send(b"I", client.NUMBER.pack(self.sequence) + data)
        self.sequence += 1

    def next(self, timeout=10):
        deadline = time.monotonic() + timeout
        while not self.messages:
            if not select.select(
                [self.process.stdout], [], [], max(0, deadline - time.monotonic())
            )[0]:
                raise AssertionError("Timed out waiting for session output")
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                raise AssertionError("Session ended: " + self.process.stderr.read().decode())
            self.messages.extend(self.decoder.feed(data))
        kind, payload = self.messages.popleft()
        if kind == b"O":
            offset = client.NUMBER.unpack_from(payload)[0]
            if offset != self.cursor:
                raise AssertionError("Output was lost or duplicated")
            self.cursor += len(payload) - client.NUMBER.size
        return kind, payload

    def until(self, marker):
        output = bytearray()
        deadline = time.monotonic() + 10
        while marker not in output:
            kind, payload = self.next(max(0, deadline - time.monotonic()))
            if kind == b"O":
                output.extend(payload[8:])
            elif kind == b"E":
                raise AssertionError(json.loads(payload))
        return bytes(output)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=5)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


class ArgumentTests(unittest.TestCase):
    def test_no_host_opens_the_combined_picker(self):
        args = client.parse_args([])
        self.assertIsNone(args.destination)
        self.assertIsNone(args.name)
        self.assertTrue(args.select)
        self.assertFalse(args.generated_name)

    def test_named_session_requires_a_host(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            client.parse_args(["--name", "work"])

    def test_picker_does_not_generate_a_name(self):
        args = client.parse_args(["host", "--select"])
        self.assertIsNone(args.name)
        self.assertFalse(args.generated_name)

    def test_picker_rejects_named_session(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            client.parse_args(["host", "--select", "--name", "work"])

    def test_unnamed_connections_use_local_creation_time(self):
        with mock.patch.object(
            client.time,
            "localtime",
            return_value=time.struct_time((2026, 11, 6, 19, 5, 9, 4, 310, -1)),
        ):
            first = client.parse_args(["host"])
        self.assertEqual(first.name, "2026.11.06-19:05:09")
        self.assertTrue(first.generated_name)
        connection = client.Client(first, "helper")
        with mock.patch.object(client, "terminal_size", return_value=[24, 80]):
            self.assertTrue(connection.request()["create_only"])
            connection.generation = "original-shell"
            self.assertFalse(connection.request()["create_only"])

    def test_timestamp_name_can_be_used_for_reattachment(self):
        args = client.parse_args(["host", "--name", "2026.11.06-19:05:09"])
        self.assertEqual(args.name, "2026.11.06-19:05:09")
        self.assertFalse(args.generated_name)

    def test_explicit_name_is_preserved(self):
        args = client.parse_args(["host", "--name", "work-agent"])
        self.assertEqual(args.name, "work-agent")
        self.assertFalse(args.generated_name)

    def test_listing_does_not_generate_a_name(self):
        args = client.parse_args(["host", "--list"])
        self.assertIsNone(args.name)
        self.assertFalse(args.generated_name)
        self.assertEqual(client.Client(args, "helper").request()["name"], "")

    def test_management_requires_explicit_name(self):
        for operation in ("--detach", "--kill"):
            with self.subTest(operation=operation), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    client.parse_args(["host", operation])
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(
                    client.parse_args(["host", operation, "--name", "work"]).name, "work"
                )

    def test_empty_explicit_name_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            client.parse_args(["host", "--name", ""])
        self.assertEqual(error.exception.code, 2)


class HostRegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name, "hosts.json")
        self.environment = mock.patch.dict(os.environ, WARP_SSH_HOSTS_FILE=str(self.path))
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.directory.cleanup()

    def test_remembered_host_preserves_routing_and_updates_forwarding(self):
        args = client.parse_args(
            [
                "host",
                "-A",
                "-i",
                "/key with spaces",
                "-J",
                "jump",
                "-o",
                "ProxyCommand=ssh jump -W %h:%p",
            ]
        )
        args.helper_digest = "a" * 64
        client.remember_host(args)
        args.forward_agent = False
        args.no_forward_agent = True
        client.remember_host(args)
        records = client.read_hosts()
        self.assertEqual(len(records), 1)
        saved, command = client.saved_host(records[0])
        self.assertEqual(saved.destination, "host")
        self.assertEqual(saved.identity, "/key with spaces")
        self.assertEqual(saved.jump, "jump")
        self.assertEqual(saved.ssh_options, ["ProxyCommand=ssh jump -W %h:%p"])
        self.assertTrue(saved.no_forward_agent)
        self.assertFalse(saved.forward_agent)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertIn("helper-" + "a" * 64, command)

    def test_distinct_ports_are_distinct_hosts(self):
        first = client.parse_args(["host", "-p", "2222"])
        first.helper_digest = "a" * 64
        second = client.parse_args(["host", "-p", "2223"])
        second.helper_digest = "b" * 64
        client.remember_host(first)
        client.remember_host(second)
        self.assertEqual(len(client.read_hosts()), 2)
        self.assertNotEqual(client.host_identity(first), client.host_identity(second))

    def test_empty_registry_does_not_create_a_session(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(client.select_all_hosts(client.parse_args([])), 0)
        self.assertIn("No remembered hosts", output.getvalue())
        self.assertFalse(self.path.exists())

    def test_saved_helper_must_be_a_digest(self):
        with self.assertRaisesRegex(ValueError, "Invalid saved SSH helper"):
            client.saved_host({"arguments": ["host"], "helper": "$(echo injected)"})


class ProtocolTests(unittest.TestCase):
    def test_picker_shows_one_row_per_session(self):
        rows = client.session_rows(
            [
                {
                    "name": "work",
                    "host": "test-host",
                    "created_at": 100,
                    "last_interaction_at": 200,
                    "state": "attached",
                    "shell_pid": 42,
                    "output_bytes": 2048,
                },
                {"name": "older", "created_at": 100, "created_at_estimated": True},
            ]
        )
        self.assertEqual(
            rows,
            [
                " 1. test-host / work — attached",
                " 2. older — unknown (older or unavailable supervisor)",
            ],
        )

    def test_detailed_listing_falls_back_for_an_older_supervisor(self):
        with tempfile.TemporaryDirectory(prefix="wss-", dir="/tmp") as root:
            directory = Path(root, hashlib.sha256(b"older").hexdigest()[:24])
            directory.mkdir(mode=0o700)
            (directory / "name").write_text("older")
            (directory / "output").write_bytes(b"retained")
            with (directory / "lock").open("w") as lock, socket.socket(socket.AF_UNIX) as listener:
                fcntl.flock(lock, fcntl.LOCK_EX)
                listener.bind(str(directory / "socket"))
                listener.listen()
                listener.settimeout(5)
                peer = Proxy(
                    dict(os.environ, WARP_SSH_SESSION_DIR=root),
                    {
                        "name": "",
                        "action": "list",
                        "details": True,
                        "client": uuid.uuid4().hex,
                        "size": [24, 80],
                        "term": "xterm",
                    },
                )
                try:
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(5)
                        stream.recv(4096)
                        stream.sendall(client.json_frame(b"E", "unknown action status"))
                    kind, payload = peer.next()
                    self.assertEqual(kind, b"L")
                    info = json.loads(payload)[0]
                    self.assertEqual(info["name"], "older")
                    self.assertEqual(info["state"], "unknown")
                    self.assertTrue(info["created_at_estimated"])
                    self.assertIsNotNone(info["created_at"])
                    self.assertIsNone(info["last_interaction_at"])
                    self.assertEqual(info["output_bytes"], 8)
                finally:
                    peer.close()

    def test_reattach_restores_only_current_shell_state(self):
        replay = client.ReplayFilter(session_id=42)
        history = b"".join(
            [
                client.shell_hook("InitShell", {"session_id": 42, "shell": "bash"}),
                client.shell_hook("Bootstrapped", {"session_id": 42, "path": "x" * 10000}),
                client.shell_hook(
                    "Precmd", {"session_id": 42, "pwd": "/old", "next_block_id": "1"}
                ),
                client.shell_hook("Preexec", {"session_id": 42, "command": "cd /work"}),
                client.shell_hook("CommandFinished", {"session_id": 42, "next_block_id": "2"}),
                client.shell_hook(
                    "Precmd", {"session_id": 42, "pwd": "/work", "next_block_id": "2"}
                ),
                client.shell_hook("Preexec", {"session_id": 42, "command": "cat"}),
                client.shell_hook("Precmd", {"session_id": 99, "pwd": "/wrong"}),
                client.shell_hook("FinishUpdate", {"session_id": 42}),
                b"\x1b]52;c;YWJj\x07output",
            ]
        )
        output = b"".join(replay.feed(history[i : i + 7], True) for i in range(0, len(history), 7))
        self.assertEqual(output, b"output")
        self.assertEqual(replay.hooks["Precmd"]["pwd"], "/work")
        self.assertEqual(replay.hooks["Preexec"]["command"], "cat")
        self.assertEqual(len(replay.hooks["Bootstrapped"]["path"]), 10000)
        self.assertEqual(
            set(replay.hooks), {"InitShell", "Bootstrapped", "Precmd", "Preexec", "CommandFinished"}
        )

    def test_completed_generator_preserves_prompt_metadata_on_reattach(self):
        replay = client.ReplayFilter(session_id=42)
        replay.feed(
            client.shell_hook("Precmd", {"session_id": 42, "pwd": "/work", "next_block_id": "1"}),
            True,
        )
        replay.feed(client.shell_hook("Preexec", {"session_id": 42, "command": "generator"}), True)
        replay.feed(
            client.shell_hook(
                "Precmd",
                {
                    "session_id": 42,
                    "pwd": "",
                    "next_block_id": "2",
                    "is_after_in_band_command": True,
                },
            ),
            True,
        )
        self.assertEqual(
            replay.hooks["Precmd"], {"session_id": 42, "pwd": "/work", "next_block_id": "2"}
        )
        self.assertNotIn("Preexec", replay.hooks)

    def test_dcs_hooks_are_recovered_across_replay_boundary(self):
        replay = client.ReplayFilter(session_id=42)
        hook = (
            b"\x1bP$d"
            + b'{"hook":"InitShell","value":{"session_id":42,"shell":"bash"}}'.hex().encode()
        )
        self.assertEqual(replay.feed(hook, True), b"")
        self.assertEqual(replay.feed(b"\x1b\\live", False), b"live")
        self.assertEqual(replay.hooks["InitShell"]["shell"], "bash")

    def test_live_hooks_follow_restored_state_when_replay_ends_mid_hook(self):
        replay = client.ReplayFilter(session_id=42)
        init = client.shell_hook("InitShell", {"session_id": 42, "shell": "bash"})
        bootstrapped = client.shell_hook("Bootstrapped", {"session_id": 42})
        replay.feed(init[:-1], True)
        output, restored = replay.finish_replay(init[-1:] + bootstrapped)
        self.assertTrue(restored)
        self.assertEqual(output, init + bootstrapped)

    def test_replayed_completion_output_stays_hidden_across_replay_boundary(self):
        replay = client.ReplayFilter()
        self.assertEqual(replay.feed(b"before\x1b]9277;A\x07encoded", True), b"before")
        self.assertEqual(replay.feed(b"payload\x1b]9277;B\x07after", False), b"after")

    def test_fragmented_frames_and_binary_payloads(self):
        decoder = client.Decoder()
        data = client.frame(b"O", b"\0\xff\x1b[31m")
        self.assertEqual(decoder.feed(data[:3]), [])
        self.assertEqual(decoder.feed(data[3:7]), [])
        self.assertEqual(decoder.feed(data[7:]), [(b"O", b"\0\xff\x1b[31m")])

    def test_oversized_frame_is_rejected_before_allocating_payload(self):
        with self.assertRaises(ValueError):
            client.Decoder().feed(client.HEADER.pack(b"O", 1024 * 1024 + 1))

    def test_replay_preserves_colors_but_does_not_reexecute_terminal_queries(self):
        replay = client.ReplayFilter()
        self.assertEqual(replay.feed(b"\x1b[31mred\x1b[0m\x1b[6", True), b"\x1b[31mred\x1b[0m")
        self.assertEqual(replay.feed(b"n\x1b]52;c;YWJj\x07tail", True), b"tail")
        self.assertEqual(
            replay.feed(b"\x1b[6n\x1b]52;c;YWJj\x07", False), b"\x1b[6n\x1b]52;c;YWJj\x07"
        )

    def test_replay_string_can_cross_into_live_output(self):
        replay = client.ReplayFilter()
        self.assertEqual(replay.feed(b"\x1b]52;c;abc", True), b"")
        self.assertEqual(replay.feed(b"\x1b\\live", False), b"live")

    def test_forwarding_to_an_older_supervisor_reports_upgrade_requirement(self):
        with tempfile.TemporaryDirectory(prefix="wss-", dir="/tmp") as root:
            directory = Path(root, hashlib.sha256(b"test").hexdigest()[:24])
            directory.mkdir(mode=0o700)
            with (directory / "lock").open("w") as lock, socket.socket(socket.AF_UNIX) as listener:
                fcntl.flock(lock, fcntl.LOCK_EX)
                listener.bind(str(directory / "socket"))
                listener.listen()
                listener.settimeout(5)
                peer = Proxy(
                    dict(
                        os.environ, WARP_SSH_SESSION_DIR=root, SSH_AUTH_SOCK="/tmp/forwarded-agent"
                    ),
                    {
                        "name": "test",
                        "action": "attach",
                        "client": uuid.uuid4().hex,
                        "size": [24, 80],
                        "term": "xterm",
                    },
                )
                try:
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(5)
                        stream.recv(4096)
                        stream.sendall(client.json_frame(b"H", {"generation": "legacy"}))
                        kind, payload = peer.next()
                        self.assertEqual(kind, b"E")
                        self.assertIn("predates agent forwarding", json.loads(payload))
                finally:
                    peer.close()


class PickerTests(unittest.TestCase):
    def setUp(self):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        self.process = None

    def tearDown(self):
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)

    def start(self):
        program = (
            "import sys; sys.path.insert(0, sys.argv[1]); import client; "
            "sessions = [{'name': 'first'}, {'name': 'second'}, {'name': 'third'}]; "
            "print('CHOICE:' + client.json.dumps(client.pick_session(sessions, 'test-host')))"
        )
        self.run_program(program)
        return self.until(b"Session number:")

    def run_program(self, program, *args):
        self.process = subprocess.Popen(
            [sys.executable, "-c", program, str(Path(__file__).parent), *args],
            env={**os.environ, "TERM": "xterm-256color"},
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
        )

    def until(self, marker):
        output = bytearray()
        deadline = time.monotonic() + 5
        while marker not in output:
            if not select.select([self.master], [], [], max(0, deadline - time.monotonic()))[0]:
                self.fail(f"Picker did not display {marker!r}: {output!r}")
            output.extend(os.read(self.master, 65536))
        return bytes(output)

    def test_arrow_keys_highlight_and_select_a_session(self):
        self.assertIn(b"\x1b[7m 0. NEW", self.start())
        os.write(self.master, b"\x1b[B\x1b[B\x1b[B\x1b[A")
        self.until(b"\x1b[7m 2. second")
        os.write(self.master, b"\r")
        self.assertIn(b'CHOICE:["t", {"name": "second"}]', self.until(b"CHOICE:"))
        self.process.wait(timeout=5)
        self.assert_terminal_restored()

    def test_numeric_selection_still_works(self):
        screen = self.start()
        self.assertIn(b"Session number: 0 / 3", screen)
        os.write(self.master, b"3\r")
        self.assertIn(b'CHOICE:["t", {"name": "third"}]', self.until(b"CHOICE:"))

    def test_zero_selects_new_from_a_session_row(self):
        self.start()
        os.write(self.master, b"\x1b[B")
        screen = self.until(b"Session number: 1 / 3")
        self.assertIn(b"\x1b[7m 1. first", screen)
        os.write(self.master, b"0\r")
        self.assertIn(b'CHOICE:["n", null]', self.until(b"CHOICE:"))

    def test_new_is_available_without_selecting_an_existing_session(self):
        self.run_program(
            "import sys; sys.path.insert(0, sys.argv[1]); import client; "
            "print('CHOICE:' + client.json.dumps(client.pick_session([], 'test-host')))"
        )
        screen = self.until(b"Session number:")
        self.assertIn(b"\x1b[7m 0. NEW", screen)
        self.assertIn(b"Session number: 0 / 0", screen)
        self.assertNotIn(b"N: new", screen)
        os.write(self.master, b"\r")
        self.assertIn(b'CHOICE:["n", null]', self.until(b"CHOICE:"))

    def test_host_picker_selects_a_host_with_arrows_and_enter(self):
        self.run_program(
            "import sys; sys.path.insert(0, sys.argv[1]); import client; "
            "hosts = [{'name': 'one', 'host': 'first'}, {'name': 'two', 'host': 'second:2222'}]; "
            "print('CHOICE:' + client.json.dumps(client.pick_session(hosts, '', host_selection=True)))"
        )
        screen = self.until(b"Host number:")
        self.assertIn("New session — choose a host".encode(), screen)
        self.assertIn(b"Enter: create session", screen)
        self.assertNotIn(b"Age:", screen)
        os.write(self.master, b"\x1b[B\r")
        self.assertIn(
            b'CHOICE:["n", {"name": "two", "host": "second:2222"}]', self.until(b"CHOICE:")
        )
        self.process.wait(timeout=5)
        self.assert_terminal_restored()

    def test_session_shortcuts_do_not_act_on_new_row(self):
        self.start()
        os.write(self.master, b"ADKTN\x1b[B\r")
        self.assertIn(b'CHOICE:["t", {"name": "first"}]', self.until(b"CHOICE:"))

    def test_plain_picker_new_row_requires_selection(self):
        for choice, expected in [("0", ("n", None)), ("k 0", ("b", None))]:
            with (
                mock.patch("builtins.input", return_value=choice),
                mock.patch.object(sys.stdin, "isatty", return_value=False),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(client.pick_session([], "host"), expected)

    def test_escape_from_host_picker_returns_to_sessions_without_creating_one(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory, "hosts.json")
            registry.write_text(client.json.dumps([{"arguments": ["host"], "helper": "a" * 64}]))
            self.run_program(
                """
import os, sys
sys.path.insert(0, sys.argv[1])
import client
os.environ['WARP_SSH_HOSTS_FILE'] = sys.argv[2]
client.ssh_command = lambda *a, **kw: [sys.executable, '-c', 'raise SystemExit(255)']
print('EXIT:' + str(client.select_all_hosts(client.parse_args([]))))
""",
                str(registry),
            )
            self.until(b"Enter: choose host")
            os.write(self.master, b"\r")
            self.until(b"Host number:")
            os.write(self.master, b"\x1b")
            self.until(b"Enter: choose host")
            os.write(self.master, b"\x1b")
            self.assertIn(b"EXIT:0", self.until(b"EXIT:"))

    def test_quitting_restores_the_terminal(self):
        self.start()
        os.write(self.master, b"Q")
        self.assertIn(b'CHOICE:["q", null]', self.until(b"CHOICE:"))
        self.process.wait(timeout=5)
        self.assert_terminal_restored()

    def test_session_actions_are_available_without_entering_a_submenu(self):
        self.start()
        os.write(self.master, b"\x1b[B\x1b[B")
        screen = self.until(b"\x1b[7m 2. second")
        self.assertIn(b"A: attach | D: detach | K: kill", screen)
        self.assertNotIn(b"refresh", screen)
        self.assertNotIn(b"quit", screen)
        os.write(self.master, b"K")
        self.assertIn(b'CHOICE:["k", {"name": "second"}]', self.until(b"CHOICE:"))
        self.process.wait(timeout=5)
        self.assert_terminal_restored()

    def test_escape_exits_and_restores_the_terminal(self):
        self.start()
        os.write(self.master, b"\x1b")
        self.assertIn(b'CHOICE:["q", null]', self.until(b"CHOICE:"))
        self.process.wait(timeout=5)
        self.assert_terminal_restored()

    def test_escape_cancels_a_slow_background_query(self):
        self.run_program("""
import sys
sys.path.insert(0, sys.argv[1])
import client
refresh = client.SessionRefresh(client.parse_args(['host', '--select']), 'helper')
refresh.command = [sys.executable, '-c', 'import time; time.sleep(60)']
refresh.next_update = 0
try:
    choice = client.pick_session([{'name': 'work'}], 'test-host', refresh)
finally:
    refresh.close()
print('CHOICE:' + client.json.dumps(choice))
""")
        self.until(b"Session number:")
        os.write(self.master, b"\x1b")
        self.assertIn(b'CHOICE:["q", null]', self.until(b"CHOICE:"))
        self.process.wait(timeout=5)
        self.assert_terminal_restored()

    def start_refreshing(self, path):
        self.run_program(
            """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import client
class Refresh:
    def poll(self):
        path = Path(sys.argv[2])
        if path.exists():
            sessions = client.json.loads(path.read_text())
            path.unlink()
            return sessions
sessions = [{"name": "first"}, {"name": "second"}]
print('CHOICE:' + client.json.dumps(client.pick_session(sessions, 'test-host', Refresh())))
""",
            str(path),
        )
        return self.until(b"Session number:")

    def test_auto_refresh_preserves_the_highlighted_session(self):
        with tempfile.TemporaryDirectory() as directory:
            update = Path(directory, "update.json")
            self.start_refreshing(update)
            os.write(self.master, b"\x1b[B\x1b[B")
            self.until(b"\x1b[7m 2. second")
            pending = Path(directory, "pending.json")
            pending.write_text('[{"name":"added"},{"name":"first"},{"name":"second"}]')
            pending.rename(update)
            self.until(b"\x1b[7m 3. second")
            os.write(self.master, b"K")
            self.assertIn(b'CHOICE:["k", {"name": "second"}]', self.until(b"CHOICE:"))

    def test_auto_refresh_preserves_new_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            update = Path(directory, "update.json")
            self.start_refreshing(update)
            pending = Path(directory, "pending.json")
            pending.write_text('[{"name":"added"}]')
            pending.rename(update)
            screen = self.until(b"1. added")
            self.assertIn(b"\x1b[7m 0. NEW", screen)
            os.write(self.master, b"\r")
            self.assertIn(b'CHOICE:["n", null]', self.until(b"CHOICE:"))

    def test_disappearing_selection_requires_selecting_another_session(self):
        with tempfile.TemporaryDirectory() as directory:
            update = Path(directory, "update.json")
            self.start_refreshing(update)
            os.write(self.master, b"\x1b[B")
            self.until(b"\x1b[7m 1. first")
            pending = Path(directory, "pending.json")
            pending.write_text('[{"name":"second"}]')
            pending.rename(update)
            self.until("Session number: — / 1".encode())
            os.write(self.master, b"\r\x1b[B\x1b[BK")
            self.assertIn(b'CHOICE:["k", {"name": "second"}]', self.until(b"CHOICE:"))

    def test_combined_picker_does_not_switch_to_a_same_named_session_on_another_host(self):
        with tempfile.TemporaryDirectory() as directory:
            update = Path(directory, "update.json")
            self.start_refreshing(update)
            os.write(self.master, b"\x1b[B")
            self.until(b"\x1b[7m 1. first")
            pending = Path(directory, "pending.json")
            pending.write_text(
                '[{"name":"work","host":"one","host_id":"one"},{"name":"work","host":"two","host_id":"two"}]'
            )
            pending.rename(update)
            self.until("Session number: — / 2".encode())
            os.write(self.master, b"\x1b[B\x1b[B\x1b[B")
            self.until(b"\x1b[7m 2. two / work")
            pending.write_text('[{"name":"work","host":"one","host_id":"one"}]')
            pending.rename(update)
            self.until("Session number: — / 1".encode())
            os.write(self.master, b"\r\x1b[B\x1b[BK")
            self.assertIn(
                b'CHOICE:["k", {"name": "work", "host": "one", "host_id": "one"}]',
                self.until(b"CHOICE:"),
            )

    def assert_terminal_restored(self):
        restored = termios.tcgetattr(self.slave)
        expected = list(self.original)
        # macOS sets the kernel-managed PENDIN flag when restoring canonical input.
        restored[3] &= ~getattr(termios, "PENDIN", 0)
        expected[3] &= ~getattr(termios, "PENDIN", 0)
        self.assertEqual(restored, expected)

    def test_interrupt_restores_the_terminal(self):
        self.start()
        os.write(self.master, b"\x03")
        self.until(b"\x1b[?1049l")
        self.process.wait(timeout=5)
        self.assertNotEqual(self.process.returncode, 0)
        self.assert_terminal_restored()

    def test_scroll_keeps_the_selection_on_screen(self):
        screen = client.picker_screen(
            [{"name": "first"}, {"name": "second"}, {"name": "third"}],
            "test-host",
            3,
            "",
            os.terminal_size((80, 6)),
        )
        self.assertIn("\x1b[7m 3. third", screen)
        self.assertNotIn("1. first", screen)
        self.assertLessEqual(len(screen.split("\r\n")), 6)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wss-", dir="/tmp")
        self.root = self.directory.name
        shell = Path(self.root, "test-shell")
        shell.write_text("#!/bin/sh\nexec /bin/sh -f\n")
        shell.chmod(0o700)
        self.env = dict(os.environ, WARP_SSH_SESSION_DIR=self.root, SHELL=str(shell), ENV="")
        self.env.pop("SSH_AUTH_SOCK", None)
        self.peers = []
        self.identity = uuid.uuid4().hex

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        killer = Proxy(self.env, self.request(action="kill"))
        try:
            killer.next()
        finally:
            killer.close()
        self.directory.cleanup()

    def request(self, **changes):
        request = {
            "name": "test",
            "client": self.identity,
            "action": "attach",
            "size": [24, 80],
            "term": "xterm-256color",
            "offset": 0,
        }
        request.update(changes)
        return request

    def attach(self, **changes):
        proxy = Proxy(self.env, self.request(**changes))
        self.peers.append(proxy)
        kind, payload = proxy.next()
        self.assertEqual(kind, b"H", payload)
        return proxy, json.loads(payload)

    def ready(self, proxy):
        proxy.input(b"stty -echo; printf 'READY\\n'\n")
        proxy.until(b"READY\r\n")

    def listing(self, details=True):
        proxy = Proxy(self.env, self.request(action="list", details=details))
        self.peers.append(proxy)
        kind, payload = proxy.next()
        self.assertEqual(kind, b"L")
        return json.loads(payload)

    def test_background_refresh_reads_live_state_and_cleans_up(self):
        self.attach()
        args = client.parse_args(["host", "--select"])
        with (
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(client, "ssh_command", return_value=[HELPER, "proxy"]),
        ):
            refresh = client.SessionRefresh(args, "helper")
            try:
                refresh.next_update = 0
                deadline = time.monotonic() + 5
                result = refresh.poll()
                while result is None and time.monotonic() < deadline:
                    result = refresh.poll()
                self.assertEqual(result[0]["state"], "attached")
                self.assertIsNone(refresh.process)
                detach = Proxy(self.env, self.request(action="detach"))
                self.peers.append(detach)
                self.assertEqual(detach.next()[0], b"D")
                refresh.next_update = 0
                deadline = time.monotonic() + 5
                result = refresh.poll()
                while result is None and time.monotonic() < deadline:
                    result = refresh.poll()
                self.assertEqual(result[0]["state"], "detached")
                self.assertIsNone(refresh.process)
            finally:
                refresh.close()

    def test_combined_picker_routes_actions_to_the_selected_host_despite_an_unavailable_host(self):
        self.attach()
        with tempfile.TemporaryDirectory(prefix="wss-", dir="/tmp") as other_root:
            other_env = dict(self.env, WARP_SSH_SESSION_DIR=other_root)
            other = Proxy(other_env, self.request())
            self.peers.append(other)
            self.assertEqual(other.next()[0], b"H")

            def command(args, remote_command, reconnect=False, session=False):
                if args.destination == "offline":
                    return [sys.executable, "-c", "raise SystemExit(255)"]
                root = other_root if args.destination == "second" else self.root
                return ["env", "WARP_SSH_SESSION_DIR=" + root, HELPER, "proxy"]

            with mock.patch.object(client, "ssh_command", side_effect=command):
                refresh = client.HostsRefresh(
                    [
                        {"arguments": ["first"], "helper": "a" * 64},
                        {"arguments": ["second"], "helper": "a" * 64},
                        {"arguments": ["offline"], "helper": "a" * 64},
                    ],
                    client.parse_args([]),
                )
                try:
                    deadline = time.monotonic() + 5
                    sessions = []
                    while refresh.pending and time.monotonic() < deadline:
                        updated = refresh.poll()
                        if updated is not None:
                            sessions = updated
                    self.assertFalse(refresh.pending)
                    self.assertEqual([session["host"] for session in sessions], ["first", "second"])
                    self.assertEqual([session["name"] for session in sessions], ["test", "test"])
                    self.assertIn("offline", refresh.status)
                    selected = sessions[1]
                    args, remote_command, _ = refresh.hosts[selected["host_id"]]
                    with (
                        mock.patch("builtins.input", return_value="kill"),
                        contextlib.redirect_stdout(io.StringIO()),
                    ):
                        client.session_action(args, remote_command, "k", selected)
                    deadline = time.monotonic() + 5
                    remaining = client.manage_sessions(args, remote_command, "list")
                    while remaining and time.monotonic() < deadline:
                        remaining = client.manage_sessions(args, remote_command, "list")
                    self.assertEqual(remaining, [])
                    self.assertEqual(self.listing(details=False), ["test"])
                finally:
                    refresh.close()
                    killer = Proxy(other_env, self.request(action="kill"))
                    try:
                        killer.next()
                    finally:
                        killer.close()

    def test_statistics_leave_the_attached_shell_and_activity_unchanged(self):
        first, hello = self.attach()
        self.ready(first)
        info = self.listing()[0]
        self.assertEqual(info["name"], "test")
        self.assertEqual(info["state"], "attached")
        self.assertEqual(info["generation"], hello["generation"])
        self.assertGreater(info["shell_pid"], 0)
        self.assertGreater(info["output_bytes"], 0)
        self.assertLessEqual(info["created_at"], info["last_interaction_at"])
        self.assertFalse(info["created_at_estimated"])
        self.assertEqual(self.listing()[0]["last_interaction_at"], info["last_interaction_at"])
        self.assertEqual(self.listing(details=False), ["test"])
        first.input(b"printf 'STILL-ATTACHED\\n'\n")
        first.until(b"STILL-ATTACHED\r\n")
        detach = Proxy(self.env, self.request(action="detach"))
        self.peers.append(detach)
        self.assertEqual(detach.next()[0], b"D")
        detached = self.listing()[0]
        self.assertEqual(detached["state"], "detached")
        self.assertEqual(detached["created_at"], info["created_at"])

    def test_picker_cannot_replace_a_vanished_session(self):
        proxy = Proxy(self.env, self.request(existing_only=True))
        self.peers.append(proxy)
        kind, payload = proxy.next()
        self.assertEqual(kind, b"E")
        self.assertIn("not silently replaced", json.loads(payload))
        self.assertEqual(self.listing(), [])

    def test_stale_picker_cannot_kill_a_replacement_session(self):
        first, _ = self.attach()
        killer = Proxy(self.env, self.request(action="kill", generation="previous-session"))
        self.peers.append(killer)
        kind, payload = killer.next()
        self.assertEqual(kind, b"E")
        self.assertIn("Session was replaced", json.loads(payload))
        self.ready(first)

    def test_generated_name_collision_cannot_attach_to_an_existing_shell(self):
        first, _ = self.attach()
        duplicate = Proxy(self.env, self.request(create_only=True))
        self.peers.append(duplicate)
        kind, payload = duplicate.next()
        self.assertEqual(kind, b"E")
        self.assertIn("timestamp already exists", json.loads(payload))
        self.ready(first)

    def test_picker_requires_confirmation_before_killing(self):
        first, _ = self.attach()
        self.ready(first)
        args = client.parse_args(["host", "--select"])
        with (
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(client, "ssh_command", return_value=[HELPER, "proxy"]),
            mock.patch("builtins.input", side_effect=["k 1", "", "q"]),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(client.select_session(args, "helper"), 0)
        self.assertIn("Cancelled.", output.getvalue())
        self.assertEqual(self.listing(details=False), ["test"])
        self.ready(first)

    def test_enter_takes_over_the_original_shell_in_a_real_terminal(self):
        first, hello = self.attach()
        self.ready(first)
        first.input(b"PICKER_VALUE=original; printf 'SAVED\\n'\n")
        first.until(b"SAVED\r\n")
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        program = (
            "import sys; sys.path.insert(0, sys.argv[1]); import client; "
            "client.ssh_command = lambda *a, **kw: [sys.argv[2], 'proxy']; "
            "sys.exit(client.select_session(client.parse_args(['host', '--select']), 'helper'))"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", program, str(Path(__file__).parent), HELPER],
            env={**self.env, "TERM": "xterm-256color"},
            stdin=slave,
            stdout=slave,
            stderr=slave,
        )
        os.close(slave)

        def until(marker):
            output = bytearray()
            deadline = time.monotonic() + 10
            while marker not in output:
                if not select.select([master], [], [], max(0, deadline - time.monotonic()))[0]:
                    self.fail(f"Picker did not display {marker!r}: {output!r}")
                output.extend(os.read(master, 65536))
            return output

        try:
            screen = until(b"Session number")
            self.assertNotIn(b"Since last interaction:", screen)
            self.assertNotIn(b"Shell PID:", screen)
            self.assertIn(b"attached", screen)
            os.write(master, b"1\n")
            until(b"SAVED\r\n")
            os.write(master, b"printf 'PICKER-%s\\n' \"$PICKER_VALUE\"\n")
            until(b"PICKER-original\r\n")
            self.assertEqual(self.listing()[0]["generation"], hello["generation"])
        finally:
            process.terminate()
            process.wait(timeout=5)
            os.close(master)

    def test_new_session_from_host_picker_creates_a_distinct_shell(self):
        first, _ = self.attach()
        self.ready(first)
        Path(self.root, "test-shell").write_text(
            "#!/bin/sh\nprintf 'NEW-SHELL-READY\\n'\nexec /bin/sh -f\n"
        )
        registry = Path(self.root, "hosts.json")
        registry.write_text(client.json.dumps([{"arguments": ["host"], "helper": "a" * 64}]))
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        program = """
import sys
sys.path.insert(0, sys.argv[1])
import client
client.ssh_command = lambda *a, **kw: [sys.argv[2], 'proxy']
def install(args):
    args.helper_digest = 'a' * 64
    return 'helper'
client.install = install
sys.exit(client.select_all_hosts(client.parse_args([])))
"""
        process = subprocess.Popen(
            [sys.executable, "-c", program, str(Path(__file__).parent), HELPER],
            env={**self.env, "TERM": "xterm-256color", "WARP_SSH_HOSTS_FILE": str(registry)},
            stdin=slave,
            stdout=slave,
            stderr=slave,
        )
        os.close(slave)

        def until(marker):
            output = bytearray()
            deadline = time.monotonic() + 10
            while marker not in output:
                if not select.select([master], [], [], max(0, deadline - time.monotonic()))[0]:
                    self.fail(f"New session did not display {marker!r}: {output!r}")
                output.extend(os.read(master, 65536))
            return bytes(output)

        try:
            until(b"Session number:")
            os.write(master, b"\r")
            until(b"Host number:")
            os.write(master, b"\r")
            screen = until(b"NEW-SHELL-READY\r\n")
            match = client.re.search(
                rb"Warp SSH session: (\d{4}\.\d{2}\.\d{2}-\d{2}:\d{2}:\d{2})", screen
            )
            self.assertIsNotNone(match)
            name = match.group(1).decode()
            self.assertEqual(self.listing(details=False), [name, "test"])
            os.write(master, b"printf 'CREATED-%s\\n' \"$WARP_PERSISTENT_SSH_SESSION\"\n")
            until(b"CREATED-" + name.encode() + b"\r\n")
            self.ready(first)
        finally:
            process.terminate()
            process.wait(timeout=5)
            os.close(master)
            for name in self.listing(details=False):
                if name != "test":
                    killer = Proxy(self.env, self.request(name=name, action="kill"))
                    try:
                        killer.next()
                    finally:
                        killer.close()

    def test_picker_kills_only_the_confirmed_session(self):
        self.attach()
        args = client.parse_args(["host", "--select"])
        with (
            mock.patch.dict(os.environ, self.env),
            mock.patch.object(client, "ssh_command", return_value=[HELPER, "proxy"]),
            mock.patch("builtins.input", side_effect=["k 1", "kill", "q"]),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(client.select_session(args, "helper"), 0)
        self.assertIn("Killed test.", output.getvalue())
        deadline = time.monotonic() + 5
        while self.listing(details=False) and time.monotonic() < deadline:
            pass
        self.assertEqual(self.listing(details=False), [])

    def test_integrated_bash_keeps_hooks_and_generators_after_reconnect(self):
        assets = Path(__file__).resolve().parents[2] / "assets/bundled/bootstrap"
        bootstrap = (
            (assets / "bash_init_shell.sh")
            .read_text()
            .replace("@@WARP_SESSION_ID@@", "$WARP_SESSION_ID")
        )
        bootstrap += (
            (assets / "bash.sh")
            .read_text()
            .replace(
                "#include bundled/bootstrap/bash_body.sh", (assets / "bash_body.sh").read_text()
            )
        )
        bootstrap = bootstrap.replace("@@USING_CON_PTY_BOOLEAN@@", "false").encode()
        digest = hashlib.sha256(bootstrap).hexdigest()
        Path(self.root, "bootstrap-" + digest).write_bytes(bootstrap)
        Path(self.root, ".bashrc").write_text("")
        Path(self.root, ".bash_profile").write_text("")
        self.env.update(HOME=self.root, SHELL="/bin/bash")
        integration = {"session_id": 42, "bootstrap": digest}
        first, hello = self.attach(integration=integration)
        self.assertEqual(hello["integration"]["session_id"], 42)
        hooks = client.ReplayFilter(session_id=42)
        deadline = time.monotonic() + 15
        while "Bootstrapped" not in hooks.hooks or "Precmd" not in hooks.hooks:
            kind, payload = first.next(max(0, deadline - time.monotonic()))
            if kind == b"O":
                hooks.feed(payload[8:], True)
        first.input(b"saved=kept; printf 'BOOT_OK\\n'\n")
        first.until(b"BOOT_OK\r\n")
        first.close()
        resumed, new_hello = self.attach(
            generation=hello["generation"], offset=first.cursor, integration=integration
        )
        self.assertEqual(new_hello["integration"], hello["integration"])
        resumed.sequence = new_hello["accepted"] + 1
        resumed.input(b"_warp_execute_command probe 'printf %s \"$saved\"'\n")
        output = resumed.until(b"70726f62653b6b6570743b30")
        self.assertIn(b"\x1b]9277;A", output)

    def test_same_shell_and_output_survive_transport_death(self):
        first, hello = self.attach()
        self.ready(first)
        first.input(b"saved=still_here; printf 'PID:%s\\n' $$\n")
        first.until(b"PID:")
        first.close()
        resumed, new_hello = self.attach(generation=hello["generation"], offset=first.cursor)
        self.assertEqual(new_hello["generation"], hello["generation"])
        resumed.sequence = new_hello["accepted"] + 1
        resumed.input(b"printf 'VALUE:%s\\n' \"$saved\"\n")
        self.assertIn(b"VALUE:still_here\r\n", resumed.until(b"VALUE:still_here\r\n"))

    def test_output_generated_without_client_is_replayed(self):
        first, hello = self.attach()
        self.ready(first)
        os.mkfifo(os.path.join(self.root, "gate"))
        os.mkfifo(os.path.join(self.root, "done"))
        first.input(
            b"printf 'WAITING\\n'; read value < '"
            + os.fsencode(self.root)
            + b"/gate'; printf 'OFFLINE:%s\\n' \"$value\"; printf done > '"
            + os.fsencode(self.root)
            + b"/done'\n"
        )
        first.until(b"WAITING\r\n")
        first.close()
        with open(os.path.join(self.root, "gate"), "w") as gate:
            gate.write("completed\n")
        with open(os.path.join(self.root, "done")) as done:
            self.assertEqual(done.read(), "done")
        resumed, _ = self.attach(generation=hello["generation"], offset=first.cursor)
        self.assertIn(b"OFFLINE:completed\r\n", resumed.until(b"OFFLINE:completed\r\n"))

    def test_new_client_replays_scrollback_and_keeps_shell_environment(self):
        first, hello = self.attach()
        self.ready(first)
        first.input(b"saved=preserved; printf 'OLD-OUTPUT\\n'\n")
        first.until(b"OLD-OUTPUT\r\n")
        detach = Proxy(self.env, self.request(action="detach"))
        self.peers.append(detach)
        self.assertEqual(detach.next()[0], b"D")
        first.close()
        resumed, new_hello = self.attach(client=uuid.uuid4().hex)
        self.assertEqual(new_hello["generation"], hello["generation"])
        self.assertIn(b"OLD-OUTPUT\r\n", resumed.until(b"OLD-OUTPUT\r\n"))
        resumed.input(b"printf 'VALUE:%s\\n' \"$saved\"\n")
        self.assertIn(b"VALUE:preserved\r\n", resumed.until(b"VALUE:preserved\r\n"))

    def test_unacknowledged_input_is_not_executed_twice(self):
        first, hello = self.attach()
        self.ready(first)
        sequence = first.sequence
        command = b"counter=$(( ${counter:-0} + 1 )); printf 'COUNT:%s\\n' \"$counter\"\n"
        first.input(command)
        first.until(b"COUNT:1\r\n")
        first.close()
        resumed, new_hello = self.attach(generation=hello["generation"], offset=first.cursor)
        resumed.send(b"I", client.NUMBER.pack(sequence) + command)
        resumed.sequence = new_hello["accepted"] + 1
        resumed.input(b"printf 'FINAL:%s\\n' \"$counter\"\n")
        self.assertIn(b"FINAL:1\r\n", resumed.until(b"FINAL:1\r\n"))

    def test_resizing_and_control_c_reach_the_original_pty(self):
        proxy, _ = self.attach()
        self.ready(proxy)
        proxy.send(b"R", json.dumps([37, 111]).encode())
        proxy.input(b"stty size\n")
        proxy.until(b"37 111\r\n")
        program = "import signal; signal.signal(signal.SIGINT, lambda *_: (print('INTERRUPTED', flush=True), exit(0))); print('SIGNAL-READY', flush=True); signal.pause()"
        proxy.input((shlex.quote(sys.executable) + " -c " + shlex.quote(program) + "\n").encode())
        proxy.until(b"SIGNAL-READY\r\n")
        proxy.input(b"\x03")
        self.assertIn(b"INTERRUPTED\r\n", proxy.until(b"INTERRUPTED\r\n"))

    def test_a_second_client_cannot_silently_take_over(self):
        first, _ = self.attach()
        other = Proxy(self.env, self.request(client=uuid.uuid4().hex))
        self.peers.append(other)
        kind, payload = other.next()
        self.assertEqual(kind, b"E")
        self.assertIn("already attached", json.loads(payload))
        self.ready(first)

    def test_rejected_client_does_not_replace_the_forwarded_agent(self):
        with (
            socket.socket(socket.AF_UNIX) as first_agent,
            socket.socket(socket.AF_UNIX) as other_agent,
        ):
            first_path = self.root + "/first-agent"
            other_path = self.root + "/other-agent"
            first_agent.bind(first_path)
            other_agent.bind(other_path)
            self.env["SSH_AUTH_SOCK"] = first_path
            first, _ = self.attach()
            self.ready(first)
            self.env["SSH_AUTH_SOCK"] = other_path
            other = Proxy(self.env, self.request(client=uuid.uuid4().hex))
            self.peers.append(other)
            self.assertEqual(other.next()[0], b"E")
            first.input(b'readlink "$SSH_AUTH_SOCK"\n')
            self.assertIn(first_path.encode(), first.until(first_path.encode() + b"\r\n"))

    def test_detach_prevents_a_disconnected_client_from_reconnecting(self):
        first, hello = self.attach()
        first.close()
        detach = Proxy(self.env, self.request(action="detach"))
        self.peers.append(detach)
        self.assertEqual(detach.next()[0], b"D")
        stale = Proxy(self.env, self.request(generation=hello["generation"]))
        self.peers.append(stale)
        self.assertEqual(stale.next()[0], b"D")
        fresh, fresh_hello = self.attach(client=uuid.uuid4().hex)
        self.assertEqual(fresh_hello["generation"], hello["generation"])
        self.ready(fresh)

    def test_disconnected_output_larger_than_the_socket_buffer_is_retained(self):
        first, hello = self.attach()
        self.ready(first)
        os.mkfifo(os.path.join(self.root, "done"))
        program = "import os; os.write(1,b'x' * (2 * 1024 * 1024)); print('LARGE-DONE', flush=True)"
        first.input(
            (
                "printf 'LARGE-START\\n'; "
                + shlex.quote(sys.executable)
                + " -c "
                + shlex.quote(program)
                + "; printf done > "
                + shlex.quote(self.root + "/done")
                + "\n"
            ).encode()
        )
        first.until(b"LARGE-START\r\n")
        first.close()
        with open(os.path.join(self.root, "done")) as done:
            self.assertEqual(done.read(), "done")
        resumed, _ = self.attach(generation=hello["generation"], offset=first.cursor)
        output = resumed.until(b"LARGE-DONE\r\n")
        self.assertEqual(output.count(b"x"), 2 * 1024 * 1024)

    def test_reconnect_never_creates_a_replacement_shell(self):
        peer = Proxy(self.env, self.request(generation="missing"))
        self.peers.append(peer)
        kind, payload = peer.next()
        self.assertEqual(kind, b"E")
        self.assertIn("not silently replaced", json.loads(payload))

    def test_normal_shell_exit_returns_exit_code(self):
        proxy, _ = self.attach()
        proxy.input(b"exit 17\n")
        kind, payload = proxy.next()
        while kind != b"X":
            kind, payload = proxy.next()
        self.assertEqual(json.loads(payload), 17)


if __name__ == "__main__":
    unittest.main()

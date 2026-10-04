"""GOST chain tests with loopback-only dummy proxies and synthetic credentials."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from farm.network import chain as bridge


def headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        block = sock.recv(4096)
        if not block:
            raise EOFError
        data += block
        if len(data) > 16384:
            raise ValueError("oversized fixture header")
    head, rest = data.split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    return lines[0], {k.lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:])}, rest


class DummyProxy:
    def __init__(self, mode, remote=None):
        self.mode, self.remote = mode, remote
        self.requests, self.errors = [], []
        self.stop = threading.Event()
        self.done = threading.Event()
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.workers = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.handle, args=(connection,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def handle(self, connection):
        try:
            with connection:
                connection.settimeout(3)
                first, fields, trailing = headers(connection)
                self.requests.append((first, fields))
                if self.mode == "reject":
                    connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                    return
                if self.mode == "stall":
                    self.stop.wait(3)
                    return
                if self.mode == "echo":
                    connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    if trailing:
                        connection.sendall(trailing)
                    while True:
                        block = connection.recv(4096)
                        if not block:
                            self.done.set()
                            return
                        connection.sendall(block)
                if self.mode == "forward":
                    # Only this explicit loopback tuple is dialled. The
                    # claimed remote .invalid hostname is never resolved.
                    with socket.create_connection(("127.0.0.1", self.remote.port), timeout=2) as upstream:
                        connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        if trailing:
                            upstream.sendall(trailing)
                        def pump(source, target):
                            try:
                                while True:
                                    block = source.recv(4096)
                                    if not block:
                                        break
                                    target.sendall(block)
                            except OSError:
                                pass
                            finally:
                                try:
                                    target.shutdown(socket.SHUT_WR)
                                except OSError:
                                    pass
                        worker = threading.Thread(target=pump, args=(connection, upstream), daemon=True)
                        worker.start()
                        pump(upstream, connection)
                        worker.join(timeout=3)
                        self.done.set()
        except (OSError, EOFError, ValueError) as exc:
            self.errors.append(type(exc).__name__)

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)
        for worker in self.workers:
            worker.join(timeout=4)


class ProxyChainConfigTests(unittest.TestCase):
    def test_private_config_is_owned_0600_and_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.json"
            value = {"remote_proxy": {"host": "proxy.example.invalid", "port": 8080,
                                      "username": "fixture-user", "password": "fixture-password"}}
            bridge.write_private_config(path, value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(bridge.read_private_config(path), value)
            with self.assertRaises(FileExistsError):
                bridge.write_private_config(path, {})
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                bridge.read_private_config(path)
            os.chmod(path, 0o600)
            link = Path(temp) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                bridge.read_private_config(link)

    def test_two_mandatory_hops_only_final_connector_has_auth(self):
        conf = bridge.build_gost_config({"remote_proxy": {"host": "proxy.example.invalid", "port": 8080,
                                         "username": "fixture-user", "password": "fixture-password"}})
        self.assertEqual(conf["services"][0]["addr"], "127.0.0.1:19097")
        self.assertNotIn("auth", conf["services"][0]["handler"])
        nodes = [hop["nodes"][0] for hop in conf["chains"][0]["hops"]]
        self.assertEqual([node["addr"] for node in nodes], ["127.0.0.1:7897", "proxy.example.invalid:8080"])
        self.assertNotIn("auth", nodes[0]["connector"])
        self.assertEqual(nodes[1]["connector"]["auth"]["username"], "fixture-user")
        for override in ({"listen": {"host": "0.0.0.0", "port": 1}},
                         {"first_proxy": {"host": "198.51.100.1", "port": 1}},
                         {"connect_timeout_seconds": float("nan")},
                         {"remote_proxy": {"host": "proxy.invalid/path", "port": 1}},
                         {"remote_proxy": {"host": "proxy.invalid", "port": True}}):
            source = {"remote_proxy": {"host": "proxy.invalid", "port": 1}, **override}
            with self.subTest(keys=tuple(override)), self.assertRaises(ValueError):
                bridge.build_gost_config(source)

    def test_error_output_does_not_echo_json_or_exception_material(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.json"
            marker = "PRIVATE-FIXTURE-CANARY"
            bridge.write_private_config(path, {"remote_proxy": {"host": marker + "/bad", "port": 80,
                                                              "username": marker, "password": marker}})
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                code = bridge.main(["--config", str(path), "--write-gost", str(Path(temp) / "new.json")])
            self.assertEqual(code, 1)
            self.assertNotIn(marker, output.getvalue())
            self.assertIn("proxy_chain_configuration_or_start_failed", output.getvalue())


@unittest.skipUnless(Path(bridge.DEFAULT_GOST).is_file(), "installed GOST 3 is optional")
class ProxyChainLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.remote = DummyProxy("echo")
        self.addCleanup(self.remote.close)

    def start(self, mode="forward", timeout=1):
        first = DummyProxy(mode, self.remote)
        self.addCleanup(first.close)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        source = {"listen": {"host": "127.0.0.1", "port": port},
                  "first_proxy": {"host": "127.0.0.1", "port": first.port},
                  "remote_proxy": {"host": "proxy.invalid", "port": self.remote.port,
                      "username": "FIXTURE-USER-CANARY", "password": "FIXTURE-PASSWORD-CANARY"},
                  "connect_timeout_seconds": timeout}
        path = Path(self.temp.name) / "gost.json"
        bridge.write_private_config(path, bridge.build_gost_config(source))
        process = subprocess.Popen([bridge.DEFAULT_GOST, "-C", str(path)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            process.terminate()
            out, err = process.communicate(timeout=4)
            self.assertNotIn(b"FIXTURE-USER-CANARY", out + err)
            self.assertNotIn(b"FIXTURE-PASSWORD-CANARY", out + err)
            self.assertNotIn(b"CONNECT target.invalid", out + err)
        self.addCleanup(cleanup)
        self.assertFalse(any("CANARY" in str(argument) for argument in process.args))
        deadline = time.monotonic() + 4
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                break
            except ConnectionRefusedError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail("GOST did not start its loopback listener")
                time.sleep(0.02)
        client.settimeout(3)
        self.addCleanup(client.close)
        return first, client

    def test_actual_two_connect_hops_inject_auth_and_relay_both_directions(self):
        first, client = self.start()
        client.sendall(b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n")
        status, _, trailing = headers(client)
        self.assertIn(" 200 ", status)
        self.assertEqual(trailing, b"")
        client.sendall(b"fixture-tunnel-payload")
        self.assertEqual(client.recv(1024), b"fixture-tunnel-payload")
        self.assertEqual(first.requests[0][0], f"CONNECT proxy.invalid:{self.remote.port} HTTP/1.1")
        self.assertNotIn("proxy-authorization", first.requests[0][1])
        self.assertEqual(self.remote.requests[0][0], "CONNECT target.invalid:443 HTTP/1.1")
        expected = "Basic " + base64.b64encode(b"FIXTURE-USER-CANARY:FIXTURE-PASSWORD-CANARY").decode()
        self.assertEqual(self.remote.requests[0][1]["proxy-authorization"], expected)
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(client.recv(1), b"")
        self.assertTrue(self.remote.done.wait(1))
        self.assertTrue(first.done.wait(1))

    def test_first_hop_rejection_never_dials_remote_directly(self):
        first, client = self.start("reject")
        client.sendall(b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n")
        status, _, _ = headers(client)
        self.assertNotIn(" 200 ", status)
        self.assertEqual(len(first.requests), 1)
        self.assertEqual(self.remote.requests, [])

    def test_connect_timeout_closes_stalled_first_hop(self):
        first, client = self.start("stall", timeout=0.3)
        start = time.monotonic()
        client.sendall(b"CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n")
        status, _, _ = headers(client)
        self.assertNotIn(" 200 ", status)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(len(first.requests), 1)
        self.assertEqual(self.remote.requests, [])


if __name__ == "__main__":
    unittest.main()

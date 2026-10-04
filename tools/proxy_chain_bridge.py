"""Private GOST 3 configuration for loopback -> local proxy -> remote proxy.

This delegates CONNECT framing and bidirectional relay to installed GOST;
there is no custom relay, direct fallback, system proxy edit or Clash edit.
Only a configuration path is passed in argv. Credentials stay in mode-0600
files and child stdout/stderr are suppressed by the runner.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile


DEFAULT_GOST = "/opt/homebrew/bin/gost"


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def read_private_config(path):
    """Read an owned regular 0600 file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                     "configuration must be a regular mode-0600 file")
            _require(info.st_uid == os.getuid(), "configuration must belong to this user")
            raw = stream.read(65537)
            _require(len(raw) <= 65536, "configuration is too large")
        result = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ValueError("cannot read private JSON configuration") from None
    _require(isinstance(result, dict), "configuration must be an object")
    return result


def _endpoint(value, *, loopback=False, authentication=False):
    allowed = {"host", "port"} | ({"username", "password"} if authentication else set())
    _require(isinstance(value, dict) and {"host", "port"} <= set(value) <= allowed,
             "invalid proxy endpoint schema")
    host, port = value["host"], value["port"]
    _require(isinstance(host, str) and bool(host) and len(host) <= 253 and host.isascii(),
             "invalid proxy host")
    _require(type(port) is int and 1 <= port <= 65535, "invalid proxy port")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        _require(not loopback and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host),
                 "invalid proxy host")
        formatted = host
    else:
        _require(not loopback or ip.is_loopback, "listener and first proxy must use loopback IPs")
        formatted = f"[{ip}]" if ip.version == 6 else str(ip)
    auth = None
    if "username" in value or "password" in value:
        _require({"username", "password"} <= set(value), "both proxy credential fields are required")
        user, password = value["username"], value["password"]
        _require(isinstance(user, str) and bool(user) and isinstance(password, str),
                 "invalid proxy credential types")
        _require(":" not in user and all(c.isprintable() for c in user + password),
                 "invalid proxy credential encoding")
        auth = {"username": user, "password": password}
    return f"{formatted}:{port}", auth


def build_gost_config(source):
    """Build two mandatory HTTP proxy hops; never serialize credentials to URLs."""
    _require(isinstance(source, dict) and set(source) <=
             {"listen", "first_proxy", "remote_proxy", "connect_timeout_seconds"} and "remote_proxy" in source,
             "invalid chain configuration schema")
    listen, _ = _endpoint(source.get("listen", {"host": "127.0.0.1", "port": 19097}), loopback=True)
    first, _ = _endpoint(source.get("first_proxy", {"host": "127.0.0.1", "port": 7897}), loopback=True)
    remote, auth = _endpoint(source["remote_proxy"], authentication=True)
    timeout = source.get("connect_timeout_seconds", 10)
    _require(type(timeout) in (int, float) and 0.1 <= timeout <= 120, "invalid connect timeout")
    duration = f"{timeout:g}s"
    hops = []
    for index, address in enumerate((first, remote)):
        connector = {"type": "http", "metadata": {"timeout": duration}}
        if index == 1 and auth is not None:
            connector["auth"] = auth
        node = {"name": f"proxy-{index}", "addr": address, "connector": connector,
                "dialer": {"type": "tcp", "metadata": {"timeout": duration}},
                "metadata": {"timeout": duration}}
        hops.append({"name": f"hop-{index}", "nodes": [node], "metadata": {"timeout": duration}})
    return {"log": {"level": "fatal", "format": "json", "output": "stderr"},
            "services": [{"name": "loopback-http", "addr": listen,
                "handler": {"type": "http", "chain": "via-local-proxy", "metadata": {"readTimeout": duration}},
                "listener": {"type": "tcp"}}],
            "chains": [{"name": "via-local-proxy", "hops": hops}]}


def write_private_config(path, value):
    """Create exclusively; do not overwrite an existing configuration."""
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


def run_gost(config, executable=DEFAULT_GOST):
    """Run foreground; neither child logs nor config contents reach stdout."""
    previous = signal.getsignal(signal.SIGTERM)
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        with tempfile.TemporaryDirectory(prefix="keeta-proxy-chain-") as directory:
            path = Path(directory) / "gost.json"
            write_private_config(path, config)
            with subprocess.Popen([executable, "-C", str(path)], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
                print(json.dumps({"event": "gost_started", "listen": "http://" + config["services"][0]["addr"]}), flush=True)
                try:
                    code = process.wait()
                except KeyboardInterrupt:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    return 0
                if code:
                    print('{"event":"gost_failed"}', file=sys.stderr)
                return 0 if code == 0 else 1
    finally:
        signal.signal(signal.SIGTERM, previous)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="owned mode-0600 chain JSON")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--write-gost", type=Path, help="write a new mode-0600 GOST configuration only")
    actions.add_argument("--run", action="store_true", help="run installed GOST in the foreground")
    parser.add_argument("--gost", default=DEFAULT_GOST, help="installed GOST 3 executable path")
    args = parser.parse_args(argv)
    try:
        config = build_gost_config(read_private_config(args.config))
        if args.write_gost:
            write_private_config(args.write_gost, config)
            print('{"event":"configuration_written"}')
            return 0
        return run_gost(config, args.gost)
    except (ValueError, OSError):
        # Exceptions may contain remote addresses, file contents or auth.
        # Report an error category only, never interpolate exception text.
        print('{"event":"proxy_chain_configuration_or_start_failed"}', file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

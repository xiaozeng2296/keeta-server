#!/usr/bin/env python3
"""Apply a staged Keeta RPC release without replacing identities or configuration.

Only the standard library is required. SIGTERM/SIGHUP trigger code rollback;
SIGKILL, power loss, and filesystem failures cannot guarantee automatic recovery.
The backup remains available for an explicit rollback after interruption.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


RUNTIME_FILES = frozenset({
    "keeta_rpc.py", "keeta_a2.py", "keeta_offline_flow.py", "keeta_login.py",
    "keeta_sign_offline.py", "mailbox.py",
    "farm/__init__.py", "farm/_paths.py",
    "farm/fullsign.py", "farm/request_freshness.py",
    "mtgsig/mtg_crypto.py", "mtgsig/a9_codec.py", "mtgsig/collection_cache.py",
    "mtgsig/envelope_codec.py",
    "mtgsig/provider_config.py", "mtgsig/fingerprint_refresh.py",
    "mtgsig/newreg.py", "mtgsig/registration_state.py",
    "mtgsig/registration_checksum.py", "mtgsig/registration_collector.py", "mtgsig/timestamp_identity.py", "mtgsig/region_state.py",
    "mtgsig/registration_reporting.py", "mtgsig/registration_region.py",
    "mtgsig/m175_codec.py", "mtgsig/session_identity.py", "mtgsig/scfg.py",
    "mtgsig/local_identity.py", "mtgsig/bootstrap_identity.py",
    "mtgsig/corpse_codec.py",
    "mtgsig/oneid.py", "mtgsig/registration_payloads.py", "mtgsig/login_protocol.py",
    "mtgsig/email_flow.py", "mtgsig/login_context.py",
    "mtgsig/incognia_state.py", "mtgsig/incognia_token.py", "mtgsig/request_trace.py",
    "mtgsig/ntp_protocol.py", "mtgsig/http_transport.py", "mtgsig/mail_transport.py",
    "mtgsig/embedded_rsa_pubkeys.json",
    "mtgsig/keeta_const.json", "mtgsig/a9_legacy_profile.json",
    "mtgsig/data/T.bin", "mtgsig/data/tableA.bin",
    "mtgsig/data/tableB_const.bin", "mtgsig/ref_domestic/M.bin",
})
OPTIONAL_FILES = frozenset({
    'tests/test_collection_refresh.py',
    'config/rpc-deploy.example.json',
    'docs/archive/A2_PASS2.md',
    'docs/archive/A9_RPC.md',
    'docs/archive/A9_USAGE.md',
    'docs/archive/ENVELOPE_SDK.md',
    'mtgsig/a9_cli.py',
    'rpc/deploy.py',
    'rpc/remote_update.py',
    'rpc/requirements.txt',
    'rpc/smoke.py',
    'tests/__init__.py',
    'tests/fixtures/a2_pass2_accepted_boundaries.json',
    'tests/fixtures/a2_pass2_synthetic.json',
    'tests/fixtures/a9_native_cbc_vectors.json',
    'tests/fixtures/a9_native_vectors.json',
    'tests/fixtures/corpse_native_vectors.json',
    'tests/fixtures/envelope_rsa_vector.json',
    'tests/fixtures/fingerprint_i_series_vector.json',
    'tests/fixtures/m175_vectors.json',
    'tests/fixtures/m239_synthetic.json',
    'tests/fixtures/m324_native_vectors.json',
    'tests/fixtures/oneid_native_vector.json',
    'tests/fixtures/registration_m320_pairs_vectors.json',
    'tests/fixtures/registration_m320_vectors.json',
    'tests/test_a9_cli.py',
    'tests/test_a9_rpc.py',
    'tests/test_bootstrap_identity.py',
    'tests/test_corpse_codec.py',
    'tests/test_email_flow.py',
    'tests/test_envelope_codec.py',
    'tests/test_envelope_rpc.py',
    'tests/test_envelope_sdk.py',
    'tests/test_fullsign.py',
    'tests/test_local_identity.py',
    'tests/test_login_context.py',
    'tests/test_login_execution.py',
    'tests/test_login_protocol.py',
    'tests/test_m175_codec.py',
    'tests/test_mailbox.py',
    'tests/test_newreg_signature.py',
    'tests/test_offline_flow.py',
    'tests/test_oneid.py',
    'tests/test_provider_config.py',
    'tests/test_region_state.py',
    'tests/test_registration_checksum.py',
    'tests/test_registration_execution.py',
    'tests/test_registration_payloads.py',
    'tests/test_registration_reporting.py',
    'tests/test_registration_state.py',
    'tests/test_remote_update.py',
    'tests/test_rpc_deploy.py',
    'tests/test_rpc_smoke.py',
    'tests/test_scfg.py',
    'tests/test_session_identity.py',
    'tests/test_signing_profiles.py',
    'tests/test_timestamp_identity.py',
})
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class DeploymentError(Exception):
    """Messages must never include captured command output or credentials."""


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def release_id(value):
    require(isinstance(value, str) and ID_PATTERN.fullmatch(value), "invalid release ID")
    return value


def allowed_path(value):
    require(isinstance(value, str), "manifest path must be text")
    parts = PurePosixPath(value).parts
    require(bool(parts) and not value.startswith("/") and "\\" not in value
            and all(p not in (".", "..") for p in parts)
            and str(PurePosixPath(value)) == value, "unsafe manifest path")
    allowed = value in RUNTIME_FILES or value in OPTIONAL_FILES
    allowed = allowed or bool(re.fullmatch(r"tests/test_[A-Za-z0-9_]+\.py", value))
    require(allowed, "path is outside the code release allowlist")
    return value


def safe_path(base, relative, *, regular=False, missing=False):
    """Check every component below a trusted root; never follow a symlink."""
    parts = PurePosixPath(relative).parts
    require(bool(parts) and not PurePosixPath(relative).is_absolute()
            and all(p not in (".", "..") for p in parts), "unsafe relative path")
    target = base
    for index, part in enumerate(parts):
        target = target / part
        try:
            info = target.lstat()
        except FileNotFoundError:
            require(missing, "required file is missing")
            continue
        require(not stat.S_ISLNK(info.st_mode), "symlinks are not allowed in deployment paths")
        if index < len(parts) - 1:
            require(stat.S_ISDIR(info.st_mode), "deployment parent is not a directory")
        elif regular:
            require(stat.S_ISREG(info.st_mode), "deployment input is not a regular file")
    return target


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path):
    try:
        require(path.stat().st_size <= 1 << 20, "metadata file is too large")
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError, OSError):
        raise DeploymentError("could not read deployment metadata") from None


def atomic_bytes(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".rpc-update-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode())


def load_manifest(stage):
    data = read_json(safe_path(stage, "rpc/release.json", regular=True))
    require(isinstance(data, dict) and set(data) == {"release_id", "files"},
            "invalid release manifest structure")
    release_id(data["release_id"])
    files = data["files"]
    require(isinstance(files, dict) and 0 < len(files) <= len(RUNTIME_FILES | OPTIONAL_FILES),
            "invalid manifest file list")
    require(RUNTIME_FILES | {"rpc/smoke.py"} <= set(files), "manifest lacks required runtime files")
    require(any(re.fullmatch(r"tests/test_[A-Za-z0-9_]+\.py", p) for p in files),
            "manifest lacks deployment tests")
    for name, sha in files.items():
        allowed_path(name)
        require(isinstance(sha, str) and HASH_PATTERN.fullmatch(sha), "invalid manifest SHA256")
        path = safe_path(stage, name, regular=True)
        require(path.stat().st_size <= 32 << 20, "release file is too large")
        require(digest(path) == sha, "staged file SHA256 mismatch")
    for path in stage.rglob("*"):
        require(not path.is_symlink(), "symlinks are not allowed anywhere in a release")
        if path.is_file():
            relative = path.relative_to(stage).as_posix()
            require(relative == "rpc/release.json" or relative in files,
                    "stage contains an unlisted file")
        else:
            require(path.is_dir(), "stage contains a non-regular entry")
    return data


def clean_environment():
    env = os.environ.copy()
    env.pop("KEETA_RPC_TOKEN", None)
    env.pop("PYTHONPATH", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_stage_tests(stage, python):
    print("阶段：暂存目录完整单元测试", flush=True)
    try:
        result = subprocess.run([python, "-m", "unittest", "discover", "-s", "tests",
                                 "-p", "test_*.py"], cwd=str(stage), env=clean_environment(),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=180, text=True)
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentError("staged tests could not complete") from None
    summary = re.search(r"^Ran (\d+) tests? in [0-9.]+s$", result.stdout, re.MULTILINE)
    require(result.returncode == 0 and summary and int(summary.group(1)) > 0,
            "staged unit tests failed; command output suppressed")
    print("通过：{} 项单元测试".format(summary.group(1)), flush=True)


def deployment_dir(root):
    path = safe_path(root, ".rpc-deploy", missing=True)
    path.mkdir(mode=0o700, exist_ok=True)
    require(path.is_dir(), "deployment state is not a directory")
    return path


@contextlib.contextmanager
def deployment_lock(root):
    state = deployment_dir(root)
    lock = safe_path(state, "deploy.lock", regular=True, missing=True)
    fd = os.open(str(lock), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeploymentError("another deployment is running") from None
        yield state
    finally:
        os.close(fd)


def current_metadata(state):
    path = safe_path(state, "current.json", regular=True, missing=True)
    if not path.exists():
        return None
    data = read_json(path)
    require(isinstance(data, dict), "invalid current release metadata")
    release_id(data.get("release_id"))
    files = data.get("files")
    require(isinstance(files, dict), "invalid current release file metadata")
    for name, sha in files.items():
        allowed_path(name)
        require(isinstance(sha, str) and HASH_PATTERN.fullmatch(sha), "invalid current file hash")
    # Do not propagate unknown state fields into new metadata.
    return {"release_id": data["release_id"], "files": files}


def make_backup(root, state, manifest):
    name = manifest["release_id"]
    backup = safe_path(state, "backups/" + name, missing=True)
    require(not backup.exists(), "backup for this release already exists")
    backup.mkdir(parents=True, mode=0o700)
    records = {}
    for relative in sorted(manifest["files"]):
        target = safe_path(root, relative, regular=True, missing=True)
        if not target.exists():
            records[relative] = {"existed": False}
            continue
        info = target.stat()
        destination = backup / "files" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(target), str(destination))
        os.chmod(str(destination), 0o600)
        records[relative] = {"existed": True, "mode": stat.S_IMODE(info.st_mode),
                             "sha256": digest(destination)}
    metadata = {"release_id": name, "status": "prepared", "files": records,
                "previous": current_metadata(state)}
    atomic_json(backup / "backup.json", metadata)
    return backup, metadata


def install_files(root, stage, manifest):
    for relative, sha in sorted(manifest["files"].items()):
        source = safe_path(stage, relative, regular=True)
        require(digest(source) == sha, "staged file changed after validation")
        target = safe_path(root, relative, regular=True, missing=True)
        mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else stat.S_IMODE(source.stat().st_mode)
        atomic_bytes(target, source.read_bytes(), mode)


def validate_backup(backup, metadata):
    require(isinstance(metadata, dict) and isinstance(metadata.get("files"), dict),
            "invalid backup metadata")
    release_id(metadata.get("release_id"))
    require(bool(metadata["files"]), "empty backup")
    for relative, entry in metadata["files"].items():
        allowed_path(relative)
        require(isinstance(entry, dict) and isinstance(entry.get("existed"), bool), "invalid backup record")
        if entry["existed"]:
            require(isinstance(entry.get("mode"), int) and 0 <= entry["mode"] <= 0o7777,
                    "invalid backup file mode")
            path = safe_path(backup, "files/" + relative, regular=True)
            require(isinstance(entry.get("sha256"), str) and digest(path) == entry["sha256"],
                    "backup file SHA256 mismatch")


def restore_files(root, backup, metadata):
    validate_backup(backup, metadata)
    for relative, entry in sorted(metadata["files"].items()):
        target = safe_path(root, relative, regular=True, missing=True)
        if entry["existed"]:
            source = safe_path(backup, "files/" + relative, regular=True)
            atomic_bytes(target, source.read_bytes(), entry["mode"])
        elif target.exists():
            target.unlink()


def restore_current(state, previous):
    target = safe_path(state, "current.json", regular=True, missing=True)
    if previous is None:
        if target.exists():
            target.unlink()
    else:
        require(isinstance(previous, dict) and set(previous) == {"release_id", "files"},
                "invalid previous release metadata")
        release_id(previous["release_id"])
        for name, sha in previous["files"].items():
            allowed_path(name)
            require(isinstance(sha, str) and HASH_PATTERN.fullmatch(sha), "invalid previous hash")
        atomic_json(target, previous)


def systemctl(args, operation, *extra):
    command = (["sudo", "-n"] if args.sudo else []) + ["systemctl", operation, args.service] + list(extra)
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentError("systemctl operation could not complete") from None
    require(result.returncode == 0, "systemctl operation failed")
    return result.stdout


def service_token(args):
    raw = systemctl(args, "show", "--property=MainPID", "--value").strip()
    require(raw.isdigit() and int(raw) > 0, "service has no running MainPID")
    path = Path("/proc") / str(int(raw)) / "environ"
    try:
        data = path.read_bytes()
        values = [part.split(b"=", 1)[1] for part in data.split(b"\0")
                  if part.startswith(b"KEETA_RPC_TOKEN=")]
        token = values[0] if values else b""
    except PermissionError:
        require(args.sudo, "cannot read service authentication environment")
        # The privileged child extracts only this variable. Its captured output
        # is kept in memory, never logged or written to deployment metadata.
        script = ("import pathlib,sys; d=pathlib.Path(sys.argv[1]).read_bytes(); "
                  "v=[p.split(b'=',1)[1] for p in d.split(b'\\0') if p.startswith(b'KEETA_RPC_TOKEN=')]; "
                  "sys.stdout.buffer.write(v[0] if v else b'')")
        result = subprocess.run(["sudo", "-n", args.python, "-c", script, str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        require(result.returncode == 0, "cannot read service authentication environment")
        token = result.stdout
    return os.fsdecode(token) if token else None


def run_smoke(root, args):
    token = service_token(args)
    env = clean_environment()
    command = [args.python, str(safe_path(root, "rpc/smoke.py", regular=True)), "--url", args.url]
    if token is not None:
        env["KEETA_RPC_TOKEN"] = token
        command += ["--token-env", "KEETA_RPC_TOKEN"]
    try:
        result = subprocess.run(command, cwd=str(root), env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentError("HTTP smoke check could not complete") from None
    require(result.returncode == 0, "HTTP smoke check failed; response output suppressed")
    print("通过：线上 HTTP 加解密验收", flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def health_check(args):
    """Rollback health works for the pre-a9 service as well."""
    opener = urllib.request.build_opener(NoRedirect())
    for _ in range(12):
        try:
            # Type=simple may return from restart before MainPID/environment or
            # the listening socket is available. Obtain the current PID anew.
            token = service_token(args)
        except (DeploymentError, OSError, subprocess.TimeoutExpired):
            time.sleep(0.5)
            continue
        headers = {"X-Token": token} if token else {}
        for suffix in ("/health", "/"):
            request = urllib.request.Request(args.url.rstrip("/") + suffix, headers=headers)
            try:
                with opener.open(request, timeout=3) as response:
                    data = json.loads(response.read(1 << 20))
                    if response.status == 200 and isinstance(data, dict) and data.get("service") == "keeta-offline-crypto-rpc":
                        return
            except (OSError, ValueError, urllib.error.URLError):
                pass
        time.sleep(0.5)
    raise DeploymentError("previous service failed health check after rollback")


@contextlib.contextmanager
def ignore_termination():
    previous = {}
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        previous[number] = signal.signal(number, signal.SIG_IGN)
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def revert(root, state, backup, metadata, args):
    with ignore_termination():
        restore_files(root, backup, metadata)
        systemctl(args, "restart")
        health_check(args)
        restore_current(state, metadata.get("previous"))
        metadata["status"] = "rolled_back"
        atomic_json(backup / "backup.json", metadata)


def summary(root, manifest, status, backup=None):
    return {"release_id": manifest["release_id"], "status": status,
            "files": len(manifest["files"]), "backup": str(backup) if backup else None,
            "app_root": str(root)}


def apply(args):
    root, stage = args.root, args.stage
    manifest = load_manifest(stage)
    run_stage_tests(stage, args.python)
    require(load_manifest(stage) == manifest, "manifest changed during tests")
    if args.stage_only:
        return summary(root, manifest, "validated")
    with deployment_lock(root) as state:
        print("阶段：备份将替换的代码和静态资源", flush=True)
        backup, metadata = make_backup(root, state, manifest)
        try:
            print("阶段：原子替换发布文件并重启服务", flush=True)
            install_files(root, stage, manifest)
            systemctl(args, "restart")
            health_check(args)
            run_smoke(root, args)
            atomic_json(state / "current.json", {"release_id": manifest["release_id"],
                                                  "files": manifest["files"]})
            metadata["status"] = "applied"
            atomic_json(backup / "backup.json", metadata)
        except BaseException:
            print("阶段：更新未通过，恢复本次代码备份", flush=True)
            try:
                revert(root, state, backup, metadata, args)
            except BaseException:
                print(json.dumps(summary(root, manifest, "rollback_failed", backup)), flush=True)
                raise DeploymentError("update failed and automatic rollback needs manual recovery") from None
            print(json.dumps(summary(root, manifest, "rolled_back", backup)), flush=True)
            raise DeploymentError("update failed; previous code and service were restored") from None
        return summary(root, manifest, "applied", backup)


def rollback(args):
    with deployment_lock(args.root) as state:
        backup = safe_path(state, "backups/" + args.release_id)
        metadata = read_json(safe_path(backup, "backup.json", regular=True))
        require(isinstance(metadata, dict), "invalid backup metadata")
        require(metadata.get("release_id") == args.release_id, "backup release ID mismatch")
        require(metadata.get("status") in ("prepared", "applied"), "backup has already been rolled back")
        active = current_metadata(state)
        require((active and active["release_id"] == args.release_id)
                or (metadata["status"] == "prepared" and active == metadata.get("previous")),
                "refusing out-of-order rollback of an inactive release")
        print("阶段：恢复指定版本更新前的代码并检查旧服务", flush=True)
        revert(args.root, state, backup, metadata, args)
        return summary(args.root, metadata, "rolled_back", backup)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("apply", "rollback"):
        sub = commands.add_parser(command)
        sub.add_argument("--root", type=Path, required=True)
        sub.add_argument("--service", required=True)
        sub.add_argument("--url", required=True)
        sub.add_argument("--python", required=True)
        sub.add_argument("--sudo", action="store_true")
        if command == "apply":
            sub.add_argument("--stage", type=Path, required=True)
            sub.add_argument("--stage-only", action="store_true")
        else:
            sub.add_argument("release_id", type=release_id)
    args = parser.parse_args(argv)
    require(not args.root.is_symlink() and args.root.is_dir(), "root must be an existing real directory")
    args.root = args.root.resolve()
    if args.command == "apply":
        require(not args.stage.is_symlink() and args.stage.is_dir(), "stage must be an existing real directory")
        args.stage = args.stage.resolve()
        require(args.stage != args.root, "stage must differ from live root")
    require(bool(re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", args.service))
            and not args.service.startswith("-"), "invalid systemd service name")
    parsed = urllib.parse.urlsplit(args.url)
    require(parsed.scheme in ("http", "https") and bool(parsed.hostname)
            and not (parsed.username or parsed.password or parsed.query or parsed.fragment),
            "invalid service base URL")
    require(os.path.isabs(args.python), "python must be an absolute executable path")
    return args


def main(argv=None):
    def interrupted(number, frame):
        raise InterruptedError("deployment interrupted")
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    try:
        args = parse_args(argv)
        result = apply(args) if args.command == "apply" else rollback(args)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    except DeploymentError as exc:
        print("部署失败：" + str(exc), file=sys.stderr)
    except (Exception, KeyboardInterrupt) as exc:
        print("部署失败：本地操作异常（{}）".format(type(exc).__name__), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

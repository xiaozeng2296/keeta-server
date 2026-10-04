"""Build the local a7/a8 portion of a fresh registration identity.

This does not invent the SDK's a1, a5 collection profile, or a9 SIUA profile.
Existing server identity takes precedence; ambiguous identity replacement is
rejected instead of silently joining values from different devices.
"""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

from mtgsig.local_identity import (
    DEFAULT_LOCAL_ID_PROFILE, DEFAULT_LOCAL_XID_PROFILE,
    decode_local_dfp, encode_local_xid, generate_local_dfp,
)


def bootstrap_identity(uuid_value, timestamp_ms, *, base=None):
    """Return a new profile with reproducible initial local a7/a8 values.

    ``base`` may supply known SDK/device fields, but is never modified. An
    existing local identity must match these explicit inputs. Unclassified
    a7/a8 values must match either the new local value or an explicit server
    value; otherwise the caller must keep the old identity separately.
    """
    if base is not None and not isinstance(base, dict):
        raise TypeError("bootstrap base must be a JSON object")
    output = deepcopy(base) if base is not None else {}
    dfp = generate_local_dfp(uuid_value, timestamp_ms)
    xid = encode_local_xid(dfp, timestamp_ms // 1000)

    for active, local, server, alias, generated in (
        ("a7", "a7_local_xid", "a7_server_xid", "xid", xid),
        ("a8", "a8_local_dfp", "a8_server_dfp", "dfp", dfp),
    ):
        if output.get(local) and output[local] != generated:
            raise ValueError(f"base {local} belongs to another local identity")
        server_value = output.get(server) or output.get(alias)
        if output.get(active) and output[active] not in (generated, server_value):
            raise ValueError(f"base {active} has unclassified identity data; use a separate base")
        output[local] = generated
        output[active] = server_value or generated

    missing = [name for name in ("a0", "a1", "a3", "a6", "x0", "base_collect")
               if name not in output or output[name] is None]
    if not output.get("a9") and not (
        output.get("base_siua") and output.get("a9_profile") in ("default", "legacy")
        and output.get("a9_mode") in ("aes", "twofish", "twofish-mod")
    ):
        missing.append("a9 or base_siua+a9_profile+a9_mode")
    output["local_identity_bootstrap"] = {
        "scope": "local_a7_a8_only",
        "uuid": decode_local_dfp(dfp).uuid,
        "timestamp_ms": timestamp_ms,
        "timestamp_seconds": timestamp_ms // 1000,
        "a8_profile": DEFAULT_LOCAL_ID_PROFILE.version,
        "a7_profile": DEFAULT_LOCAL_XID_PROFILE.version,
        "missing_signer_fields": missing,
    }
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description="生成新设备首阶段本地 a7/a8；不生成完整设备画像")
    parser.add_argument("--uuid", required=True, help="显式指定本地 ID 的 UUID（不是 mtgsig.a1）")
    parser.add_argument("--timestamp-ms", required=True, type=int, help="显式指定 Unix 毫秒时间")
    parser.add_argument("--base", type=Path, help="可选：已有 SDK/设备字段，拒绝混合其他本地身份")
    parser.add_argument("--output", type=Path, help="写入新文件，拒绝覆盖；省略则输出 JSON")
    args = parser.parse_args(argv)
    try:
        base = json.loads(args.base.read_text(encoding="utf-8")) if args.base else None
        output = bootstrap_identity(args.uuid, args.timestamp_ms, base=base)
        payload = json.dumps(output, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
        else:
            sys.stdout.write(payload)
    except (OSError, ValueError, TypeError) as exc:
        # JSON input errors can echo source data; report only stable categories.
        if isinstance(exc, FileExistsError):
            detail = "output already exists; choose a new path"
        elif isinstance(exc, json.JSONDecodeError):
            detail = "base is not valid JSON"
        elif isinstance(exc, OSError):
            detail = "could not read base or write output"
        else:
            detail = str(exc)
        print("Bootstrap failed: " + detail, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

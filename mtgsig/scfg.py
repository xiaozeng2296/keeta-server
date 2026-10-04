"""Independent /v1/scfg codec and state adapter for the analysed iOS SDK.

This route uses SAKGuardCommon encrypt:/decrypt: with the aesKey selector;
it is neither an A envelope nor the FAMA /ntp protocol. No I/O occurs here.
"""
import base64
import binascii
from collections.abc import Mapping
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from .local_identity import DEFAULT_LOCAL_XID_PROFILE

SCFG_PATH = "/v1/scfg"
SCFG_ROUTE_ENUM = 4
_MAX_BYTES = 1 << 20
_PROFILE = DEFAULT_LOCAL_XID_PROFILE


def _json_text(value):
    if isinstance(value, Mapping):
        text = json.dumps(dict(value), ensure_ascii=False, separators=(",", ":"))
    elif isinstance(value, str):
        text = value
    else:
        raise ValueError("scfg plaintext must be a JSON object or its original text")
    if len(text.encode("utf-8")) > _MAX_BYTES:
        raise ValueError("scfg plaintext exceeds size limit")
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ValueError("invalid scfg JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("scfg plaintext must contain a JSON object")
    return text


def encode_scfg_data(value):
    """Encrypt a JSON object; original JSON text preserves exact serialization."""
    raw = _json_text(value).encode("utf-8")
    encrypted = AES.new(_PROFILE.key, AES.MODE_CBC, _PROFILE.iv).encrypt(pad(raw, 16))
    return base64.b64encode(encrypted).decode("ascii")


def decode_scfg_data(value, *, as_text=False):
    """Strictly decode a request data or response data.resStr value."""
    if not isinstance(value, str) or not value or len(value) > (_MAX_BYTES + 16) * 2:
        raise ValueError("scfg data must be bounded Base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
        if not raw or len(raw) % 16 or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError("noncanonical ciphertext")
        plain = unpad(AES.new(_PROFILE.key, AES.MODE_CBC, _PROFILE.iv).decrypt(raw), 16)
        text = _json_text(plain.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("scfg decryption, padding or JSON validation failed") from exc
    return text if as_text else json.loads(text)


def build_scfg_request(raw_fields, *, os_version, dfp_id, timestamp_ms,
                       sdk_version, user_id, city):
    """Build the native request from explicit current collector/state inputs.

    raw_fields supplies m154 (package), m144 (package version code), m153 (uuid)
    and m136 (dpid). user_id=None selects the native logged-out value -1.
    Other user IDs must be the SDK intValue result, a signed 32-bit integer.
    """
    if not isinstance(raw_fields, Mapping):
        raise ValueError("scfg raw_fields must be an object")
    needed = ("m154", "m144", "m153", "m136")
    if any(not isinstance(raw_fields.get(k), str) for k in needed):
        raise ValueError("scfg requires raw string m154/m144/m153/m136 values")
    if not all(isinstance(v, str) for v in (os_version, dfp_id, sdk_version, city)) or not sdk_version:
        raise ValueError("scfg environment values must be strings, with a nonempty SDK version")
    if type(timestamp_ms) is not int or timestamp_ms < 0:
        raise ValueError("scfg timestamp_ms must be a nonnegative integer")
    uid = -1 if user_id is None else user_id
    if type(uid) is not int or not -(1 << 31) <= uid < (1 << 31):
        raise ValueError("scfg user_id must be None or a signed 32-bit integer")
    fields = {"os_version": os_version, "package": raw_fields["m154"],
              "package_version_code": raw_fields["m144"], "timestamp": str(timestamp_ms),
              "dfpid": dfp_id, "uuid": raw_fields["m153"], "userid": str(uid),
              "city": city, "dpid": raw_fields["m136"]}
    return {"data": encode_scfg_data(fields), "os": "iOS", "mtg_version": sdk_version}


def parse_scfg_response(response, *, http_status, previous_private_fields=()):
    """Return a validated state patch, or {} for a rejected/malformed response.

    Use data.resStr only. Each native request clears applistOpen first; only
    the exact response string "221" enables it. private_key_config is split
    on "|" and appended (including empty entries), not treated as a key.
    version_code is retained in the config snapshot; this callback doesn't
    establish an action for it, interval, clientIp or serverTimestamp.
    """
    if (type(http_status) is not int or not 200 <= http_status < 300
            or not isinstance(response, Mapping) or type(response.get("code")) is not int
            or response["code"] != 0 or response.get("error")
            or ("success" in response and response["success"] is not True)
            or not isinstance(response.get("data"), Mapping)):
        return {}
    if (not isinstance(previous_private_fields, (list, tuple))
            or not all(isinstance(v, str) for v in previous_private_fields)):
        raise ValueError("previous_private_fields must be a list or tuple of strings")
    try:
        config = decode_scfg_data(response["data"].get("resStr"))
    except ValueError:
        return {}
    private = list(previous_private_fields)
    if isinstance(config.get("private_key_config"), str):
        private.extend(config["private_key_config"].split("|"))
    return {"scfg_config": config, "scfg_applist_open": config.get("applist_config") == "221",
            "scfg_private_collect_fields": private}

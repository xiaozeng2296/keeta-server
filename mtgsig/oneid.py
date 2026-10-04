"""Observed OneID registration bodies and response state, with no network I/O.

The Charles captures call /uuid/oversea/ios/register with idInfo.requiredId
1 and 4 in different array orders. Both responses call their output data.unionId;
the request's requiredId determines whether it becomes csecuuid/uuid or
pragma-unionid. Length is not a discriminator.
"""
import copy
import hashlib
import json
import re
from uuid import UUID, uuid4
from collections.abc import Mapping, MutableMapping


ONEID_PATH = "/uuid/oversea/ios/register"


def _identifier_checksum(value):
    """Native 0x28557dc: decimal check digit over hexadecimal symbols."""
    total = 0
    for index, char in enumerate(value):
        digit = int(char, 16)
        if index % 2 == 0:
            digit *= 2
            while digit > 9:
                digit = digit // 10 + digit % 10
        total += digit
    return str((-total) % 10)


def generate_oneid_identifier(uuid_value, timestamp_text):
    """Generate the SDK's 50-character local/session/request ID offline.

    timestamp_text is the exact NSNumber seconds string, including a possible
    fractional part. Native removes '.', pads/truncates to 16 characters,
    then appends MD5[8:24] to the normalized UUID. Two checksum digits are
    inserted at offsets 14 and 15. This is separate from SAK's local a8.
    """
    if not isinstance(uuid_value, (str, UUID)):
        raise TypeError("OneID UUID must be text or UUID")
    normalized = UUID(str(uuid_value)).hex
    if not isinstance(timestamp_text, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", timestamp_text):
        raise ValueError("OneID timestamp must be an explicit decimal seconds string")
    material = (timestamp_text.replace(".", "") + "0" * 16)[:16]
    raw = normalized + hashlib.md5(material.encode("ascii")).hexdigest()[8:24]
    check = _identifier_checksum(raw[:24]) + _identifier_checksum(raw[24:])
    return raw[:14] + check + raw[14:]


def decode_oneid_identifier(value):
    """Validate the two checksums and recover UUID and opaque time digest."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{50}", value):
        raise ValueError("OneID identifier must contain 50 lowercase hexadecimal characters")
    raw = value[:14] + value[16:]
    if value[14:16] != _identifier_checksum(raw[:24]) + _identifier_checksum(raw[24:]):
        raise ValueError("OneID identifier checksum mismatch")
    return {"uuid": str(UUID(hex=raw[:32])), "time_digest": raw[32:]}


def initialize_oneid_session(profile, timestamp_text):
    """Generate missing local/session IDs once, retaining explicit inputs.

    Request IDs are generated separately per request. IDFV and the rest of
    the device profile are still explicit caller inputs.
    """
    output = copy.deepcopy(dict(profile))
    for field in ("oneid_local_id", "oneid_session_id"):
        if field not in output:
            output[field] = generate_oneid_identifier(uuid4(), timestamp_text)
    return output


def _valid_text(value):
    return (isinstance(value, str) and bool(value) and
            all(c.isprintable() and not c.isspace() for c in value))


def _text(value, name):
    if not _valid_text(value):
        raise ValueError(f"OneID {name} must be nonempty text without whitespace")
    return value


def _body_object(value):
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, Mapping):
        raise ValueError("OneID body must be a JSON object")
    return copy.deepcopy(dict(value))


def _required_id(value):
    if type(value) is not int or value not in (1, 4):
        raise ValueError("OneID requiredId must be integer 1 or 4")
    return value


def _merge_object(body, field, updates):
    if not isinstance(body.get(field), Mapping):
        raise ValueError(f"OneID {field} must be an object")
    if updates is not None:
        if not isinstance(updates, Mapping):
            raise ValueError(f"OneID {field} overrides must be an object")
        body[field].update(copy.deepcopy(dict(updates)))


def build_oneid_body(template, profile=None, *, required_id=None):
    """Build a body from a captured JSON template and explicit profile values.

    ``idfv`` replaces deviceInfo.keyDeviceInfo.idfv; its exact UTF-8 bytes
    determine secondaryDeviceInfo.signature (MD5). ``oneid_local_id`` and
    ``oneid_session_id`` replace the corresponding idInfo fields. These names
    intentionally differ from SAKGuard's unrelated localid/session values.

    Optional oneid_app_info, oneid_environment_info, oneid_communication_info
    and oneid_device_info mappings update those template sections; explicit
    idfv takes precedence and signature is always recomputed. Optional
    oneid_extension is a JSON object/text stored as the observed JSON string.
    Fields that are not supplied are retained from the template; this is not
    a new-device profile generator and does not prove a successful registration.
    """
    body = _body_object(template)
    if profile is not None and not isinstance(profile, Mapping):
        raise ValueError("OneID profile must be an object")
    profile = profile or {}
    for field, key in (("appInfo", "oneid_app_info"),
                       ("environmentInfo", "oneid_environment_info"),
                       ("communicationInfo", "oneid_communication_info"),
                       ("deviceInfo", "oneid_device_info"), ("idInfo", None)):
        _merge_object(body, field, profile.get(key) if key else None)
    info = body["idInfo"]
    info["requiredId"] = _required_id(info.get("requiredId") if required_id is None else required_id)
    for source, target in (("oneid_local_id", "localId"), ("oneid_session_id", "sessionId")):
        if source in profile:
            info[target] = _text(profile[source], source)
        _text(info.get(target), f"idInfo.{target}")
    device = body["deviceInfo"]
    for key in ("keyDeviceInfo", "secondaryDeviceInfo"):
        if not isinstance(device.get(key), Mapping):
            raise ValueError(f"OneID deviceInfo.{key} must be an object")
    idfv = _text(profile.get("idfv", device["keyDeviceInfo"].get("idfv")), "idfv")
    device["keyDeviceInfo"]["idfv"] = idfv
    device["secondaryDeviceInfo"]["signature"] = hashlib.md5(idfv.encode("utf-8")).hexdigest()
    if "oneid_extension" in profile:
        extension = profile["oneid_extension"]
        if isinstance(extension, str):
            decoded = json.loads(extension)
            if not isinstance(decoded, dict):
                raise ValueError("OneID extension must encode an object")
            body["extension"] = extension
        elif isinstance(extension, Mapping):
            body["extension"] = json.dumps(dict(extension), ensure_ascii=False, separators=(",", ":"))
        else:
            raise ValueError("OneID extension must be an object or JSON object text")
    return body


def oneid_header_updates(body, profile=None):
    """Headers coupled to a constructed body; request ID is explicit if known.

    Both captured requests have uuidSessionId == idInfo.sessionId. A caller
    may supply oneid_request_id; otherwise preserve its template request ID.
    No mtgsig header was present on either observed OneID request.
    """
    body = _body_object(body)
    info = body.get("idInfo")
    if not isinstance(info, Mapping):
        raise ValueError("OneID idInfo must be an object")
    updates = {"uuidSessionId": _text(info.get("sessionId"), "sessionId")}
    if profile and "oneid_request_id" in profile:
        updates["uuidRequestId"] = _text(profile["oneid_request_id"], "requestId")
    return updates


def parse_oneid_response(request_body, response, *, http_status):
    """Return a state patch only for a successful response to this request.

    Call this only for ONEID_PATH and pass the exact body that was sent.
    Unknown/missing requiredId, HTTP/code failures and wrong types yield {}.
    The data.unionId label alone does not identify which state to update.
    """
    if type(http_status) is not int or not 200 <= http_status < 300:
        return {}
    try:
        request = _body_object(request_body)
        info = request.get("idInfo")
        if not isinstance(info, Mapping):
            return {}
        required = _required_id(info.get("requiredId"))
    except (TypeError, ValueError):
        return {}
    if not isinstance(response, Mapping) or type(response.get("code")) is not int or response["code"] != 0:
        return {}
    if response.get("error") or ("success" in response and response["success"] is not True):
        return {}
    data = response.get("data")
    if not isinstance(data, Mapping) or not _valid_text(data.get("unionId")):
        return {}
    value = data["unionId"]
    return {"csecuuid": value, "uuid": value} if required == 4 else {"unionid": value}


def apply_oneid_response(state, request_body, response, *, http_status):
    """Apply a validated OneID patch atomically and return changed fields."""
    if not isinstance(state, MutableMapping):
        raise TypeError("OneID state must be a mutable mapping")
    patch = parse_oneid_response(request_body, response, http_status=http_status)
    changed = {k: v for k, v in patch.items() if state.get(k) != v}
    state.update(changed)
    return changed

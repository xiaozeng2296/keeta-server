"""Construct each registration payload from current state before signing.

The caller supplies observed device data. This module refreshes established
identity/time fields; it does not manufacture telemetry or guess field shifts.
"""
from copy import deepcopy
import json
from uuid import uuid4

from mtgsig import envelope_codec, mtg_crypto
from mtgsig.corpse_codec import encode_fields

ENVELOPE_SLOTS = {
    "envelope_info": "envelope_info_data", "envelope_sign": "envelope_sign_data",
    "envelope_device": "envelope_device_data", "envelope_bio": "envelope_bio_data",
    "envelope_ntp": "envelope_ntp_data",
}


def render_envelope_plaintext(config, state):
    """Apply explicitly established bindings/shifts to one plaintext object.

    ``raw_plaintext`` preserves an exact UTF-8 pre-deflate string. Otherwise
    ``plaintext`` is a JSON object, optional ``bindings`` map its top-level
    fields to state keys. ``transform="m-series"`` applies the recovered
    per-field table; the default ``none`` preserves prepared field values.
    """
    if not isinstance(config, dict):
        raise TypeError("envelope payload configuration must be an object")
    if "raw_plaintext" in config:
        if any(k in config for k in ("plaintext", "bindings", "transform", "passthrough", "caesar_shifts", "derive_m239", "derive_m175", "derive_outid_history", "checksum_context")):
            raise ValueError("raw envelope plaintext cannot include field transformations")
        raw = config["raw_plaintext"]
        if not isinstance(raw, str) or not raw:
            raise ValueError("raw envelope plaintext must be nonempty text")
        return raw.encode("utf-8")
    value = deepcopy(config.get("plaintext"))
    if not isinstance(value, dict):
        raise ValueError("envelope plaintext must be a JSON object")
    for field, source in config.get("bindings", {}).items():
        if field not in value:
            raise ValueError(f"envelope binding target is absent: {field}")
        if source not in state or state[source] is None:
            raise ValueError(f"envelope binding source is absent: {source}")
        value[field] = state[source]
    if "derive_m239" in config and type(config["derive_m239"]) is not bool:
        raise ValueError("derive_m239 must be bool")
    if config.get("derive_m239"):
        from mtgsig.timestamp_identity import m239_from_m251
        if "m239" not in value or "m251" not in value:
            raise ValueError("m239 derivation requires both m239 and m251 in this route")
        value["m239"] = m239_from_m251(value["m251"])
    elif "m251" in config.get("bindings", {}) and "m239" in value:
        raise ValueError("binding m251 requires derive_m239 to keep its checksum consistent")
    if "derive_m175" in config and type(config["derive_m175"]) is not bool:
        raise ValueError("derive_m175 must be bool")
    m175_sources = {"m166", "m160", "m19", "m167"}
    if config.get("derive_m175"):
        from mtgsig.m175_codec import encode_m175
        if not m175_sources.union({"m175"}) <= set(value):
            raise ValueError("m175 derivation requires m175/m166/m160/m19/m167 in this route")
        if "device_name" not in state or "timestamp_ms" not in state:
            raise ValueError("m175 derivation requires explicit device_name and timestamp_ms")
        value["m175"] = encode_m175(model=value["m166"], system_version=value["m160"],
            field19=value["m19"], screen=value["m167"], device_name=state["device_name"],
            timestamp_ms=state["timestamp_ms"])
    elif "m175" in value and m175_sources.intersection(config.get("bindings", {})):
        raise ValueError("binding m175 source fields requires derive_m175")
    if "derive_outid_history" in config and type(config["derive_outid_history"]) is not bool:
        raise ValueError("derive_outid_history must be bool")
    if config.get("derive_outid_history"):
        # Explicit protocol refresh policy, not native async cache timing.
        # Only a confirmed keychain-writing response sets outid_history_dfp.
        if state.get("fresh_outid_history") is not True:
            raise ValueError("outid history derivation requires an explicit fresh session")
        if not {"m306", "m166", "m154", "m320"} <= set(value) or not config.get("checksum_context"):
            raise ValueError("outid history derivation requires m306/m166/m154/m320 and checksum_context")
        for key in ("m166", "m154"):
            item = value[key]
            if not isinstance(item, str) or not item or any(not c.isprintable() or c.isspace() for c in item):
                raise ValueError("outid history source must be a nonempty model or bundle identifier")
        if state.get("model") is not None and state["model"] != value["m166"]:
            raise ValueError("outid history model differs from current profile")
        if not isinstance(value["m306"], str):
            raise ValueError("outid history requires string-valued m306")
        nested = json.loads(value["m306"])
        if not isinstance(nested, dict) or not isinstance(nested.get("m400"), str) or not isinstance(json.loads(nested["m400"]), dict):
            raise ValueError("outid history requires an existing object-valued m400 string")
        history = {}
        if "outid_history_dfp" in state:
            dfp = state["outid_history_dfp"]
            if not isinstance(dfp, str) or not dfp or any(not c.isprintable() or c.isspace() for c in dfp):
                raise ValueError("outid history requires a valid accepted keychain DFP value")
            history = {value["m166"] + "Apple": [{value["m154"]: dfp}]}
        nested["m400"] = json.dumps(history, ensure_ascii=False, separators=(",", ":"))
        value["m306"] = json.dumps(nested, ensure_ascii=False, separators=(",", ":"))
    checksum = config.get("checksum_context")
    if checksum is not None:
        from mtgsig.registration_checksum import compute_m320
        if not isinstance(checksum, dict) or "m320" not in value:
            raise ValueError("checksum_context requires an object and an existing m320 field")
        required = {"appkey", "version", "sdk_flag", "provider_mask_hex"}
        if not required <= set(checksum) or set(checksum) - required - {"guard_fault"}:
            raise ValueError("checksum_context requires appkey, version, sdk_flag and provider_mask_hex")
        mask_hex = checksum["provider_mask_hex"]
        if not isinstance(mask_hex, str):
            raise ValueError("m320 provider_mask_hex must be hexadecimal text")
        value["m320"] = compute_m320(value, appkey=checksum["appkey"], version=checksum["version"],
            sdk_flag=checksum["sdk_flag"], provider_mask=bytes.fromhex(mask_hex),
            guard_fault=checksum.get("guard_fault", False))
    elif "m320" in value and (config.get("bindings") or config.get("derive_m239") or config.get("derive_m175") or config.get("derive_outid_history")):
        raise ValueError("changing registration fields requires checksum_context to refresh m320")
    if "caesar_shifts" in config:
        raise ValueError("use the recovered m-series transform instead of guessed Caesar shifts")
    transform = config.get("transform", "none")
    if transform == "m-series":
        value = encode_fields(value, passthrough=config.get("passthrough", ()))
    elif transform != "none":
        raise ValueError("envelope transform must be none or m-series")
    elif config.get("passthrough"):
        raise ValueError("passthrough requires the m-series transform")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def prepare_request_profile(step, state, *, timestamp_ms, a1, session_key=None):
    """Return a copy containing this step's fresh body inputs; no I/O.

    A payloads use ``state.envelope_payloads[step.name]`` and require an SDK
    session key. Captured opaque slots remain explicit compatibility inputs.
    B inputs remain separate from A payloads and server XID/DFP values.
    """
    if type(timestamp_ms) is not int or timestamp_ms < 0:
        raise ValueError("timestamp_ms must be a nonnegative integer")
    output = deepcopy(state)
    output["timestamp_ms"] = timestamp_ms
    if "login_context_inputs" in state:
        from mtgsig.login_context import context_profile_fields
        output.update(context_profile_fields(state))
    if step.get("name") in ("bio_report", "device_info") and "reporting_inputs" in state:
        from mtgsig.registration_reporting import build_reporting_outer
        inputs = state["reporting_inputs"]
        if not isinstance(inputs, dict) or step["name"] not in inputs:
            raise ValueError("reporting_inputs missing this route's current-session inputs")
        fields = build_reporting_outer(step["name"], inputs[step["name"]], timestamp_ms=timestamp_ms)
        overrides = output.setdefault("request_body_fields", {}).setdefault(step["path"], {})
        if set(fields).intersection(overrides):
            raise ValueError("reporting outer fields must use reporting_inputs only")
        overrides.update(fields)
    if step.get("path") == "/uuid/oversea/ios/register" and "oneid_request_id" not in state:
        from mtgsig.oneid import generate_oneid_identifier
        output["oneid_request_id"] = generate_oneid_identifier(
            uuid4(), format(timestamp_ms / 1000, ".16g"))
    if step.get("path") == "/v1/scfg":
        from mtgsig.scfg import build_scfg_request
        config = state.get("scfg_inputs")
        required = {"raw_fields", "os_version", "sdk_version", "city", "user_id"}
        if not isinstance(config, dict) or set(config) != required:
            raise ValueError("scfg_inputs requires raw_fields, os_version, sdk_version, city and user_id")
        fields = deepcopy(config["raw_fields"])
        if not isinstance(fields, dict):
            raise ValueError("scfg raw_fields must be an object")
        for name in ("csecuuid", "a8"):
            if not isinstance(state.get(name), str) or not state[name]:
                raise ValueError(f"scfg requires current-session {name}")
        # m153 and getFingerprintID follow this protocol session, not the
        # phone/cache from which the non-identity observations were obtained.
        fields["m153"] = state["csecuuid"]
        output["scfg_request"] = build_scfg_request(fields,
            os_version=config["os_version"], dfp_id=state["a8"],
            timestamp_ms=timestamp_ms, sdk_version=config["sdk_version"],
            user_id=config["user_id"], city=config["city"])
    source = state.get("fingerprint_obj")
    if source is None and state.get("fingerprint_plain_json") is not None:
        raw = state["fingerprint_plain_json"]
        source = json.loads(raw) if isinstance(raw, str) else raw
    if source is not None:
        if state.get("fingerprint"):
            raise ValueError("choose plaintext fingerprint or captured fingerprint, not both")
        fp = deepcopy(source)
        if not isinstance(fp, dict):
            raise ValueError("registration fingerprint must be an I-series object")
        # Exact equality in both source captures establishes these mappings.
        for field, name in (("I20", "idfv"), ("I40", "csecuuid"), ("I18", "device_id")):
            if name in output and field in fp:
                fp[field] = output[name]
        if "I39" in fp:
            fp["I39"] = str(timestamp_ms) if isinstance(fp["I39"], str) else timestamp_ms
        for field, value in state.get("fingerprint_dynamic_fields", {}).items():
            if field not in ("I39", "I41", "I44"):
                raise ValueError("fingerprint dynamic fields support I39, I41 and I44 only")
            fp[field] = value
        key = state.get("fingerprint_key", mtg_crypto.FINGERPRINT_I_KEY)
        iv = state.get("fingerprint_iv", mtg_crypto.FINGERPRINT_IV)
        def as_bytes(value):
            if isinstance(value, str):
                try:
                    return bytes.fromhex(value) if len(value) == 32 else value.encode()
                except ValueError:
                    return value.encode()
            return value
        output["fingerprint"] = mtg_crypto.fingerprint_encrypt(fp, key=as_bytes(key), iv=as_bytes(iv))
        output["fingerprint_obj"] = fp
    slot = ENVELOPE_SLOTS.get(step["body_type"])
    config = state.get("envelope_payloads", {}).get(step["name"])
    if step["body_type"] == "envelope_ntp" and config is None and not state.get(slot):
        raise ValueError("NTP requires current-session envelope_payloads.ntp or envelope_ntp_data")
    if slot and config is not None:
        if session_key is None:
            raise ValueError("envelope session key is required")
        plaintext = render_envelope_plaintext(config, output)
        output[slot] = envelope_codec.encode_sdk(
            plaintext, a1, session_key=session_key,
            mode=state.get("envelope_mode", "twofish-mod"),
            profile=state.get("envelope_profile", "default"),
            compress=config.get("compress", True))
    return output

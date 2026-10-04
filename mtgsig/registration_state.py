"""Explicit registration-response updates for a Keeta signing identity.

The observed fingerprint info ``data.result``
supplies the server XID (a7), and v5/sign ``data.dfp`` supplies the server DFP
(a8). FAMA /ntp has a separate strict A/1.0 decoder and cache transition.
HTTP success alone is insufficient; each endpoint's business status validates.
This module performs no HTTP, signing, persistence, or identity generation.
"""
from collections.abc import Mapping, MutableMapping
from urllib.parse import urlsplit


_ENDPOINT_FIELDS = {
    "/fingerprint/v1/info/report": ("result", "a7", "a7_local_xid", "a7_server_xid", "xid"),
    "/v5/sign": ("dfp", "a8", "a8_local_dfp", "a8_server_dfp", "dfp"),
    "/ntp": ("ntp_info", "a8", "a8_local_dfp", "a8_server_dfp", "dfp"),
}


def _field_spec(endpoint):
    if not isinstance(endpoint, str):
        return None
    try:
        return _ENDPOINT_FIELDS.get(urlsplit(endpoint).path)
    except ValueError:
        return None


def _identity_value(value):
    # Keep identity values opaque rather than assuming a cipher or fixed
    # length.  Reject coercion, empty strings, whitespace, and control bytes.
    return (isinstance(value, str) and bool(value) and
            all(c.isprintable() and not c.isspace() for c in value))


def parse_registration_response(endpoint, response, *, http_status):
    """Return a validated identity patch, or ``{}`` when it is not accepted.

    ``endpoint`` may be an exact path or full URL (a query is ignored).
    ``response`` must already be a decoded JSON object.  Callers must pass
    the actual HTTP status; no implicit successful status is supplied.
    Successful patches contain the effective signing field and both explicit
    server aliases, e.g. ``a7``, ``a7_server_xid``, and ``xid``.  Arbitrary
    nested fields, string codes, bool codes, and responses for other paths
    never update registration state.
    """
    spec = _field_spec(endpoint)
    if spec is None or type(http_status) is not int or not 200 <= http_status < 300:
        return {}
    if urlsplit(endpoint).path == "/ntp":
        from mtgsig.ntp_protocol import decode_ntp_response
        try:
            decoded = decode_ntp_response(response, http_status=http_status)
        except (TypeError, ValueError):
            return {}
        return dict(decoded.identity_patch(), ntp_fingerprint_data=decoded.fingerprint_data(),
                    ntp_response_source=decoded.source_endpoint)
    if not isinstance(response, Mapping):
        return {}
    if type(response.get("code")) is not int or response["code"] != 0:
        return {}
    if response.get("error") or ("success" in response and response["success"] is not True):
        return {}
    data = response.get("data")
    if not isinstance(data, Mapping):
        return {}
    wire_field, current_field, _, server_field, alias = spec
    value = data.get(wire_field)
    if not _identity_value(value):
        return {}
    patch = {current_field: value, server_field: value, alias: value}
    # Native /v5/sign completion 0x327758 enters the direct keychain writer
    # only for ab_test_flag == B. Native cache observations also contain A,
    # but its other write path is not yet reproduced here; merely accepting
    # its a8 does not prove that this response refreshed outidInfoData.
    if current_field == "a8" and data.get("ab_test_flag") == "B":
        patch["outid_history_dfp"] = value
    return patch


def apply_registration_response(identity, endpoint, response, *, http_status):
    """Update a mutable signing identity and return only changed fields.

    ``identity`` uses the same flat keys as ``FullSigner.dev``.  Validation
    finishes before mutation, so errors leave every field unchanged.  An
    existing ``a7_local_xid``/``a8_local_dfp`` is always preserved.  On the
    first server transition, if no server alias exists and the value changes,
    the preceding a7/a8 value is retained as the local candidate.  A value
    already equal to the response is not relabelled as local.  Pass an identity representing
    the request that produced the response, not a different device/session.

    An OfflineSigner integration must update both ``mt`` and the corresponding
    fields in ``pay_template``; updating just ``mt`` would sign stale data.
    Persistence and signer synchronization are explicit caller operations.
    """
    if not isinstance(identity, MutableMapping):
        raise TypeError("identity must be a mutable mapping")
    patch = parse_registration_response(endpoint, response, http_status=http_status)
    if not patch:
        return {}
    _, current_field, local_field, server_field, alias = _field_spec(endpoint)
    if (local_field not in identity and
            not _identity_value(identity.get(server_field)) and
            not _identity_value(identity.get(alias)) and
            _identity_value(identity.get(current_field)) and
            identity[current_field] != patch[current_field]):
        patch[local_field] = identity[current_field]
    changed = {key: value for key, value in patch.items()
               if key not in identity or identity[key] != value}
    identity.update(changed)
    return changed

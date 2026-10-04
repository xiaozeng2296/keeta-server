"""按 Charles 抓包顺序构造并执行注册请求，保留重复请求和各自模板。

FullSigner 每请求签名；OneID、XID、DFP 按成功响应回填后再构造下一步。
A envelope 可从明确的 pre-deflate 文本或 m-series 字段生成，B fingerprint
可从 I-series 对象生成。设备画像由调用者提供，不能由加密算法推断。
默认只构造请求；--send 才发送。完整成功抓包用于离线校验，不代表本次协议会话已被放行。

用法:
  python3 keeta_offline_flow.py --profile prof.json                 # dry-run 打印全流程请求
  python3 keeta_offline_flow.py --profile prof.json --only userriskcheck
  python3 keeta_offline_flow.py --profile prof.json --send          # 逐响应执行
  python3 keeta_offline_flow.py --demo                              # 无网络自检
"""
import argparse, json, os, re, secrets, sys, time, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtgsig import mtg_crypto
from mtgsig.newreg import NEWREG_APP_NAME, NEWREG_PASSWORD, newreg_signature, parse_newreg_response
from mtgsig.registration_state import parse_registration_response
from mtgsig.registration_payloads import ENVELOPE_SLOTS, prepare_request_profile
from mtgsig import login_protocol
from mtgsig import registration_region
from mtgsig import incognia_state
from mtgsig.request_trace import ensure_m_shark_session_marker

HERE = os.path.dirname(os.path.abspath(__file__))
CHLSJ = os.path.join(HERE, "evidence", "captures", "从app初次打开到登录被拦截.chlsj")
PSEUDO = {":method", ":scheme", ":path", ":authority"}

# 登录关键接口(保留旧的三元组 API，供已有脚本引用)。
# 新代码应使用 FLOW_STEPS/build_offline_plan，它还包含 fingerprint info report
# 并能在不同抓包中的 host 别名之间回退查找模板。
LOGIN_FLOW = [
    ("mtpush.mykeeta.com",       "/sdkapi/newreg",                              "plaintext_json"),
    ("fooddelivery-eu.mykeeta.com","/appupdate/mach/checkUpdate",               "plaintext_json"),
    ("pikachu.mykeeta.com",      "/fingerprint/v1/info/report",                "envelope"),
    ("pikachu.mykeeta.com",      "/v5/sign",                                    "envelope"),
    ("pikachu.mykeeta.com",      "/v5/device-info",                             "envelope"),
    ("fooddelivery.mykeeta.com", "/fingerprint/v1/app/bio/info/report",         "envelope"),
    ("fooddelivery.mykeeta.com", "/api/protocolcenter/v1/protocol/confirmProtocol","plaintext_urlencoded"),
    ("passport-hk.mykeeta.com",  "/api/emaillogin/v1/userriskcheck",            "plaintext_urlencoded"),
]

# 设备注册/登录前需要生成的最小请求计划。每一步只描述模板和替换方式，
# 不会隐式发送网络请求。``name`` 是稳定的离线审计标识。
FLOW_STEPS = [
    {"name": "oneid_register", "host": "uuid-eu.mykeeta.com",
     "path": "/uuid/oversea/ios/register", "body_type": "plaintext_json"},
    {"name": "newreg", "host": "mtpush.mykeeta.com", "path": "/sdkapi/newreg",
     "body_type": "plaintext_json"},
    {"name": "check_update", "host": "fooddelivery-eu.mykeeta.com",
     "path": "/appupdate/mach/checkUpdate", "body_type": "plaintext_json"},
    {"name": "fingerprint_info", "host": "pikachu.mykeeta.com",
     "path": "/fingerprint/v1/info/report", "body_type": "envelope_info"},
    {"name": "ntp", "host": "poke.mykeeta.com", "path": "/ntp",
     "body_type": "envelope_ntp"},
    {"name": "v5_sign", "host": "pikachu.mykeeta.com", "path": "/v5/sign",
     "body_type": "envelope_sign"},
    {"name": "compass", "host": "i18n-eu.mykeeta.com",
     "path": registration_region.COMPASS_CONFIG_PATH, "body_type": "plaintext_json"},
    {"name": "service_regions", "host": "fooddelivery-eu.mykeeta.com",
     "path": registration_region.SERVICE_REGIONS_PATH, "body_type": "plaintext_json"},
    {"name": "current_local_info", "host": "i18n-eu.mykeeta.com",
     "path": registration_region.CURRENT_LOCAL_INFO_PATH, "body_type": "plaintext_urlencoded"},
    {"name": "scfg", "host": "pikachu.mykeeta.com",
     "path": "/v1/scfg", "body_type": "scfg"},
    {"name": "bio_report", "host": "fooddelivery.mykeeta.com",
     "path": "/fingerprint/v1/app/bio/info/report", "body_type": "envelope_bio"},
    {"name": "device_info", "host": "pikachu.mykeeta.com", "path": "/v5/device-info",
     "body_type": "envelope_device"},
    {"name": "confirm_protocol", "host": "fooddelivery.mykeeta.com",
     "path": "/api/protocolcenter/v1/protocol/confirmProtocol",
     "body_type": "plaintext_urlencoded"},
    {"name": "user_risk_check", "host": "passport-hk.mykeeta.com",
     "path": "/api/emaillogin/v1/userriskcheck", "body_type": "plaintext_urlencoded"},
]

UNSIGNED_PATHS = {"/sdkapi/newreg", "/uuid/oversea/ios/register"}

# Charles 抓包按区域/启动阶段使用过多个同义 host。优先使用请求规范中的
# host，找不到时再选抓包里实际出现的别名，并将最终 host 回写到 URL。
HOST_ALIASES = {
    "/ntp": ("poke.mykeeta.com", "poke-eu.mykeeta.com"),
    "/appupdate/mach/checkUpdate": ("dd-eu.mykeeta.com", "fooddelivery-eu.mykeeta.com"),
    "/api/protocolcenter/v1/protocol/confirmProtocol": (
        "fooddelivery.mykeeta.com", "fooddelivery-eu.mykeeta.com"),
    "/fingerprint/v1/app/bio/info/report": (
        "fooddelivery.mykeeta.com", "pikachu.mykeeta.com"),
    registration_region.COMPASS_CONFIG_PATH: ("i18n-eu.mykeeta.com", "i18n.mykeeta.com"),
    registration_region.SERVICE_REGIONS_PATH: ("fooddelivery-eu.mykeeta.com", "fooddelivery.mykeeta.com"),
    registration_region.CURRENT_LOCAL_INFO_PATH: (
        "i18n-eu.mykeeta.com", "i18n.mykeeta.com", "fooddelivery-eu.mykeeta.com", "fooddelivery.mykeeta.com"),
}

# DeviceProfile: 要替换进模板的设备画像。空值=沿用 chlsj 原样(不替换)。
PROFILE_KEYS = [
    "email", "uuid", "csecuuid", "idfv", "mac", "signature", "apnstoken",
    "app_name", "bundle_id", "newreg_password", "newreg_signature",
    "unionid", "localid", "sessionid", "token", "userid", "csecuserid",
    "incog-token", "header_overrides", "incognia", "incognia_state",
    "fingerprint",        # B 型 blob(checkUpdate/confirmProtocol/userriskcheck 复用)
    "fingerprint_plain_json",  # I-series JSON; encrypted locally when fingerprint omitted
    "fingerprint_obj",         # alias for an object/list I-series value
    "fingerprint_key", "fingerprint_iv",
    "envelope_data",      # A 型兼容槽（旧 profile）
    "envelope_sign_data", "envelope_device_data", "envelope_info_data",
    "envelope_bio_data", "envelope_ntp_data",  # A 型各接口独立槽
    "tk_context_plain", "token_id", "dfp", "requestCode", "responseCode",
    "userTicket", "serialNumber", "emailCode", "random", "country", "model",
    "os", "mode", "network", "app_version", "channel", "platform", "app",
    "region_inputs", "region_compass_response", "service_region_candidates", "region_state", "compass_snapshot",
    "outid_history_dfp", "ntp_fingerprint_data", "ntp_response_source",
]

def _fp_key_bytes(value, default):
    if value is None:
        return default
    if isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value):
        return bytes.fromhex(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise ValueError("fingerprint key/iv must be text or bytes")


def profile_fingerprint(profile):
    """Return the B-line I-series fingerprint, deriving it when given JSON.

    Existing profiles may keep a captured ``fingerprint`` blob.  New profiles
    can instead provide ``fingerprint_plain_json`` (exact JSON text) or
    ``fingerprint_obj``; the latter is serialized compactly before AES-CBC.
    """
    if profile.get("fingerprint"):
        return profile["fingerprint"]
    plain = profile.get("fingerprint_plain_json")
    if plain is None:
        plain = profile.get("fingerprint_obj")
    if plain is None:
        return None
    key = _fp_key_bytes(profile.get("fingerprint_key"), mtg_crypto.FINGERPRINT_I_KEY)
    iv = _fp_key_bytes(profile.get("fingerprint_iv"), mtg_crypto.FINGERPRINT_IV)
    return mtg_crypto.fingerprint_encrypt(plain, key=key, iv=iv)


def capture_authority(flow):
    """Use the HTTP request authority, not a coalesced HTTP/2 connection host."""
    headers = ((flow.get("request") or {}).get("header") or {}).get("headers") or []
    for name in (":authority", "host"):
        values = [h.get("value") for h in headers if h.get("name", "").lower() == name]
        if values:
            if len(set(values)) != 1:
                raise ValueError("conflicting capture authority headers")
            authority = values[0]
            break
    else:
        authority = flow.get("host")
    if not isinstance(authority, str) or not authority or any(c.isspace() for c in authority):
        raise ValueError("missing or invalid capture authority")
    parsed = urllib.parse.urlsplit("https://" + authority)
    if (not parsed.hostname or parsed.netloc != authority or parsed.path or parsed.query
            or parsed.fragment or parsed.username is not None or parsed.password is not None):
        raise ValueError("invalid capture authority")
    # Validate an explicit port without removing it from the request target.
    parsed.port
    return authority


def load_chlsj_index(path=CHLSJ):
    """(host, path_no_query) -> 该接口最后一次请求的 flow。"""
    idx = {}
    with open(path, encoding="utf-8") as stream:
        flows = json.load(stream)
    for f in flows:
        p = (f.get("path") or "").split("?")[0]
        if f.get("request") and p:
            idx[(capture_authority(f), p)] = f
    return idx


def _capture_body_type(item, default):
    """Use each plaintext request's own wire encoding, retaining A slots.

    confirmProtocol sends JSON for splash/region consent and form data for
    login consent; its path alone does not select one body format.
    """
    if default.startswith("envelope") or default == "scfg":
        return default
    request = item.get("request") or {}
    headers = (request.get("header") or {}).get("headers") or []
    content_type = next((h.get("value", "") for h in headers
                         if h.get("name", "").lower() == "content-type"), "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "application/json" or media_type.endswith("+json"):
        return "plaintext_json"
    if media_type == "application/x-www-form-urlencoded":
        return "plaintext_urlencoded"
    body = (request.get("body") or {}).get("text") or ""
    if body.lstrip().startswith(("{", "[")):
        try:
            json.loads(body)
        except (TypeError, ValueError):
            pass
        else:
            return "plaintext_json"
    return default


def load_capture_steps(path=CHLSJ):
    """Keep actual request order, repeated reports and each original template."""
    by_path = {step["path"]: step for step in FLOW_STEPS}
    steps = []
    with open(path, encoding="utf-8") as fh:
        for index, item in enumerate(json.load(fh)):
            spec = by_path.get((item.get("path") or "").split("?")[0])
            if spec and item.get("request", {}).get("body"):
                step = dict(spec, host=capture_authority(item), template=item,
                            body_type=_capture_body_type(item, spec["body_type"]),
                            capture_index=index)
                steps.append(step)
    return steps


def extract_template(flow):
    """flow -> (full_path_with_query, headers{无伪头/无mtgsig}, body_text)。"""
    fp, headers = flow.get("path"), {}
    if flow.get("query") and "?" not in fp:
        fp += "?" + flow["query"]
    for h in flow["request"]["header"]["headers"]:
        n, v = h["name"], h["value"]
        if n == ":path":
            fp = v
        if n in PSEUDO or n.lower() in ("mtgsig", "content-length", "incog-token"):
            continue
        headers[n] = v
    body = (flow["request"].get("body") or {}).get("text", "") or ""
    return fp, headers, body


# ---- 替换器:把 profile 值填进模板 body(明文)/ query ----
def _sub_urlencoded(body, profile):
    """urlencoded body:按 key 替换(值做 urlencode)。只动 profile 里给了的 key。"""
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    generated_fp = profile_fingerprint(profile)
    keymap = {"email": "email", "fingerprint": "fingerprint", "device_id": "device_id",
              "tk_context_plain": "tk_context_plain", "token_id": "token_id",
              "requestCode": "requestCode", "responseCode": "responseCode",
              "userTicket": "userTicket", "serialNumber": "serialNumber",
              "emailCode": "emailCode", "action": "action", "appId": "appId"}
    out = []
    for k, v in pairs:
        pk = keymap.get(k)
        if pk == "tk_context_plain" and pk in profile and profile[pk] is None:
            continue
        if pk:
            replacement = generated_fp if pk == "fingerprint" else profile.get(pk)
            if replacement is not None:
                v = replacement
        out.append((k, v))
    # A shared session may also contain login inputs. Only replace existing
    # keys here; endpoint builders or request_body_fields add explicit keys.
    return urllib.parse.urlencode(out)


def _json_replace(body, key, replacement):
    """Replace one top-level JSON scalar without reserializing the template."""
    if replacement is None:
        return body
    if isinstance(replacement, bytes):
        replacement = replacement.decode("utf-8")
    # Most device values are JSON strings. Keep the original ordering while
    # escaping the replacement as a JSON string; direct insertion would break
    # captures when an override contains a quote or backslash.
    if isinstance(replacement, str):
        encoded = json.dumps(replacement, ensure_ascii=False)
        return re.sub(r'("%s"\s*:\s*)"(?:\\.|[^"\\])*"' % re.escape(key),
                      lambda mo, val=encoded: mo.group(1) + val, body)
    # Numeric/bool fields (random, mode, network, ...) are also common in newreg.
    encoded = json.dumps(replacement, ensure_ascii=False, separators=(",", ":"))
    return re.sub(r'("%s"\s*:\s*)(?:"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'
                  % re.escape(key),
                  lambda mo, val=encoded: mo.group(1) + val, body)


def _sub_json(body, profile):
    """明文 JSON body:替换已知设备字段(字符串值精确替换,不重排结构)。"""
    m = {"fingerprint": "fingerprint", "UUID": "uuid", "uuid": "uuid",
         "deviceid": "idfv", "mac": "mac", "signature": "signature",
         "apnstoken": "apnstoken", "random": "random", "country": "country",
         "model": "model", "os": "os", "mode": "mode", "network": "network",
         "app_version": "app_version", "channel": "channel", "platform": "platform",
         "app": "app"}
    generated_fp = profile_fingerprint(profile)
    for jkey, pk in m.items():
        replacement = generated_fp if pk == "fingerprint" else profile.get(pk)
        if replacement is not None:
            body = _json_replace(body, jkey, replacement)
    return body


def _sub_newreg(body, profile, headers):
    """Sign the final random/app name, never retain a stale template signature."""
    obj = json.loads(body)
    if not isinstance(obj, dict):
        raise ValueError("newreg body must be a JSON object")
    random_value = profile.get("random", obj.get("random"))
    if random_value is None:
        raise ValueError("newreg random is required")
    app_name = (profile.get("app_name") or profile.get("bundle_id") or
                next((v for k, v in headers.items() if k.lower() == "appname"),
                     NEWREG_APP_NAME))
    signature = profile.get("newreg_signature") or profile.get("signature")
    if signature is None:
        signature = newreg_signature(random_value, app_name=app_name,
                                    password=profile.get("newreg_password", NEWREG_PASSWORD))
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{40}", signature):
        raise ValueError("newreg signature must be 40 lowercase hex characters")
    obj["random"] = str(random_value)
    obj["signature"] = signature
    app_header = next((k for k in headers if k.lower() == "appname"), "AppName")
    headers[app_header] = app_name
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _sub_envelope(body, profile, slot="envelope_data"):
    """Replace an A-envelope field with a per-endpoint profile slot.

    ``envelope_data`` remains a compatibility fallback. Keeping separate slots is
    necessary because v5/sign, device-info, info report, and bio report carry
    different plaintext sections even though their wire envelope prefix matches.
    """
    value = profile.get(slot) or profile.get("envelope_data")
    if value:
        body = re.sub(r'("(?:data|fingerPrintData)"\s*:\s*")[^"]*(")',
                      lambda mo, val=value: mo.group(1) + val + mo.group(2), body)
    return body


def _sub_ntp_envelope(body, profile):
    """NTP has exactly one data field and never reuses another route's slot."""
    source = json.loads(body)
    if not isinstance(source, dict) or set(source) != {"data"}:
        raise ValueError("NTP body must contain only data")
    value = profile.get("envelope_ntp_data")
    if not isinstance(value, str) or not value:
        raise ValueError("missing current-session envelope_ntp_data")
    return json.dumps({"data": value}, ensure_ascii=False, separators=(",", ":"))


def _sub_query(fp, profile):
    """query 里的 uuid/utm_content(=csecuuid)按 profile 替换。"""
    if profile.get("csecuuid") or profile.get("uuid"):
        val = profile.get("csecuuid") or profile.get("uuid")
        fp = re.sub(r'((?:uuid|utm_content)=)[^&]*', lambda mo: mo.group(1) + val, fp)
    if profile.get("req_trace_id"):
        fp = re.sub(r'(__reqTraceID=)[^&]*', lambda mo: mo.group(1) + str(profile["req_trace_id"]), fp)
    overrides = profile.get("query_overrides", {})
    if overrides and "?" in fp:
        if not isinstance(overrides, dict):
            raise ValueError("query_overrides must be an object")
        path, query = fp.split("?", 1)
        pairs = []
        for pair in query.split("&"):
            key, equals, value = pair.partition("=")
            name = urllib.parse.unquote(key)
            if name in overrides:
                if overrides[name] is None:
                    continue
                value = urllib.parse.quote(str(overrides[name]), safe="")
                equals = "="
            pairs.append(key + equals + value)
        fp = path + "?" + "&".join(pairs)
    return fp


def _sub_headers(headers, profile):
    """Apply device identity replacements to captured request headers.

    Captures carry the same ``csecuuid`` in a dedicated header and embedded in
    ``M-SHARK-TRACEID``.  Replacing only URL/body fields would therefore build
    a syntactically valid request with a mixed old/new device identity.  Keep
    unknown headers untouched, while allowing an explicit
    ``header_overrides`` mapping for deployment-specific headers.
    """
    out = dict(headers or {})
    # Replace the exact captured csecuuid wherever it occurs (trace IDs embed
    # it as a contiguous substring).  Do this before explicit overrides so a
    # caller can still deliberately choose a different trace header.
    new_csecuuid = profile.get("csecuuid")
    if new_csecuuid:
        old_csecuuid = next((v for k, v in out.items()
                             if k.lower() == "csecuuid" and isinstance(v, str)), None)
        if old_csecuuid:
            for k, v in list(out.items()):
                if isinstance(v, str) and old_csecuuid in v:
                    out[k] = v.replace(old_csecuuid, str(new_csecuuid))

    # Header names are case-insensitive; retain the captured spelling where it
    # exists instead of creating duplicate keys with different case.
    direct = {
        "csecuuid": "csecuuid", "uuid": "uuid", "incog-token": "incog-token",
        "token": "token", "userid": "userid", "csecuserid": "csecuserid",
        "unionid": "pragma-unionid", "localid": "localid", "sessionid": "sessionid",
    }
    for pk, hk in direct.items():
        value = profile.get(pk)
        if value is None:
            continue
        existing = next((k for k in out if k.lower() == hk.lower()), hk)
        out[existing] = str(value)

    for name, value in (profile.get("header_overrides") or {}).items():
        existing = next((k for k in out if k.lower() == str(name).lower()), str(name))
        if value is None:
            out.pop(existing, None)
        else:
            out[existing] = str(value)
    return out


def _sub_scfg(body, profile):
    """Use this request's encrypted config body, never the capture's data."""
    request = profile.get("scfg_request")
    if not isinstance(request, dict) or set(request) != {"data", "os", "mtg_version"}:
        raise ValueError("missing current-session scfg_request")
    return json.dumps(request, ensure_ascii=False, separators=(",", ":"))


SUBS = {"scfg": _sub_scfg, "plaintext_urlencoded": _sub_urlencoded,
        "plaintext_json": _sub_json,
        "envelope": _sub_envelope,
        "envelope_sign": lambda b, p: _sub_envelope(b, p, "envelope_sign_data"),
        "envelope_device": lambda b, p: _sub_envelope(b, p, "envelope_device_data"),
        "envelope_info": lambda b, p: _sub_envelope(b, p, "envelope_info_data"),
        "envelope_bio": lambda b, p: _sub_envelope(b, p, "envelope_bio_data"),
        "envelope_ntp": _sub_ntp_envelope}


def _find_flow(idx, host, path):
    """Return ``(actual_host, flow)`` using known capture host aliases."""
    flow = idx.get((host, path))
    if flow:
        return host, flow
    for candidate in HOST_ALIASES.get(path, ()):
        flow = idx.get((candidate, path))
        if flow:
            return candidate, flow
    return None, None


def _sign_value(signer, url, body):
    """Call either the offline or device signer API and return a mtgsig string.

    The repository has two deliberately different signer interfaces:
    ``OfflineSigner.sign(url, body)`` returns ``(mtgsig, a2)`` while the
    Frida-backed signer accepts ``(method, url, body)`` and returns a string.
    Keeping this normalization here lets the request planner be used for both
    a fully offline run and a live device-backed audit.
    """
    try:
        result = signer.sign(url, body)
    except TypeError:
        result = signer.sign("POST", url, body)
    if isinstance(result, tuple):
        result = result[0]
    if not isinstance(result, str) or not result:
        raise ValueError("signer returned an empty/non-text mtgsig")
    return result


def build_request(idx, host, path, body_type, profile, signer=None, overrides=None,
                  template=None):
    """返回 dict: {method,url,headers,body,signed}。signer=None 则不算 mtgsig(纯模板)。"""
    actual_host, flow = (capture_authority(template), template) if template is not None else _find_flow(idx, host, path)
    if not flow:
        return {"error": f"chlsj 无 {host}{path}"}
    # Runtime state (ticket, serial, captcha codes) is applied to a copy so a
    # plan can safely generate repeated requests for different accounts.
    effective = dict(profile or {})
    effective.update(overrides or {})
    if path in registration_region.REGION_PATHS and effective.get("_region_flow"):
        effective["req_trace_id"] = registration_region.new_request_trace()
    fp, headers, body = extract_template(flow)
    headers = _sub_headers(headers, effective)
    fp = _sub_query(fp, effective)
    try:
        actual_host, fp, headers = registration_region.apply_selected_region_route(
            actual_host, fp, headers, effective)
        if path in registration_region.REGION_PATHS and effective.get("_region_flow"):
            actual_host, headers, body = registration_region.prepare_region_request(
                path, body, headers, actual_host, effective)
        else:
            body = SUBS[body_type](body, effective)
    except (TypeError, ValueError) as exc:
        return {"error": str(exc), "url": f"https://{actual_host}{fp}", "signed": False}
    if any(name.lower() == "host" for name in headers):
        headers = {name: value for name, value in headers.items() if name.lower() != "host"}
        headers["Host"] = actual_host
    url = f"https://{actual_host}{fp}"
    # Endpoint-specific values (formatted envelope time, bio index/region,
    # etc.) come from explicit current-session input, not timestamp guesses.
    body_fields = effective.get("request_body_fields", {}).get(path, {})
    if body_fields:
        if path in registration_region.REGION_PATHS and effective.get("_region_flow"):
            return {"error": "region body fields must use region_inputs", "url": url, "signed": False}
        if body_type == "scfg":
            return {"error": "scfg body fields must use scfg_inputs", "url": url, "signed": False}
        if body_type == "envelope_ntp":
            return {"error": "NTP outer body contains only its envelope data", "url": url, "signed": False}
        if not isinstance(body_fields, dict):
            return {"error": "request_body_fields entries must be objects", "url": url, "signed": False}
        if body_type == "plaintext_urlencoded":
            pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
            seen = {key for key, _ in pairs}
            pairs = [(key, body_fields.get(key, value)) for key, value in pairs]
            pairs.extend((key, value) for key, value in body_fields.items() if key not in seen)
            body = urllib.parse.urlencode(pairs)
        else:
            obj = json.loads(body)
            if not isinstance(obj, dict):
                return {"error": "request body must be an object", "url": url, "signed": False}
            if any(key in body_fields for key in ("data", "fingerPrintData", "fingerprint")):
                return {"error": "encrypted body fields must use their payload configuration", "url": url, "signed": False}
            obj.update(body_fields)
            body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if path == "/sdkapi/newreg":
        try:
            body = _sub_newreg(body, effective, headers)
        except (TypeError, ValueError) as e:
            return {"error": str(e), "url": url, "signed": False}
    if path == "/uuid/oversea/ios/register":
        from mtgsig.oneid import build_oneid_body, oneid_header_updates
        try:
            body = json.dumps(build_oneid_body(body, effective), ensure_ascii=False,
                              separators=(",", ":"))
            for name, value in oneid_header_updates(body, effective).items():
                existing = next((k for k in headers if k.lower() == name.lower()), name)
                headers[existing] = value
        except (TypeError, ValueError) as e:
            return {"error": str(e), "url": url, "signed": False}
    if path == login_protocol.RISK_PATH:
        try:
            captured = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
            common = {key: effective.get(key, captured.get(key))
                      for key in ("device_id", "tk_context_plain", "fingerprint")}
            common["fingerprint"] = profile_fingerprint(effective) or captured.get("fingerprint")
            body = login_protocol.build_risk_body(
                effective.get("email"),
                request_code=effective.get("request_code", effective.get("requestCode")),
                response_code=effective.get("response_code", effective.get("responseCode")),
                token_id=effective.get("token_id", captured.get("token_id", "")), common=common)
            headers = login_protocol.passport_headers(headers)
        except (TypeError, ValueError) as e:
            return {"error": str(e), "url": url, "signed": False}
    elif path in (login_protocol.LOGIN_APPLY_PATH, login_protocol.SIGNUP_APPLY_PATH):
        try:
            common = {key: effective.get(key) for key in ("device_id", "tk_context_plain")}
            common["fingerprint"] = profile_fingerprint(effective)
            options = {"signup": path == login_protocol.SIGNUP_APPLY_PATH, "common": common}
            if options["signup"]:
                for key in ("username", "password", "encrypted_password"):
                    if key in effective:
                        options[key] = effective[key]
                # The observed passwordless signup sends explicit empty
                # strings. Keep the low-level model's None/absent distinction.
                options.setdefault("username", "")
                if "password" not in options and "encrypted_password" not in options:
                    options["encrypted_password"] = ""
            body = login_protocol.build_apply_body(effective.get("user_ticket"), **options)
            headers = login_protocol.passport_headers(headers)
        except (TypeError, ValueError) as e:
            return {"error": str(e), "url": url, "signed": False}
    elif path in (login_protocol.LOGIN_PATH, login_protocol.SIGNUP_PATH):
        try:
            common = {key: effective.get(key) for key in ("device_id", "tk_context_plain")}
            common["fingerprint"] = profile_fingerprint(effective)
            options = {"signup": path == login_protocol.SIGNUP_PATH, "common": common}
            if options["signup"]:
                for key in ("username", "password", "encrypted_password"):
                    if key in effective:
                        options[key] = effective[key]
                options.setdefault("username", "")
                if "password" not in options and "encrypted_password" not in options:
                    options["encrypted_password"] = ""
            body = login_protocol.build_submit_body(
                effective.get("user_ticket"), effective.get("email_code"),
                effective.get("serial_number"),
                request_code=effective.get("request_code", effective.get("requestCode")),
                response_code=effective.get("response_code", effective.get("responseCode")),
                **options)
            headers = login_protocol.passport_headers(headers)
        except (TypeError, ValueError) as e:
            return {"error": str(e), "url": url, "signed": False}
    # Explicit Incognia configuration owns this header after final routing.
    # Captured tokens were removed in extract_template; without the new
    # configuration, legacy explicitly supplied current tokens still work.
    try:
        state_store = (getattr(signer, "dev", False)
                       if signer is not None and path not in UNSIGNED_PATHS else None)
        headers = incognia_state.refresh_request_headers(
            headers, effective, storage=state_store, timestamp_ms=effective.get("timestamp_ms"))
    except (TypeError, ValueError, KeyError) as exc:
        return {"error": str(exc), "url": url, "signed": False}
    signed = False
    if signer is not None and path not in UNSIGNED_PATHS:
        try:
            headers["mtgsig"] = _sign_value(signer, url, body)
            signed = True
        except Exception as e:
            # A placeholder is dangerous: callers may accidentally send it as
            # a real signature.  Preserve the error for dry-run auditing and
            # leave the header absent so ``--send`` cannot silently issue an
            # invalid request.
            headers.pop("mtgsig", None)
            return {"method": "POST", "url": url, "headers": headers,
                    "body": body, "body_type": body_type, "signed": False,
                    "sign_error": f"{type(e).__name__}: {e}"}
    headers["Content-Length"] = str(len(body.encode("utf-8")))
    return {"method": "POST", "url": url, "headers": headers, "body": body,
            "body_type": body_type, "signed": signed}


def build_offline_plan(idx, profile, signer=None, steps=None, only=None, overrides=None,
                       clock=time.time):
    """Build the deterministic device-registration request plan.

    The result is a list of request dictionaries and never performs I/O beyond
    reading the supplied capture index. Missing endpoint templates are reported
    as entries with ``error`` so callers can audit coverage without silently
    dropping a state transition.
    """
    plan = []
    effective = dict(profile or {}, **(overrides or {}))
    steps = list(steps if steps is not None else FLOW_STEPS)
    if any(s["path"] == "/uuid/oversea/ios/register" for s in steps):
        from mtgsig.oneid import initialize_oneid_session
        effective = initialize_oneid_session(effective, format(clock(), ".16g"))
    identity = getattr(signer, "dev", getattr(signer, "mt", {})) if signer else {}
    for key in ("a1", "a7", "a8", "a7_local_xid", "a8_local_dfp", "outid_history_dfp",
                "ntp_fingerprint_data", "ntp_response_source"):
        if key in identity:
            effective[key] = getattr(signer, key, identity[key])
    for key in registration_region.STATE_FIELDS + ("m_shark_session_marker",):
        if key in identity:
            effective.setdefault(key, identity[key])
    if any(step["path"] in registration_region.REGION_PATHS for step in steps):
        ensure_m_shark_session_marker(effective)
    envelope_key = None
    if effective.get("envelope_payloads"):
        configured = effective.get("envelope_session_key_hex")
        envelope_key = bytes.fromhex(configured) if configured else secrets.token_bytes(16)
        if len(envelope_key) != 16:
            raise ValueError("envelope_session_key_hex must represent 16 bytes")
    for step in steps:
        if only and only not in (step["name"], step["path"]):
            continue
        try:
            request_profile = prepare_request_profile(step, effective,
                timestamp_ms=int(clock()*1000), a1=effective.get("a1"), session_key=envelope_key)
            if step["path"] in registration_region.REGION_PATHS:
                request_profile["_region_flow"] = True
            req = build_request(idx, step["host"], step["path"], step["body_type"],
                                 request_profile, signer=signer, template=step.get("template"))
        except (TypeError, ValueError, KeyError) as exc:
            req = {"error": f"payload construction failed: {exc}", "signed": False}
        req["name"] = step["name"]
        req["requested_host"] = step["host"]
        req["path"] = step["path"]
        plan.append(req)
    return plan


def execute_offline_flow(idx, profile, signer, send, *, steps=None, only=None,
                         clock=time.time, payload_builder=None):
    """Build, send, validate and apply one response before signing the next.

    ``send(request)`` returns ``(HTTP status, decoded JSON)``.  Supplying the
    transport explicitly permits real execution and deterministic capture
    replay through the same state transitions.  Error responses stop the flow.
    Missing A-envelope inputs stop before any request is sent for that step.
    """
    if signer is None or not callable(getattr(signer, "apply_registration_response", None)):
        raise ValueError("a signer with registration response support is required")
    effective = dict(profile)
    steps = list(steps if steps is not None else FLOW_STEPS)
    if any(s["path"] == "/uuid/oversea/ios/register" for s in steps):
        from mtgsig.oneid import initialize_oneid_session
        effective = initialize_oneid_session(effective, format(clock(), ".16g"))
    identity = getattr(signer, "dev", getattr(signer, "mt", {}))
    effective.update({key: value for key, value in identity.items()
                      if key in ("a1", "a7_local_xid", "a8_local_dfp", "outid_history_dfp",
                                 "ntp_fingerprint_data", "ntp_response_source")})
    for key in ("scfg_config", "scfg_applist_open", "scfg_private_collect_fields", "m_shark_session_marker") + registration_region.STATE_FIELDS:
        if key in identity:
            effective.setdefault(key, identity[key])
    if any(step["path"] in registration_region.REGION_PATHS for step in steps):
        marker = ensure_m_shark_session_marker(effective)
        if isinstance(getattr(signer, "dev", None), dict):
            signer.dev["m_shark_session_marker"] = marker
    effective.update(a7=getattr(signer, "a7", identity.get("a7")),
                     a8=getattr(signer, "a8", identity.get("a8")))
    envelope_key = None
    if effective.get("envelope_payloads"):
        configured = effective.get("envelope_session_key_hex")
        envelope_key = bytes.fromhex(configured) if configured else secrets.token_bytes(16)
        if len(envelope_key) != 16:
            raise ValueError("envelope_session_key_hex must represent 16 bytes")
    for step in steps:
        if only and only not in (step["name"], step["path"]):
            continue
        request_seconds = clock()
        timestamp_ms = int(request_seconds * 1000)
        try:
            if step["name"] in ("user_risk_check", "confirm_protocol"):
                source = step.get("template") or _find_flow(idx, step["host"], step["path"])[1]
                captured_body = extract_template(source)[2] if source else ""
                fields = (json.loads(captured_body) if captured_body.lstrip().startswith("{") else
                          dict(urllib.parse.parse_qsl(captured_body, keep_blank_values=True)))
                if (step["name"] == "user_risk_check" or "email" in fields) and not effective.get("email"):
                    raise ValueError("current-session email is required")
            if (step["path"] in registration_region.REGION_PATHS and
                    "region_events" not in effective and not effective.get("region_state") and
                    isinstance(effective.get("region_inputs"), dict)):
                initial = effective["region_inputs"].get("initial_region")
                history = registration_region.region_event_patch(initial, event_seconds=request_seconds,
                    state=effective, identity=getattr(signer, "dev", {}), initialize=True)
                effective.update(history)
                if isinstance(getattr(signer, "dev", None), dict):
                    signer.dev.update(history)
            request_profile = prepare_request_profile(step, effective, timestamp_ms=timestamp_ms,
                a1=effective.get("a1"), session_key=envelope_key)
            if payload_builder is not None:
                request_profile = payload_builder(step, request_profile, timestamp_ms)
                if not isinstance(request_profile, dict):
                    raise ValueError("payload builder must return a profile object")
            if step["path"] in registration_region.REGION_PATHS:
                request_profile["_region_flow"] = True
        except (TypeError, ValueError, KeyError) as exc:
            yield {"name": step["name"], "error": f"payload construction failed: {exc}", "sent": False}
            return
        if step["path"] == "/sdkapi/newreg" and "random" not in request_profile:
            request_profile["random"] = str(int(clock()))
        bt = step["body_type"]
        if bt.startswith("envelope"):
            slot = ENVELOPE_SLOTS.get(bt, "envelope_data")
            fallback = bt != "envelope_ntp" and request_profile.get("envelope_data")
            if not request_profile.get(slot) and not fallback:
                yield {"name": step["name"], "error": f"missing current-session {slot}", "sent": False}
                return
        req = build_request(idx, step["host"], step["path"], bt, request_profile,
                            signer=signer, template=step.get("template"))
        req.update(name=step["name"], path=step["path"])
        if req.get("error") or req.get("sign_error") or (step["path"] not in UNSIGNED_PATHS and not req["signed"]):
            yield {"name": step["name"], "request": req, "error": "request construction failed", "sent": False}
            return
        if step["path"] not in UNSIGNED_PATHS:
            try:
                mt = json.loads(req["headers"]["mtgsig"])
                if not isinstance(mt, dict) or any(k not in mt for k in
                    ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "x0")):
                    raise ValueError("incomplete mtgsig")
                if not isinstance(mt["a2"], str) or not re.fullmatch(r"[0-9a-f]{32}", mt["a2"]):
                    raise ValueError("invalid a2")
            except (TypeError, ValueError):
                yield {"name": step["name"], "error": "invalid mtgsig structure", "sent": False}
                return
        try:
            status, response = send(req)
        except Exception as exc:
            yield {"name": step["name"], "error": f"transport failed: {type(exc).__name__}", "sent": True}
            return
        event = {"name": step["name"], "request": req, "http_status": status,
                 "response": response, "sent": True, "updated_fields": []}
        good = (type(status) is int and 200 <= status < 300 and isinstance(response, dict)
                and not response.get("error") and response.get("success", True) is True
                and ("code" not in response or (type(response["code"]) is int and response["code"] == 0)
                     or (type(response["code"]) is str and response["code"] == "0")))
        if step["path"] in ("/v5/sign", "/fingerprint/v1/info/report", "/ntp"):
            patch = parse_registration_response(step["path"], response, http_status=status)
            good = good and bool(patch)
            if good:
                changed = signer.apply_registration_response(step["path"], response, http_status=status)
                effective.update(patch)
                event["updated_fields"] = sorted(changed)
                if step["path"] == "/ntp":
                    event["ntp_state"] = {key: patch[key] for key in
                        ("ntp_fingerprint_data", "ntp_response_source")}
        elif step["path"] == "/sdkapi/newreg":
            patch = parse_newreg_response(response, http_status=status)
            good = good and bool(patch)
            if good:
                effective.update(patch)
                if isinstance(getattr(signer, "dev", None), dict):
                    signer.dev.update(patch)
                event["updated_fields"] = sorted(patch)
        elif step["path"] == "/uuid/oversea/ios/register":
            from mtgsig.oneid import parse_oneid_response
            patch = parse_oneid_response(req["body"], response, http_status=status)
            good = good and bool(patch)
            if good:
                effective.update(patch)
                if isinstance(getattr(signer, "dev", None), dict):
                    signer.dev.update(patch)
                event["updated_fields"] = sorted(patch)
        elif step["path"] == "/v1/scfg":
            from mtgsig.scfg import parse_scfg_response
            patch = parse_scfg_response(response, http_status=status,
                previous_private_fields=effective.get("scfg_private_collect_fields", ()))
            good = good and bool(patch)
            if good:
                effective.update(patch)
                if isinstance(getattr(signer, "dev", None), dict):
                    signer.dev.update(patch)
                event["updated_fields"] = sorted(patch)
                event["scfg_state"] = patch
        elif step["path"] in registration_region.REGION_PATHS:
            try:
                patch = registration_region.consume_region_response(step["path"], response,
                    http_status=status, state=effective)
                if step["path"] == registration_region.CURRENT_LOCAL_INFO_PATH:
                    applied_seconds = clock()
                    patch.update(registration_region.region_event_patch(patch["region"],
                        event_seconds=applied_seconds, state=effective, identity=getattr(signer, "dev", {})))
            except (TypeError, ValueError, KeyError) as exc:
                good = False
                event["region_error"] = str(exc)
            else:
                good = good and bool(patch)
                if good:
                    effective.update(patch)
                    if isinstance(getattr(signer, "dev", None), dict):
                        signer.dev.update(patch)
                    event["updated_fields"] = sorted(patch)
                    event["region_update"] = patch
        elif step["path"] == login_protocol.RISK_PATH:
            patch = login_protocol.parse_risk_response(response, http_status=status)
            good = good and bool(patch)
            if good:
                effective.update(patch)
                event["updated_fields"] = sorted(patch)
                # Keep the current ticket available to an explicit apply
                # continuation; it is never inferred from a captured response.
                event["login_state"] = patch
        elif step["path"] in (login_protocol.LOGIN_APPLY_PATH, login_protocol.SIGNUP_APPLY_PATH):
            patch = login_protocol.parse_apply_response(response, http_status=status,
                expected_email=effective.get("email"))
            good = (good and bool(patch) and isinstance(effective.get("email"), str)
                    and bool(effective["email"].strip()))
            if good:
                effective.update(patch)
                event["updated_fields"] = sorted(patch)
                event["login_state"] = patch
        elif step["path"] in (login_protocol.LOGIN_PATH, login_protocol.SIGNUP_PATH):
            patch = login_protocol.parse_submit_response(response, http_status=status,
                expected_email=effective.get("email"))
            good = (good and bool(patch) and isinstance(effective.get("email"), str)
                    and bool(effective["email"].strip()))
            if good:
                # Account credentials are separate from the device identity
                # and must never be persisted in signer.dev/profile state.
                event["account_state"] = patch
        if not good:
            event["error"] = "response did not confirm success"
        yield event
        if not good:
            return


def demo():
    """无网络自检:模板加载 + 替换正确性。"""
    # 用内联假模板,不依赖真 chlsj(CI 友好)。
    fake = {"host": "passport-hk.mykeeta.com", "path": "/api/emaillogin/v1/userriskcheck?appId=517&uuid=OLDUUID",
            "request": {"header": {"headers": [
                {"name": ":path", "value": "/api/emaillogin/v1/userriskcheck?appId=517&uuid=OLDUUID"},
                {"name": "mtgsig", "value": "OLD"}, {"name": "csecuuid", "value": "OLDUUID"}]},
                "body": {"text": "email=old%40x.com&fingerprint=OLDFP&token_id=T"}}}
    idx = {("passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck"): fake}
    prof = {"email": "new@y.com", "fingerprint": "NEWFP", "csecuuid": "NEWUUID"}
    r = build_request(idx, "passport-hk.mykeeta.com", "/api/emaillogin/v1/userriskcheck",
                      "plaintext_urlencoded", prof)
    q = urllib.parse.parse_qs(r["body"])
    assert q["email"][0] == "new@y.com", q
    assert q["fingerprint"][0] == "NEWFP", q
    assert q["token_id"][0] == "T", q            # 未给的字段沿用原值
    assert "uuid=NEWUUID" in r["url"], r["url"]  # query 里 uuid 被替换
    assert "mtgsig" not in r["headers"]          # signer=None 不签
    print("demo OK: 明文体按 profile 精确替换,未给字段保留,query uuid 替换")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", help="设备画像 JSON")
    ap.add_argument("--sample", default="/tmp/keeta_K.json", help="离线签名器样本(mtgsig 来源)")
    ap.add_argument("--identity", help="FullSigner 身份 JSON；发送时持久化计数器和 xid/dfp")
    ap.add_argument("--capture", default=CHLSJ, help="Charles JSON 抓包路径")
    ap.add_argument("--order", choices=("capture", "logical"), default="capture",
                    help="默认保留抓包顺序及重复上报；logical 使用最小步骤列表")
    ap.add_argument("--only", help="只生成某接口(path 关键词)")
    ap.add_argument("--send", action="store_true", help="执行请求并按响应推进；缺输入/响应失败即停止")
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()
    if a.demo:
        return demo()
    if not a.profile:
        sys.exit("需 --profile(或 --demo)")
    profile = json.load(open(a.profile, encoding="utf-8"))
    idx = load_chlsj_index(a.capture)
    steps = load_capture_steps(a.capture) if a.order == "capture" else FLOW_STEPS
    if a.only:
        steps = [s for s in steps if a.only in (s["name"], s["path"])]
    if not steps:
        sys.exit("没有匹配的请求步骤")
    # FullSigner refreshes a4/a5/a10 and derives a2 per request. The older
    # OfflineSigner intentionally keeps captured timestamps and is not used
    # for a new registration session.
    from contextlib import ExitStack
    import tempfile
    from farm.fullsign import FullSigner, provision_identity
    with ExitStack() as stack:
        signer = None
        if a.identity:
            signer = FullSigner(a.identity)
        elif os.path.exists(a.sample):
            tempdir = stack.enter_context(tempfile.TemporaryDirectory())
            identity = os.path.join(tempdir, "identity.json")
            provision_identity(a.sample, identity)
            signer = FullSigner(identity)
        if not a.send:
            for r in build_offline_plan(idx, profile, signer=signer, steps=steps):
                print(json.dumps({k: r[k] for k in ("name", "path", "signed", "error", "sign_error")
                                  if k in r}, ensure_ascii=False))
            return
        if signer is None:
            sys.exit("发送需要 --identity 或有效 --sample")
        import requests
        session = stack.enter_context(requests.Session())
        def send(req):
            response = session.request(req["method"], req["url"], headers=req["headers"],
                                       data=req["body"].encode("utf-8"), timeout=20,
                                       allow_redirects=False)
            try:
                body = response.json()
            except ValueError:
                body = None
            return response.status_code, body
        try:
            for event in execute_offline_flow(idx, profile, signer, send, steps=steps):
                # Do not print identity values, cookies, email or request bodies.
                print(json.dumps({k: event[k] for k in ("name", "sent", "http_status", "updated_fields", "error")
                                  if k in event}, ensure_ascii=False))
                if event.get("error"):
                    sys.exit(1)
        finally:
            if a.identity:
                signer.persist_counter()


if __name__ == "__main__":
    main()

"""Keeta 离线加解密 RPC 服务 —— 项目里所有"能离线跑"的密码能力的统一入口。

起服务(项目根):
    python keeta_rpc.py                 # 监听 127.0.0.1:8799
    python keeta_rpc.py --port 9000 --host 0.0.0.0
    python keeta_rpc.py --selftest      # 不起服务, 用 /tmp/keeta_K.json 自检

调用(全部 POST JSON, 除 GET /):
    GET  /                    能力清单 + a9 配置状态 + 示例
    POST /a5/decrypt          {a5, a1, a3, a4}                 -> {plain_json, plain_explained?}
    POST /a5/encrypt          {plain_json|plain_b64|plain_obj, a1, a3, a4} -> {a5}
    POST /a2                  {method,url,body?,payload_json,a1,counter}   -> {a2}
    POST /k2buf               {a1}                             -> {k2buf_hex}
    POST /sign                {identity_path|identity, method, url, body?} -> {mtgsig}
    POST /a9/decode           {a9, a1, profile?, mode?} -> {plain_json, plain_explained, mode, profile}
    POST /a9/encode           {siua_json, a1, mode, profile?} -> {a9, mode, profile}
                              (profile: default / legacy; 可覆盖 salt_hex/k3_hex/a1_shift)
    POST /fingerprint/decrypt {fingerprint, key?, iv?}  -> {key_used, plain_json?}
                              (登录指纹/设备指纹; 不传 key 自动试 k0 密钥表; 别名 /fp/decrypt)
    POST /fingerprint/encrypt {plain_json|plain_obj, key?, iv?} -> {fingerprint}
                              (I-series 登录指纹; 默认固定 key/IV; 别名 /fp/encrypt)
    POST /envelope/encode   {session_material, plaintext/plain_json, key, iv?}
                              -> {envelope, part1_bytes, part2_bytes}
    POST /envelope/decode   {envelope, key, iv?}               -> {plain_json?, part1_bytes, part2_bytes}
                              (不带 a1：兼容显式 AES key/IV 接口)
    POST /envelope/encode   {a1, plaintext/plain_json, session_key_hex?, mode?, profile?}
                              -> {envelope, mode, profile, session_key_hex?（仅新生成时返回）}
    POST /envelope/decode   {a1, envelope, session_key_hex/session_material_hex, mode?, profile?}
                              -> {plain_json, mode, profile, rsa_verified}
                              (带 a1：SDK 三模式；无会话 key/material 不能解任意 RSA 信封)

字段能力一览:
    a5  ✅ 加/解密(RC4变体+zlib, 全局salt派生, 换设备通用)
    a2  ✅ 生成(HMAC-SHA1+表变换, 单向)
    sign✅ 完整 mtgsig 离线现算(a0-a6,a10,x0 现算 + a7/a8/a9 用身份档)
    k2buf ✅ 派生
    a9  ✅ 加/解密(AES / Twofish / 修改 MDS 的 Twofish; 需原始 a1 和匹配配置, 无需 dump 表)
    fingerprint ✅ 加/解密(标准 AES-128-CBC, 内嵌固定 key: corpse=meituan1sankuai0 / I17=34281a9dw2i701d4)
"""
import argparse
import base64
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "mtgsig"))
from farm import fullsign as FS  # noqa: E402  (带出 k2buf/compute_a2/FullSigner/a9, 并配好 sys.path)
import mtg_crypto as MC          # noqa: E402
from mtgsig import a9_codec as A9  # noqa: E402
from mtgsig import envelope_codec as ENV  # noqa: E402

_SIGNERS = {}                    # identity_path -> FullSigner(计数器单调持久化)
_LOCK = threading.Lock()


_A5_TOP_NAMES = {
    "b1": "设备指纹主体",
    "b2": "签名序号",
    "b3": "a5 采集序号",
    "b4": "应用包名(bundleId)",
    "b5": "应用版本字符串",
    "b6": "应用版本号",
    "b7": "SDK 启动时间戳(秒)",
    "b8": "缓存采集时间戳(秒)",
    "b9": "缓存采集时间戳(秒)",
    "b10": "SIUA/SAKGuard SDK 版本",
    "b11": "SDK 版本",
    "b12": "端/平台标志",
    "b13": "采集计数",
    "b14": "预留字段",
    "b15": "预留字段",
    "b16": "三类SDK上报的调用次数、调用及HTTP200回调相对时点",
    "b17": "POST签名前置计数（出站低32位）",
    "b18": "SDK userID为nil时的前置计数（出站低32位）",
    "b19": "预留字段",
    "b20": "采集计数",
    "b21": "时间戳(秒)",
    "b22": "区域事件历史(距 SDK 启动的累计毫秒)",
    "b23": "设备标识串(短)",
    "b24": "设备标识串(长)",
    "b25": "标志位",
}

_A5_B1_NAMES = {
    **{str(i): f"设备属性槽 {i}" for i in range(0, 15)},
    "33": "环境/风控检测子对象",
    "44": "预留槽",
    "55": "数值设备指纹",
    "56": "标志",
    "57": "SDK 固定值",
    "58": "采集时间戳(毫秒)",
    "100": "子模块版本",
}

_A5_B133_NAMES = {
    "0": "检测 schema 版本/项数",
    **{str(i): "环境检测结果槽" for i in range(1, 17)},
}

_A9_BASE_NAMES = [
    "标志",
    "网络类型",
    "浮点占位",
    "常量数组",
    "系统名",
    "厂商",
    "运营商名",
    "系统版本",
    "主板型号",
    "语言",
    "设备类(小写)",
    "设备类",
    "时区",
    "屏幕分辨率",
    "内核大版本",
    "占位",
]

_A9_EXTENDED_NAMES = [
    "标志",
    "系统启动绝对时间(毫秒)",
    "磁盘总量",
    "环境检测对象",
    "电池电量",
    "亮度/电池状态",
    "应用包名(bundleId)",
    "应用版本",
    "可用磁盘",
    "当前墙钟(毫秒)",
    "设备指纹 hash/csecuuid",
    "物理内存(hw.memsize)",
    "空数组",
    "标志",
    "标志",
    "标志",
    "会话 nonce",
    "占位",
    "设备型号",
    "占位",
    "渠道",
    "内核 boottime",
    "进程启动时间戳",
]

# I-series 登录 fingerprint 中已经由项目证据确认的字段。其余键仍会
# 返回可读的通用标签，避免把尚未确认的语义当成事实。
_FP_NAMES = {
    "I1": "设备类别(utm_medium)",
    "I2": "推送标识(dtk_token)",
    "I3": "越狱检测",
    "I4": "网络类型",
    "I5": "应用检测结果",
    "I6": "运营商名称",
    "I7": "电池电量百分比",
    "I8": "设备型号",
    "I9": "电池状态",
    "I10": "系统版本",
    "I11": "运营商信息",
    "I12": "屏幕像素尺寸",
    "I13": "系统音量观测",
    "I14": "内核启动时间(秒)",
    "I15": "Wi-Fi 信息(wifimac)",
    "I16": "陀螺仪采样",
    "I17": "定位信息",
    "I18": "IDFA(广告标识)",
    "I19": "JPM SDK 首次启动时间(毫秒)",
    "I20": "IDFV(供应商标识)",
    "I21": "定位授权状态",
    "I22": "SIM 状态",
    "I23": "可用/总存储空间(MiB)",
    "I24": "设备类型名称",
    "I25": "网络接口 IP(IPv4/IPv6)",
    "I26": "安装来源",
    "I27": "业务配置",
    "I28": "指纹生成器 dpid 配置",
    "I29": "应用版本",
    "I30": "指纹格式版本",
    "I31": "SDK 固定标识(magic)",
    "I32": "渠道",
    "I33": "已加载动态库",
    "I34": "CoreServices 创建时间",
    "I35": "CoreServices 修改时间",
    "I36": "系统偏好中的设备名称",
    "I37": "应用安装时间(毫秒)",
    "I38": "设备品牌",
    "I39": "当前墙钟时间(毫秒)",
    "I40": "OneID csecuuid",
    "I41": "应用驻留内存/总物理内存(MiB)",
    "I42": "屏幕亮度",
    "I43": "CPU 核心数",
    "I44": "应用非空闲线程 CPU 占用总和(%)",
    "I45": "CPU 架构",
}


def _parse_json_string(value):
    """Parse a nested JSON string while retaining its original representation."""
    if not isinstance(value, str):
        return value, None
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return value, None
    return parsed, value


def _explained_field(key, name, value, *, child_names=None):
    parsed, raw = _parse_json_string(value)
    item = {"key": str(key), "name": name, "value": parsed}
    if raw is not None:
        item["raw"] = raw
    if isinstance(parsed, dict):
        item["fields"] = _explained_fields(parsed, child_names or {})
    return item


def _explained_fields(obj, names=None):
    names = names or {}
    return [_explained_field(k, names.get(str(k), "未知字段"), v)
            for k, v in obj.items()]


def _explain_a5(value):
    if not isinstance(value, dict):
        return {"fields": []}
    fields = []
    for key, raw_value in value.items():
        key_s = str(key)
        item = _explained_field(key_s, _A5_TOP_NAMES.get(key_s, "未知字段"), raw_value)
        if key_s == "b1":
            parsed, raw = _parse_json_string(raw_value)
            if isinstance(parsed, dict):
                item["fields"] = _explained_fields(parsed, _A5_B1_NAMES)
                # b1.33 is itself commonly serialized as JSON text.
                for child in item["fields"]:
                    if child["key"] == "33":
                        nested = child["value"]
                        if isinstance(nested, dict):
                            child["fields"] = _explained_fields(
                                nested, _A5_B133_NAMES)
        fields.append(item)
    return {"fields": fields}


def _explain_a9(value):
    if not isinstance(value, dict):
        return {"fields": []}
    fields = []
    for key, raw_value in value.items():
        key_s = str(key)
        name = {
            "0": "schema 版本/项数",
            "1": "基础设备字段(16项)",
            "2": "扩展设备字段(23项)",
            "3": "采集来源/耗时码映射",
        }.get(key_s, "未知字段")
        item = _explained_field(key_s, name, raw_value)
        parsed, raw = _parse_json_string(raw_value)
        if key_s in ("1", "2") and isinstance(parsed, list):
            labels = _A9_BASE_NAMES if key_s == "1" else _A9_EXTENDED_NAMES
            items = []
            for index, value in enumerate(parsed):
                item_value, item_raw = _parse_json_string(value)
                child = {
                    "index": index,
                    "name": labels[index] if index < len(labels) else "未知字段",
                    "value": item_value,
                }
                if item_raw is not None:
                    child["raw"] = item_raw
                if isinstance(item_value, dict):
                    child["fields"] = _explained_fields(item_value)
                items.append(child)
            item["items"] = items
        fields.append(item)
    return {"fields": fields}


def _explain_fingerprint(value):
    """Give I-series fields stable labels without guessing unknown meanings."""
    if not isinstance(value, dict):
        return {"fields": []}
    fields = []
    for key, raw_value in value.items():
        key_s = str(key)
        item = _explained_field(key_s, _FP_NAMES.get(key_s, f"I 系列字段 {key_s}"), raw_value)
        fields.append(item)
    return {"fields": fields}


def _plain_out(b: bytes, kind=None) -> dict:
    """Return compact JSON-first output for decrypted payloads.

    The old base64/text pair made normal JSON responses unnecessarily large.
    Keep the parsed value as ``plain_json`` and add a human-readable field map
    for the known a5/a9 schemas.  Non-JSON payloads use a small fallback value
    or byte length; they never expose a second base64/text copy.
    """
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        return {"plain_bytes_len": len(b)}
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return {"plain_value": text}
    out = {"plain_json": value}
    if kind == "a5":
        out["plain_explained"] = _explain_a5(value)
    elif kind == "a9":
        out["plain_explained"] = _explain_a9(value)
    elif kind == "fingerprint":
        out["plain_explained"] = _explain_fingerprint(value)
    return out


def _plain_in(p: dict) -> bytes:
    if "plain_b64" in p:
        return base64.b64decode(p["plain_b64"])
    if "plain_obj" in p:
        return json.dumps(p["plain_obj"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if "plain_json" in p:
        value = p["plain_json"]
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        raise ValueError("plain_json must be JSON text, an object or an array")
    raise ValueError("需 plain_b64 / plain_json / plain_obj 之一")


def op_a5_decrypt(p):
    plain, profile = FS.decode_a5(p["a5"], p["a1"], int(p["a3"]), int(p["a4"]),
                                  profile=p.get("signing_profile", p.get("profile", "auto")))
    return {**_plain_out(plain, "a5"), "profile": profile}


def op_a5_encrypt(p):
    profile = p.get("signing_profile", p.get("profile", "legacy"))
    k2 = FS.k2buf(p["a1"], profile)
    return {"a5": MC.a5_encrypt(_plain_in(p), p["a1"], int(p["a3"]), int(p["a4"]), k2),
            "profile": profile}


def op_a2(p):
    profile = p.get("signing_profile", p.get("profile"))
    if profile is None:
        payload = json.loads(p["payload_json"])
        _, profile = FS.decode_a5(payload["a5"], p["a1"], payload["a3"], payload["a4"])
    return {"a2": FS.compute_a2(p["method"], p["url"], p.get("body", ""),
                                p["payload_json"], p["a1"], int(p["counter"]),
                                signing_profile=profile,
                                sign_sequence=p.get("sign_sequence"))}


def op_k2buf(p):
    return {"k2buf_hex": FS.k2buf(p["a1"], p.get("signing_profile", p.get("profile", "legacy"))).hex()}


def op_sign(p):
    path = p.get("identity_path")
    if not path and "identity" in p:
        signer = FS.FullSigner(p["identity"])
        mtgsig = signer.sign(p["method"], p["url"], p.get("body", ""))
        return {"mtgsig": mtgsig, "identity": signer.persist_counter()}
    if not path:
        raise ValueError("需 identity_path 或 identity")
    path = os.path.abspath(path)
    with _LOCK:
        signer = _SIGNERS.get(path)
        if signer is None:
            signer = _SIGNERS[path] = FS.FullSigner(path)
        mtgsig = signer.sign(p["method"], p["url"], p.get("body", ""))
        try:
            signer.persist_counter()
        except Exception:
            pass
    return {"mtgsig": mtgsig}


def _a9_options(p):
    """Resolve an explicit SDK profile; never try unrelated salt/UUID values."""
    name = p.get("profile", "default")
    if name not in ("default", "legacy"):
        raise ValueError("a9 profile must be default or legacy")
    fields = {}
    if name == "legacy":
        with open(os.path.join(ROOT, "mtgsig", "a9_legacy_profile.json"), encoding="utf-8") as f:
            fields.update(json.load(f))
    overrides = [k for k in ("salt_hex", "k3_hex", "a1_shift") if k in p]
    fields.update({k: p[k] for k in overrides})
    options = {}
    for field, dest in (("salt_hex", "salt"), ("k3_hex", "k3")):
        if field in fields:
            if not isinstance(fields[field], str):
                raise ValueError(f"a9 {field} must contain hexadecimal text")
            try:
                options[dest] = bytes.fromhex(fields[field])
            except ValueError as exc:
                raise ValueError(f"a9 {field} must contain hexadecimal text") from exc
    if "a1_shift" in fields:
        options["a1_shift"] = fields["a1_shift"]
    metadata = {"profile": name, "a1_shift": options.get("a1_shift", 31)}
    if overrides:
        metadata["profile_overrides"] = overrides
    return options, metadata


def op_a9_decode(p):
    options, metadata = _a9_options(p)
    result = A9.decode(p["a9"], p["a1"], mode=p.get("mode", "auto"), **options)
    return {**_plain_out(result.plaintext, "a9"), "mode": result.mode, **metadata}


def _op_a9_decode_for_decrypt(params):
    """Decode a complete capture, trying only the profiles known to this build.

    An explicit profile or any explicit override disables fallback. This keeps
    custom configurations deterministic while allowing a raw mtgsig body to
    select the verified current or historical profile by strict validation.
    """
    override_fields = ("salt_hex", "k3_hex", "a1_shift")
    if "profile" in params or any(field in params for field in override_fields):
        return op_a9_decode(params)
    errors = []
    for profile in ("default", "legacy"):
        candidate = dict(params, profile=profile)
        try:
            return op_a9_decode(candidate)
        except Exception as exc:
            errors.append(exc)
    raise errors[-1]


def op_a9_encode(p):
    options, metadata = _a9_options(p)
    mode = p.get("mode")
    if mode not in A9.MODES:
        raise ValueError("a9 encode requires mode: aes, twofish or twofish-mod")
    plain = p["siua_json"]
    if isinstance(plain, (dict, list)):
        plain = json.dumps(plain, separators=(",", ":"), ensure_ascii=False)
    if not isinstance(plain, str):
        raise ValueError("siua_json must be JSON text, an object or an array")
    return {"a9": A9.encode(plain, p["a1"], mode=mode, **options), "mode": mode, **metadata}


def _env_bytes(value, name, *, expected=None):
    """Parse an envelope key/IV/session value without guessing encodings."""
    if isinstance(value, str):
        if value.startswith("hex:"):
            try:
                value = bytes.fromhex(value[4:])
            except ValueError as exc:
                raise ValueError(f"{name} hex 无效") from exc
        elif expected and len(value) == expected * 2 and all(c in "0123456789abcdefABCDEF" for c in value):
            value = bytes.fromhex(value)
        else:
            value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError(f"{name} 需要 ASCII 文本或 hex:<...>")
    value = bytes(value)
    if expected is not None and len(value) != expected:
        raise ValueError(f"{name} 必须是 {expected} 字节")
    return value


def _env_plain_input(p):
    if "plain_b64" in p:
        try:
            return base64.b64decode(p["plain_b64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("plain_b64 不是有效 base64") from exc
    if "plaintext_b64" in p:
        try:
            return base64.b64decode(p["plaintext_b64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("plaintext_b64 不是有效 base64") from exc
    if "plaintext" in p:
        value = p["plaintext"]
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if "plain_json" in p or "plain_obj" in p:
        return _plain_in(p)
    raise ValueError("需 plaintext/plain_json/plain_obj/plain_b64 之一")


def _env_shift(shift):
    if shift is None:
        return None, None
    if isinstance(shift, bool) or not isinstance(shift, int) or not -255 <= shift <= 255:
        raise ValueError("caesar_shift 必须是 -255 到 255 的整数")
    return (lambda data: bytes((b + shift) & 0xff for b in data),
            lambda data: bytes((b - shift) & 0xff for b in data))


def _env_hex(p, field, *, expected=16):
    """SDK fields use exact hex names and never reinterpret text as a key."""
    if field not in p:
        return None
    value = p[field]
    if (not isinstance(value, str) or len(value) != expected * 2 or
            any(c not in "0123456789abcdefABCDEF" for c in value)):
        raise ValueError(f"{field} 必须是 {expected * 2} 位十六进制文本")
    return bytes.fromhex(value)


def _env_sdk_options(p):
    conflicting = {"key", "iv", "session_key", "session_material", "caesar_shift", "k3_hex"} & p.keys()
    if conflicting:
        raise ValueError("带 a1 的 SDK envelope 不接受旧字段：" + ", ".join(sorted(conflicting)))
    profile = p.get("profile", "default")
    if profile not in ("default", "legacy"):
        raise ValueError("envelope profile 必须是 default 或 legacy")
    options = {"profile": profile, "modulus": p.get("modulus_hex", ENV.DEFAULT_MODULUS_HEX)}
    if "salt_hex" in p:
        options["salt"] = _env_hex(p, "salt_hex")
    if "a1_shift" in p:
        options["a1_shift"] = p["a1_shift"]
    return options


def _env_bool(p, field, default):
    value = p.get(field, default)
    if not isinstance(value, bool):
        raise ValueError(f"{field} 必须是 JSON boolean")
    return value


def _env_require_legacy_fields(p):
    if {"session_key_hex", "session_material_hex", "compressed_b64", "mode", "profile", "salt_hex", "a1_shift"} & p.keys():
        raise ValueError("SDK envelope 字段需要原始 a1；旧接口只支持显式 AES key/iv")


def _op_envelope_encode_sdk(p):
    options = _env_sdk_options(p)
    if "session_material_hex" in p:
        raise ValueError("SDK envelope 加密请提供 session_key_hex；session_material_hex 用于解密")
    key = _env_hex(p, "session_key_hex")
    generated = key is None
    if generated:
        key = secrets.token_bytes(16)
    mode = p.get("mode", "twofish-mod")
    compressed = _env_bool(p, "compress", True)
    if "compressed_b64" in p:
        if not compressed or {"plaintext", "plain_json", "plain_obj", "plain_b64", "plaintext_b64", "zlib_level"} & p.keys():
            raise ValueError("compressed_b64 应单独提供，不能同时提供明文、zlib_level 或 compress=false")
        try:
            value = base64.b64decode(p["compressed_b64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("compressed_b64 不是有效 base64") from exc
        envelope = ENV.encode_compressed_sdk(value, p["a1"], session_key=key, mode=mode, **options)
    else:
        level = p.get("zlib_level", 6)
        if isinstance(level, bool) or not isinstance(level, int) or not -1 <= level <= 9:
            raise ValueError("zlib_level 必须是 -1 到 9 的整数")
        envelope = ENV.encode_sdk(_env_plain_input(p), p["a1"], session_key=key,
                                  mode=mode, compress=compressed, zlib_level=level, **options)
    parts = ENV.split(envelope)
    result = {"envelope": envelope, "part1_bytes": len(parts.part1),
              "part2_bytes": len(parts.part2), "compressed": compressed,
              "codec": "sdk", "mode": mode, "profile": options["profile"],
              "session_key_generated": generated}
    if generated:
        result["session_key_hex"] = key.hex()
    return result


def _op_envelope_decode_sdk(p):
    options = _env_sdk_options(p)
    key = _env_hex(p, "session_key_hex")
    material = _env_hex(p, "session_material_hex")
    result = ENV.decode_sdk(p["envelope"], p["a1"], session_key=key,
                            session_material=material, mode=p.get("mode", "auto"),
                            decompress=_env_bool(p, "decompress", True),
                            max_plaintext=p.get("max_plaintext", 4 << 20), **options)
    return {**_plain_out(result.plaintext, "envelope"), "part1_bytes": len(result.parts.part1),
            "part2_bytes": len(result.parts.part2), "codec": "sdk", "mode": result.mode,
            "profile": result.profile, "rsa_verified": result.rsa_verified}


def op_envelope_encode(p):
    """With a1 use the SDK codec; otherwise retain the explicit AES interface."""
    if "a1" in p:
        return _op_envelope_encode_sdk(p)
    _env_require_legacy_fields(p)
    session = p.get("session_material", p.get("session_key"))
    if session is None:
        raise ValueError("需 session_material/session_key")
    session = _env_bytes(session, "session_material", expected=16)
    key = _env_bytes(p.get("key"), "key")
    iv = _env_bytes(p.get("iv", "0102030405060708"), "iv", expected=16)
    modulus = p.get("modulus_hex", ENV.DEFAULT_MODULUS_HEX)
    plain = _env_plain_input(p)
    pre, _ = _env_shift(p.get("caesar_shift"))
    envelope = ENV.encode(session, plain, key=key, iv=iv, modulus=modulus,
                          compress=bool(p.get("compress", True)),
                          zlib_level=int(p.get("zlib_level", 6)), pre_encrypt=pre)
    parts = ENV.split(envelope)
    return {"envelope": envelope, "part1_bytes": len(parts.part1),
            "part2_bytes": len(parts.part2), "compressed": bool(p.get("compress", True))}


def op_envelope_decode(p):
    """With a1 validate SDK session material; otherwise use explicit AES key/IV."""
    if "a1" in p:
        return _op_envelope_decode_sdk(p)
    _env_require_legacy_fields(p)
    key = _env_bytes(p.get("key"), "key")
    iv = _env_bytes(p.get("iv", "0102030405060708"), "iv", expected=16)
    _, inverse = _env_shift(p.get("caesar_shift"))
    result = ENV.decode(p["envelope"], key=key, iv=iv,
                        decompress=bool(p.get("decompress", True)),
                        max_plaintext=int(p.get("max_plaintext", 4 << 20)),
                        post_decrypt=inverse)
    plain = result.plaintext if result.plaintext is not None else result.payload
    return {**_plain_out(plain, "envelope"), "part1_bytes": len(result.parts.part1),
            "part2_bytes": len(result.parts.part2)}


# 每字段可解性说明(给 /decrypt 用, "能解的自己提示")
_FIELD_INFO = {
    "a2": "单向 HMAC-SHA1, 设计上不可逆",
    "a7": "注册阶段 XID：首次是 main(1/2) 生成的本地候选；fingerprint/v1/info/report 响应 data.result 后，后续 a7 使用该 xid（不是可逆密文）",
    "a8": "注册阶段 DFP：首次可能是本地 dfpID；v5/sign 响应 data.dfp 后，后续 a8 使用该服务端 dfp（不是可逆密文）",
}


def op_decrypt(p):
    """把整条 mtgsig 丢进来, 自动解出能解的字段, 并逐字段标注可解性。

    body 可为 {"mtgsig": <对象/字符串>} 或直接就是 mtgsig 对象。
    """
    mt = p.get("mtgsig", p)
    if isinstance(mt, str):
        mt = json.loads(mt)
    if not isinstance(mt, dict):
        raise ValueError("需 mtgsig(JSON 对象或字符串)")
    out = {}
    # a5: 可解(需同条 a1/a3/a4)
    if "a5" in mt:
        if all(k in mt for k in ("a1", "a3", "a4")):
            try:
                # a9 can be cached across provider changes. Its optional
                # profile selector must not force a5 to use the same profile.
                plain, profile = FS.decode_a5(mt["a5"], mt["a1"], int(mt["a3"]), int(mt["a4"]),
                                               profile=p.get("signing_profile", "auto"))
                out["a5"] = {"decryptable": True, "profile": profile, **_plain_out(plain, "a5")}
            except Exception as e:
                out["a5"] = {"decryptable": False, "error": f"{type(e).__name__}: {e}"}
        else:
            out["a5"] = {"decryptable": False, "reason": "缺同条 a1/a3/a4, 无法解"}
    # a9: 从同条 mtgsig 取 a1，使用调用方明确选择的 SDK 配置。
    if "a9" in mt:
        try:
            params = {k: p[k] for k in ("profile", "mode", "salt_hex", "k3_hex", "a1_shift", "a1") if k in p}
            if "a1" in mt:
                if "a1" in params and params["a1"] != mt["a1"]:
                    raise ValueError("a1 differs between request and mtgsig")
                params["a1"] = mt["a1"]
            if "a1" not in params:
                raise ValueError("a9 requires the original a1")
            params["a9"] = mt["a9"]
            out["a9"] = {"decryptable": True, **_op_a9_decode_for_decrypt(params)}
        except Exception as e:
            out["a9"] = {"decryptable": False, "error": f"{type(e).__name__}: {e}"}
    # 其余: 单向 / 设备身份
    for f, why in _FIELD_INFO.items():
        if f in mt:
            out[f] = {"decryptable": False, "reason": why}
    if not out:
        raise ValueError("mtgsig 里没找到 a2/a5/a7/a8/a9 任何可识别字段")
    return {"fields": out}


# 登录 fingerprint / 设备指纹 = 标准 AES-128-CBC, key 为内嵌固定常量(k0 表), IV 固定。
# 逆向来源: hook 标准 AES(Keeta+0x2d9064)读 x2=AES_KEY, 实测标准 AES; corpse/I17 各用不同固定 key。
FP_IV = b"0102030405060708"
FP_KEYS = {                       # key(ASCII 16B) -> 用途标注
    "meituan1sankuai0": "corpse / 设备指纹(m 系列)",
    "34281a9dw2i701d4": "I17 定位指纹",
    "meituan0sankuai1": "k0.k2",
    "$MXMYBS@HelloPay": "k0.k3",
    "Maoyan010iauknaS": "k0.k4",
    "X%rj@KiuU+|xY}?f": "k0.k6",
}


def _fp_ct_bytes(p):
    """从多种字段拿密文原始字节, 容错 base64(去 \\/ 转义/空白, 补位, 截 16 倍数)。"""
    s = p.get("fingerprint") or p.get("ct_b64") or p.get("cipher")
    if s is None:
        raise ValueError("需 fingerprint / ct_b64(base64 密文)")
    warn = None
    s = str(s).replace("\\/", "/")
    s = "".join(s.split())
    if len(s) % 4 != 0:
        warn = f"base64 长度 {len(s)} 非 4 的倍数, 疑复制时丢字符, 尾部可能解出乱码"
    raw = base64.b64decode(s + "=" * (-len(s) % 4))
    if len(raw) % 16 != 0:
        warn = (warn or "") + f"; 密文 {len(raw)}B 非 16 倍数(应为整块), 已截断"
    return raw[: len(raw) // 16 * 16], warn


def _fp_key_bytes(k):
    """key 接受 16B ASCII 或 32 hex。"""
    if len(k) == 32 and all(c in "0123456789abcdefABCDEF" for c in k):
        return bytes.fromhex(k)
    kb = k.encode() if isinstance(k, str) else k
    if len(kb) not in (16, 24, 32):
        raise ValueError(f"key 长度需 16/24/32 字节(或 32 hex), 收到 {len(kb)}")
    return kb


def _fp_try(raw, key, iv):
    from Crypto.Cipher import AES
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(raw)
    if pt and 1 <= pt[-1] <= 16 and pt.endswith(bytes([pt[-1]]) * pt[-1]):
        pt = pt[:-pt[-1]]               # 去 PKCS7(仅当完整)
    return pt


def _fp_looks_plain(pt):
    head = pt[:64]
    return head[:1] in (b"{", b"[") or b'"m1"' in head or b'"I' in head or head[:2] == b"\x78\x9c"


def _fp_result(pt, **extra):
    return {**extra, **_plain_out(pt, "fingerprint")}


def op_fp_decrypt(p):
    """解登录 fingerprint / 设备指纹密文。

    body: {fingerprint|ct_b64: <base64密文>, key?: <16B ASCII 或 32 hex>, iv?: <16B ASCII 或 32 hex>}
    不传 key -> 自动用 k0 已知密钥表逐个试, 返回命中的那把 + 明文。
    """
    raw, warn = _fp_ct_bytes(p)
    iv = _fp_key_bytes(p["iv"]) if p.get("iv") else FP_IV
    if p.get("key"):
        key = _fp_key_bytes(p["key"])
        pt = _fp_try(raw, key, iv)
        res = _fp_result(pt, key_used=p["key"], iv=iv.decode("latin1", "replace"))
        if warn:
            res["warn"] = warn
        return res
    # 自动试 k0 表
    tried = []
    for k, label in FP_KEYS.items():
        try:
            pt = _fp_try(raw, k.encode(), iv)
        except Exception as e:
            tried.append({"key": k, "error": str(e)}); continue
        if _fp_looks_plain(pt):
            res = _fp_result(pt, key_used=k, key_label=label, iv=iv.decode())
            if warn:
                res["warn"] = warn
            return res
        tried.append({"key": k, "label": label, "head_hex": pt[:16].hex()})
    raise ValueError("k0 已知密钥表均未解出可读明文; 传 key 手动指定, 或确认密文完整。tried=%s"
                     % json.dumps(tried, ensure_ascii=False))


def _fp_plain_input(p):
    """Read fingerprint plaintext without requiring a redundant base64 copy."""
    if "plain_obj" in p:
        return MC.fingerprint_plain_bytes(p["plain_obj"])
    if "plain_json" in p:
        return MC.fingerprint_plain_bytes(p["plain_json"])
    # Keep the old input escape hatch for scripts that already hold bytes;
    # encryption responses themselves never include a base64/text duplicate.
    if "plain_b64" in p:
        try:
            return base64.b64decode(p["plain_b64"], validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("plain_b64 不是有效 base64") from exc
    raise ValueError("需 plain_json / plain_obj 之一")


def op_fp_encrypt(p):
    """Encode an I-series fingerprint for userriskcheck's ``fingerprint``."""
    key_arg = p.get("key")
    key = _fp_key_bytes(key_arg) if key_arg else MC.FINGERPRINT_I_KEY
    iv = _fp_key_bytes(p["iv"]) if p.get("iv") else MC.FINGERPRINT_IV
    ct = MC.fingerprint_encrypt(_fp_plain_input(p), key=key, iv=iv)
    return {
        "fingerprint": ct,
        "key_used": key_arg or MC.FINGERPRINT_I_KEY.decode("ascii"),
        "iv": iv.decode("latin1", "replace"),
    }


ROUTES = {
    "/decrypt": op_decrypt,
    "/a5/decrypt": op_a5_decrypt, "/a5/encrypt": op_a5_encrypt,
    "/a2": op_a2, "/k2buf": op_k2buf, "/sign": op_sign,
    "/a9/decode": op_a9_decode, "/a9/encode": op_a9_encode,
    "/fingerprint/decrypt": op_fp_decrypt, "/fp/decrypt": op_fp_decrypt,
    "/fingerprint/encrypt": op_fp_encrypt, "/fp/encrypt": op_fp_encrypt,
    "/envelope/encode": op_envelope_encode, "/envelope/decode": op_envelope_decode,
}

TOKEN = os.environ.get("KEETA_RPC_TOKEN")   # 设了就要求请求头 X-Token 匹配


def capabilities():
    return {
        "service": "keeta-offline-crypto-rpc",
        "auth": "X-Token required" if os.environ.get("KEETA_RPC_TOKEN") else "none",
        "v73_present": FS._A9 is not None,
        "a9_ready": True,
        "a9_requires_v73": False,
        "a9_modes": list(A9.MODES),
        "a9_profiles": ["default", "legacy"],
        "signing_profiles": ["default", "legacy"],
        "a5_auto_profile": True,
        "envelope_sdk_ready": True,
        "envelope_modes": list(A9.MODES),
        "envelope_profiles": ["default", "legacy"],
        "envelope_requires_session_key": True,
        "fields": {
            "a5": "encrypt/decrypt (offline)",
            "a2": "generate (offline, one-way)",
            "sign": "full mtgsig (offline; a7/a8/a9 from identity file)",
            "k2buf": "derive (offline)",
            "a9": "encrypt/decrypt (offline; original a1 and matching SDK profile required)",
            "fingerprint": "encrypt/decrypt (offline; I-series AES-128-CBC, fixed k0 keys)",
            "envelope": "SDK encrypt/decrypt (AES/Twofish/Twofish-mod, a1/profile); decode requires session key or known RSA plaintext material; arbitrary public RSA envelopes cannot be decrypted",
        },
        "endpoints": sorted(ROUTES),
        "example": {
            "url": "POST /a5/decrypt",
            "body": {"a5": "<base64 a5>", "a1": "<uuid>", "a3": 25, "a4": 1790527417},
        },
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_ok(self):
        if not TOKEN:
            return True
        if self.headers.get("X-Token") == TOKEN:
            return True
        self._send(401, {"error": "需要正确的 X-Token 请求头"})
        return False

    def do_GET(self):
        if not self._auth_ok():
            return
        if self.path.rstrip("/") in ("", "/health"):
            self._send(200, capabilities())
        else:
            self._send(404, {"error": "GET only / and /health", "endpoints": sorted(ROUTES)})

    def do_POST(self):
        if not self._auth_ok():
            return
        fn = ROUTES.get(self.path.rstrip("/") or self.path)
        if fn is None:
            self._send(404, {"error": "unknown endpoint", "endpoints": sorted(ROUTES)})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception as e:
            self._send(400, {"error": f"bad json body: {e}"})
            return
        try:
            self._send(200, fn(payload))
        except NotImplementedError as e:
            self._send(501, {"error": str(e)})
        except KeyError as e:
            self._send(400, {"error": f"缺字段 {e}"})
        except Exception as e:
            self._send(400, {"error": f"{type(e).__name__}: {e}"})

    def log_message(self, *a):
        pass  # 静默


def selftest():
    """用 /tmp/keeta_K.json 直接调各 op(不走 HTTP), 校验能力。"""
    import re
    ok = True
    sample = "/tmp/keeta_K.json"
    if os.path.exists(sample):
        mt = json.load(open(sample))["mtgsig"]
        a1, a3, a4 = mt["a1"], int(mt["a3"]), int(mt["a4"])
        dec = op_a5_decrypt({"a5": mt["a5"], "a1": a1, "a3": a3, "a4": a4})
        re_a5 = op_a5_encrypt({"plain_json": dec["plain_json"], "a1": a1, "a3": a3, "a4": a4})
        assert re_a5["a5"] == mt["a5"], "a5 往返不一致"
        print("  ✓ a5 decrypt+encrypt 往返一致")
        cnt = int(re.findall(r"\d+", mt["a10"])[-1])
        a2 = op_a2({"method": "POST", "url": "/x", "body": "", "payload_json": "{}",
                    "a1": a1, "counter": cnt, "sign_sequence": dec["plain_json"]["b2"],
                    "signing_profile": dec["profile"]})
        assert len(a2["a2"]) == 32, "a2 长度异常"
        print("  ✓ a2 生成")
        print("  ✓ k2buf:", op_k2buf({"a1": a1})["k2buf_hex"])
    else:
        print("  (跳过 a5/a2 自检: 无 /tmp/keeta_K.json)")
    if os.path.exists(sample):
        identity = FS.provision_identity({"mtgsig": mt})
        r = op_sign({"identity": identity, "method": "POST",
                     "url": "/api/v1/shop/shopInfo", "body": ""})
        assert '"a2"' in r["mtgsig"], "sign 输出无 a2"
        print("  ✓ sign 完整 mtgsig, 长度", len(r["mtgsig"]))
    print("  a9: ready (aes / twofish / twofish-mod; original a1 and SDK profile required)")
    print("[selftest] 通过" if ok else "[selftest] 有失败")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest()
        return
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"[keeta-rpc] listening http://{a.host}:{a.port}  a9=ready")
    print(f"[keeta-rpc] GET http://{a.host}:{a.port}/ 看能力清单")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

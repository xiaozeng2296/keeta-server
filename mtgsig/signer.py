"""Full offline mtgsig from an existing account identity and matched SDK profile.

Request fields and observed counters advance on the copied state. Caller owns
persistence; no device attachment, remote service or device-table dump is used.
Server a7/a8 values are accepted only from explicit successful response input.
"""
import hashlib
import hmac
import json
import os
import re
import time
import base64
import zlib
from collections import OrderedDict
from copy import deepcopy
import tempfile
from urllib.parse import urlsplit

from mtgsig import a2 as A2                         # 表 + a2Mix/a2Substitute/canonicalString
from pathlib import Path
PACKAGE_ROOT = Path(__file__).resolve().parent
from mtgsig import mtg_crypto as MC                       # a5 RC4变体 + zlib
from mtgsig import a9_codec as A9             # 新版 a9 双向 codec（无需 v73）
from mtgsig.registration_state import apply_registration_response
from mtgsig.collection_cache import CollectionCache

_CONST = json.load(open(PACKAGE_ROOT / "keeta_const.json", encoding="utf-8"))
SALT = bytes.fromhex(_CONST["salt"])
K1 = bytes.fromhex(_CONST["k1"])
EFF = _CONST["embeddedA0_eff"].encode()

_A9_LEGACY_PROFILE = PACKAGE_ROOT / "a9_legacy_profile.json"


def _a9_options(profile):
    """Return codec options for a persisted SDK profile.

    Keep this local to the signer so identity files only need to store the
    profile name.  The default profile is represented by codec defaults;
    legacy carries the historical salt and identifier offset.
    """
    if profile in (None, "default"):
        return {}
    if profile != "legacy":
        raise ValueError("a9 profile must be default or legacy")
    with open(_A9_LEGACY_PROFILE, encoding="utf-8") as f:
        cfg = json.load(f)
    options = {}
    if "salt_hex" in cfg:
        options["salt"] = bytes.fromhex(cfg["salt_hex"])
    if "k3_hex" in cfg:
        options["k3"] = bytes.fromhex(cfg["k3_hex"])
    if "a1_shift" in cfg:
        options["a1_shift"] = cfg["a1_shift"]
    return options


def _detect_a9_codec(a9, a1):
    """Strictly identify a9 profile/mode from an existing sample.

    A candidate is accepted only after padding, CRC32 and complete zlib
    validation inside :func:`a9_codec.decode`; no plaintext heuristics are
    used.  Return ``None`` when this build's new codec does not match.
    """
    if not a9 or not a1:
        return None
    for profile in ("default", "legacy"):
        try:
            result = A9.decode(a9, a1, mode="auto", **_a9_options(profile))
        except Exception:
            continue
        try:
            plain = result.plaintext.decode("utf-8")
        except UnicodeDecodeError:
            continue
        return {"profile": profile, "mode": result.mode, "plain": plain}
    return None




def _identity_a9_options(options):
    """Read JSON-safe a9 overrides and turn byte fields back into bytes."""
    out = dict(options or {})
    if "salt_hex" in out:
        out["salt"] = bytes.fromhex(out.pop("salt_hex"))
    if "k3_hex" in out:
        out["k3"] = bytes.fromhex(out.pop("k3_hex"))
    return out


def a9_generate(siua_json, a1, *, profile="default", mode="twofish-mod"):
    """Encode a9 using its original a1 and matching profile."""
    return A9.encode(siua_json, a1, mode=mode, **_a9_options(profile))


def k2buf(a1, profile="legacy"):
    """SDK mask; the no-argument default preserves existing identity files.

    The current provider and the historical provider use different salt and
    a1 offsets. a5/signing and cached a9 have independently selected profiles.
    An explicit ProviderConfig uses the decoded native salt and parameter.
    """
    from mtgsig.provider_config import ProviderConfig
    if isinstance(profile, ProviderConfig):
        return profile.mask(a1)
    if profile == "default":
        return A9.derive_mask(a1)
    if profile != "legacy":
        raise ValueError("signing profile must be default or legacy")
    return A9.derive_mask(a1, salt=SALT, a1_shift=12)


def decode_a5(a5, a1, a3, a4, *, profile="auto", max_plaintext=4 << 20):
    """Detect a5's provider using complete zlib and JSON-object validation."""
    profiles = ("default", "legacy") if profile == "auto" else (profile,)
    from mtgsig.provider_config import ProviderConfig
    if any(not isinstance(p, ProviderConfig) and p not in ("default", "legacy") for p in profiles):
        raise ValueError("a5 profile must be auto, default or legacy")
    if isinstance(profile, ProviderConfig) and a3 != profile.parameter:
        raise ValueError("provider configuration parameter differs from signature a3")
    ciphertext = base64.b64decode(a5, validate=True)
    for candidate in profiles:
        key = MC.a5_derive_key(a1, a3, a4, k2buf(a1, candidate))
        compressed = MC.rc4_variant(key, ciphertext)
        try:
            stream = zlib.decompressobj()
            plain = stream.decompress(compressed, max_plaintext + 1)
            if (len(plain) > max_plaintext or not stream.eof or
                    stream.unused_data or stream.unconsumed_tail):
                continue
            if not isinstance(json.loads(plain), dict):
                continue
        except (zlib.error, ValueError, UnicodeError):
            continue
        return plain, candidate
    raise ValueError("a5 validation failed for the selected signing profile")


def hmac_key(counter, a1):
    cb = counter & 0xff
    a1b = a1.encode()
    return bytes(EFF[(j + 8) % 36] ^ a1b[j % 36] ^ cb for j in range(36))


def _a2_pass2(out1, k2, sign_sequence):
    """a2[8:16], including the independent sequence stored in a5.b2."""
    o = out1
    K2 = {1: k2[1], 2: k2[2], 3: k2[3], 15: k2[15]}
    A9 = k2[0] ^ o[0] ^ o[7] ^ (sign_sequence & 0xff)
    A10 = o[1] ^ o[6] ^ K2[1] ^ ((sign_sequence >> 8) & 0xff)
    A11 = o[2] ^ o[5] ^ K2[2] ^ ((sign_sequence >> 16) & 0xff)
    A12 = o[3] ^ o[4] ^ K2[3] ^ ((sign_sequence >> 24) & 0xff)
    A13 = 0x7e & (o[3] ^ o[4] ^ k2[4])
    A14 = 0x02 | (0xbd & (k2[5] ^ o[4] ^ o[5]))
    A15 = 0x20 | (0xdb & (k2[6] ^ o[5] ^ o[6]))
    A8 = A9 ^ A10 ^ A11 ^ A12 ^ A13 ^ A14 ^ A15 ^ K2[15]
    return bytes([A8, A9, A10, A11, A12, A13, A14, A15])


def compute_a2(method, url, body, payload_json, a1, counter, *, signing_profile="legacy",
               sign_sequence=None):
    """Generate both halves. counter is a10's session value, not a5.b2."""
    k2 = k2buf(a1, signing_profile)
    if sign_sequence is None:
        mt = json.loads(payload_json)
        plain, _ = decode_a5(mt["a5"], a1, mt["a3"], mt["a4"], profile=signing_profile)
        sign_sequence = json.loads(plain)["b2"]
    if type(sign_sequence) is not int or sign_sequence < 0:
        raise ValueError("sign_sequence must be a nonnegative integer")
    K = hmac_key(counter, a1)
    msg = A2.signing_message(method, url, body, payload_json)
    d16 = hmac.new(K, msg, hashlib.sha1).digest()[:16]
    s9 = A2.a2Mix(d16)
    sub = A2.a2Substitute(s9)
    KK = bytes(K1[i] ^ k2[i] for i in range(8))
    out1 = bytes(((sub[i] + d16[i]) & 0xff) ^ KK[i] for i in range(8))
    return out1.hex() + _a2_pass2(out1, k2, sign_sequence).hex()


_B16_TRIPLE = r"\[\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\]"
_RENDER_B16_ZERO = re.compile(
    r"^\s*" + _B16_TRIPLE + r"\s*,\s*" + _B16_TRIPLE +
    r"\s*,\s*\[\s*(?P<count>0)(?=\s*,\s*\d+\s*,\s*\d+\s*\])")


def render_b16(value):
    """Apply the validated render rule to the outgoing device-info count only.

    Keep captured snapshots, nonzero counters, timestamps and suffixes intact.
    This request adaptation does not fabricate a device-info HTTP callback.
    """
    match = _RENDER_B16_ZERO.match(value) if isinstance(value, str) else None
    if not match:
        return value
    return value[:match.start('count')] + '1' + value[match.end('count'):]


def continued_signing_counters(device):
    """Continue explicit counters, or preserve the last legacy-generated values.

    Migration cannot reconstruct missed SDK events. Once persisted, POST and
    nil-user counts advance independently of the total signature sequence.
    Local totals stay monotonic; outgoing native values use their low 32 bits.
    """
    sequence = int(device.get("sign_sequence", device.get("counter", 1000)))
    collect = device.get("base_collect", {})
    previous = collect.get("b2")
    result = {}
    for name, field in (("post_sign_count", "b17"), ("nil_user_sign_count", "b18")):
        if name in device:
            value = device[name]
        elif type(collect.get(field)) is int:
            value = collect[field]
            if type(previous) is int:
                if field == "b17" and previous - value in (0, 1):
                    value = sequence - (previous - value)
                elif field == "b18" and value > 0 and value == previous:
                    value = sequence
        else:
            continue
        if type(value) is not int or value < 0:
            raise ValueError("signing counters require nonnegative integers")
        result[name] = value
    return result


class FullSigner:
    """从 provision 出的设备身份档,每请求现算全字段 mtgsig。"""

    # payload 字段顺序(a2 最后单独追加,便于服务端删 a2 还原)
    ORDER = ["a0", "a1", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "x0"]

    def __init__(self, identity_path):
        if isinstance(identity_path, dict):
            self.dev = deepcopy(identity_path)
            identity_path = None
        else:
            with open(identity_path, encoding="utf-8") as fh:
                self.dev = json.load(fh)
        self.counter = int(self.dev.get("sign_sequence", self.dev.get("counter", 1000)))
        self.signature_counter = int(self.dev.get("signature_counter", self.dev.get("counter", 1000)))
        self._id_path = identity_path
        self._signing_counters = continued_signing_counters(self.dev)
        self.sdk_user_id_state = self.dev.get("sdk_user_id_state", "unknown")
        if self.sdk_user_id_state not in ("nil", "non_nil", "unknown"):
            raise ValueError("sdk_user_id_state must be nil, non_nil or unknown")
        # Native-parity/registration callers keep captured collection times.
        # The crawler can explicitly render the two validated freshness clocks
        # per request; this does not remeasure the captured device observations.
        self.collection_clock_mode = self.dev.get("collection_clock_mode", "captured")
        if self.collection_clock_mode not in ("captured", "request", "periodic"):
            raise ValueError("collection_clock_mode must be captured, request or periodic")
        if self.collection_clock_mode == "request" and any(
                type(self.dev.get("base_collect", {}).get(key)) is not int
                for key in ("b8", "b9")):
            raise ValueError("request collection clocks require captured integer b8 and b9")
        self.signing_profile = self.dev.get("signing_profile", "legacy")
        k2buf(self.dev["a1"], self.signing_profile)
        self.a9_profile = self.dev.get("a9_profile")
        self.a9_mode = self.dev.get("a9_mode")
        self.a9_options = _identity_a9_options(self.dev.get("a9_options", {}))
        self._collection_cache = None
        self.request_dynamic_mode = self.dev.get("request_dynamic_mode", "captured")
        if self.request_dynamic_mode not in ("captured", "fresh"):
            raise ValueError("request_dynamic_mode must be captured or fresh")
        self._fingerprint_cache = {}

        # a7/a8 are staged values during first registration.  The value in
        # the first mtgsig can be a locally generated XID/dfpID, while later
        # requests use the values returned by the registration endpoints.
        # Keep the distinction explicit in the identity file and prefer a
        # server value only when it was supplied as such by the caller.
        self.a7_local_xid = self.dev.get("a7_local_xid")
        self.a7_server_xid = (self.dev.get("a7_server_xid") or
                              self.dev.get("xid"))
        self.a8_local_dfp = self.dev.get("a8_local_dfp")
        self.a8_server_dfp = (self.dev.get("a8_server_dfp") or
                              self.dev.get("dfp"))
        self.a7 = self.a7_server_xid or self.dev.get("a7") or self.a7_local_xid
        self.a8 = self.a8_server_dfp or self.dev.get("a8") or self.a8_local_dfp
        if not self.a7 or not self.a8:
            raise ValueError("identity file requires captured a7/a8 or explicit server xid/dfp")

        # provision_identity 保存了经过严格校验的 profile/mode。已有旧档
        # 可能只有 base_siua/a9，此时先用捕获 a9 严格识别，避免猜默认
        # 模式把旧 v73 身份误换成另一种密文。
        explicit_codec = (self.a9_profile in ("default", "legacy") and
                           self.a9_mode in A9.MODES)
        if self.dev.get("base_siua") and not explicit_codec:
            try:
                detected = _detect_a9_codec(self.dev.get("a9"), self.dev.get("a1"))
            except Exception:
                detected = None
            if detected:
                self.a9_profile = detected["profile"]
                self.a9_mode = detected["mode"]
                self.dev["a9_profile"] = self.a9_profile
                self.dev["a9_mode"] = self.a9_mode
                self.a9_options = {}
                explicit_codec = True

        if self.dev.get("base_siua") and explicit_codec:
            try:
                opts = _a9_options(self.a9_profile)
                opts.update(self.a9_options)
                self.a9 = A9.encode(self.dev["base_siua"], self.dev["a1"],
                                    mode=self.a9_mode, **opts)
            except Exception:
                explicit_codec = False
        if self.collection_clock_mode == "periodic":
            if not explicit_codec or not self.dev.get("base_siua"):
                raise ValueError("periodic cache requires a validated a9 codec and decoded SIUA")
            self._collection_cache = CollectionCache(self.dev)
        if not explicit_codec or not self.dev.get("base_siua"):
            self.a9 = self.dev["a9"]

    def apply_registration_response(self, endpoint, response, *, http_status):
        """Feed a response from this identity into subsequent signed requests."""
        identity = dict(self.dev, a7=self.a7, a8=self.a8)
        patch = apply_registration_response(identity, endpoint, response,
                                            http_status=http_status)
        if not patch:
            return {}
        self.dev.update(identity)
        for key in ("a7", "a8", "a7_local_xid", "a8_local_dfp",
                    "a7_server_xid", "a8_server_dfp"):
            if key in self.dev:
                setattr(self, key, self.dev[key])
        return patch

    def _fresh_a5(self, a1, a3, a4, *, timestamp_ms=None, for_render=False):
        col = OrderedDict(self.dev["base_collect"])
        if self._collection_cache is not None:
            col, siua = self._collection_cache.refresh(timestamp_ms if timestamp_ms is not None else a4 * 1000)
            opts = _a9_options(self.a9_profile)
            opts.update(self.a9_options)
            self.a9 = A9.encode(siua, a1, mode=self.a9_mode, **opts)
        # Native pre-sign counters are independent: POST advances b17;
        # only an explicitly observed nil SDK userID advances b18.
        for name, field in (("post_sign_count", "b17"), ("nil_user_sign_count", "b18")):
            if name in self._signing_counters:
                col[field] = self._signing_counters[name] & 0xffffffff
        col["b2"] = self.counter & 0xffffffff
        # Fixed-time controls plus live menu/detail requests establish that
        # stale b8/b9 cause these collection endpoints to reject a fresh a4.
        # Opt-in rendering only updates these clocks in the outgoing payload;
        # retain b7, b13 and all device observations in the source snapshot.
        if self.collection_clock_mode == "request":
            col["b8"] = a4
            col["b9"] = a4
        # Keep report events separate from the immutable capture/cache fingerprint.
        from mtgsig.fingerprint_refresh import outgoing_b16
        if "b16" in col:
            col["b16"] = outgoing_b16(self.dev, col["b16"])
        if for_render and "b16" in col:
            col["b16"] = render_b16(col["b16"])
        raw = json.dumps(col, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return MC.a5_encrypt(raw, a1, a3, a4, k2buf(a1, self.signing_profile))

    def sign(self, method, url, body):
        if method.upper() == "POST" and "post_sign_count" in self._signing_counters:
            self._signing_counters["post_sign_count"] += 1
        if self.sdk_user_id_state == "nil" and "nil_user_sign_count" in self._signing_counters:
            self._signing_counters["nil_user_sign_count"] += 1
        self.counter += 1
        a1 = self.dev["a1"]
        a3 = self.dev["a3"]
        now = time.time()
        for_render = method.upper() == "POST" and urlsplit(url).path == "/api/v1/shop/product/render"
        a4 = int(now)
        mt = OrderedDict()
        vals = {"a0": self.dev["a0"], "a1": a1, "a3": a3, "a4": a4,
                "a5": self._fresh_a5(a1, a3, a4, timestamp_ms=int(now * 1000), for_render=for_render), "a6": self.dev["a6"],
                "a7": self.a7, "a8": self.a8, "a9": self.a9,
                "a10": f"3,{self.signature_counter}", "x0": self.dev["x0"]}
        for k in self.ORDER:
            mt[k] = vals[k]
        payload = json.dumps(mt, separators=(",", ":"), ensure_ascii=False)
        mt["a2"] = compute_a2(method, url, body, payload, a1, self.signature_counter,
                              signing_profile=self.signing_profile, sign_sequence=self.counter)
        return json.dumps(mt, separators=(",", ":"), ensure_ascii=False)

    def persist_counter(self):
        self.dev["counter"] = self.counter
        self.dev["sign_sequence"] = self.counter
        self.dev["signature_counter"] = self.signature_counter
        self.dev.update(self._signing_counters)
        if self._id_path is not None:
            from pathlib import Path
            path = Path(self._id_path)
            fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    json.dump(self.dev, stream, ensure_ascii=False)
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        return deepcopy(self.dev)

    def prepare_request(self, url, headers, body):
        """Refresh opted-in request values before signing the final bytes."""
        if self.request_dynamic_mode == "captured":
            return url, dict(headers), body
        from mtgsig.request import refresh_request
        return refresh_request(url, headers, body, self.dev,
                               fingerprint_cache=self._fingerprint_cache)


def provision_identity(sample_path, out_path=None, token=None, registration=None):
    """从设备取样抽出身份档，并保留注册阶段的 a7/a8 语义。

    ``mtgsig.a7``/``mtgsig.a8`` 只说明“这一次请求使用的值”。首次启动
    时它们可能仍是本地生成的 XID/dfpID；fingerprint info report 返回
    ``xid``、v5/sign 返回 ``dfp`` 后，后续请求才会切换到服务端值。调用方
    若已经保存了这些响应，可通过 ``registration={"xid": ..., "dfp": ...}``
    显式传入。没有响应时绝不从本地值推断服务端值。
    """
    if isinstance(sample_path, dict):
        samp = deepcopy(sample_path)
    else:
        with open(sample_path, encoding="utf-8") as fh:
            samp = json.load(fh)
    mt = samp["mtgsig"]
    if registration is None:
        # A sample may carry a separately captured registration response.  It
        # is safe to consume only the explicit mapping; never infer server
        # values from the request's a7/a8 or from arbitrary response text.
        registration = samp.get("registration")
    a1 = mt["a1"]
    collect_plain, signing_profile = decode_a5(mt["a5"], a1, mt["a3"], mt["a4"])
    base_collect = json.loads(collect_plain, object_pairs_hook=OrderedDict)
    dev = OrderedDict([
        ("a0", mt["a0"]), ("a1", a1), ("a3", mt["a3"]), ("a6", mt["a6"]),
        ("a7", mt["a7"]), ("a8", mt["a8"]), ("a9", mt["a9"]), ("x0", mt["x0"]),
        ("base_collect", base_collect), ("counter", int(base_collect["b2"])),
        ("sign_sequence", int(base_collect["b2"])),
        ("signature_counter", int(mt["a10"].split(",")[1])),
        ("signing_profile", signing_profile),
    ])
    # Preserve the observed values.  Do not call them "local" unless the
    # caller also supplied the matching registration responses: a sample may
    # have been captured after the response and then already contain server
    # values.
    dev["a7_captured"] = mt["a7"]
    dev["a8_captured"] = mt["a8"]
    if registration:
        if not isinstance(registration, dict):
            raise TypeError("registration must be a mapping")
        xid = registration.get("xid") or registration.get("a7_server_xid")
        dfp = registration.get("dfp") or registration.get("a8_server_dfp")
        if xid:
            dev["a7_local_xid"] = mt["a7"]
            dev["xid"] = str(xid)
            dev["a7_server_xid"] = str(xid)
            dev["a7"] = str(xid)
        if dfp:
            dev["a8_local_dfp"] = mt["a8"]
            dev["dfp"] = str(dfp)
            dev["a8_server_dfp"] = str(dfp)
            dev["a8"] = str(dfp)
    # a9 codec 可直接从样本识别 profile/mode，并保留压缩前的 SIUA JSON，
    # 让后续 FullSigner 每次按同一配置重算，而不是静态复用 a9。
    try:
        detected = _detect_a9_codec(mt["a9"], a1)
        if detected is None:
            raise ValueError("a9 profile not recognised")
        dev["a9_profile"] = detected["profile"]
        dev["a9_mode"] = detected["mode"]
        dev["a9_options"] = {}
        dev["base_siua"] = detected["plain"]
    except ValueError:
        pass  # Preserve opaque a9 when no known profile validates.
    if token:
        dev["token"] = token
    if out_path is not None:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(dev, fh, ensure_ascii=False)
    return dev

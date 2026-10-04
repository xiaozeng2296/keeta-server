#!/usr/bin/env python3
"""通过 HTTP 验收已部署 RPC；默认只发送合成数据，不输出响应或密钥。

HTTP 客户端仅用标准库；预期结果由项目 codec 生成（需要 PyCryptodome）。
可从任意工作目录运行，不导入 keeta_rpc 或签名器。
"""
import argparse
import base64
import json
import math
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request


ROOT = next((p for p in (Path(__file__).resolve().parent,
                        Path(__file__).resolve().parent.parent)
             if (p / "mtgsig/a9_codec.py").is_file()), None)
if ROOT is not None:
    sys.path.insert(0, str(ROOT))

A1 = "00112233-4455-6677-8899-aabbccddeeff"
PLAIN = {"0": 12, "1": ["rpc-smoke"], "2": ["合成验收"], "3": "{}"}
TEXT = json.dumps(PLAIN, separators=(",", ":"), ensure_ascii=False)
MAX_RESPONSE = 8 << 20


class SmokeFailure(Exception):
    """Only fixed, non-sensitive descriptions may be included in this error."""


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # Do not forward X-Token or sample data to an unexpected target.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, url, token=None, timeout=8):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme in ("http", "https") and bool(parsed.hostname),
                "--url 必须是 http(s) 基础地址")
        require(not (parsed.username or parsed.password or parsed.query or parsed.fragment),
                "--url 不得包含认证信息、查询参数或片段")
        require(math.isfinite(timeout) and 0 < timeout <= 10,
                "timeout 必须大于 0 且不超过 10 秒")
        require(token is None or (isinstance(token, str) and bool(token)
                                  and "\r" not in token and "\n" not in token),
                "认证环境变量为空或格式无效")
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout
        self.opener = urllib.request.build_opener(NoRedirect())
        self.requests = 0

    def request(self, path, body=None):
        headers = {"Accept": "application/json"}
        if self.token is not None:
            headers["X-Token"] = self.token
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        self.requests += 1
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                require(response.status == 200, "HTTP 状态异常")
                raw = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            # Server errors may echo keys or plaintext: never print their body.
            raise SmokeFailure(f"HTTP {exc.code}：{path} 验收失败") from None
        except (OSError, ValueError, urllib.error.URLError):
            raise SmokeFailure(f"连接失败或超时：{path}") from None
        require(len(raw) <= MAX_RESPONSE, "HTTP 响应超过大小限制")
        try:
            result = json.loads(raw)
        except (ValueError, UnicodeError):
            raise SmokeFailure(f"响应不是 JSON：{path}") from None
        require(isinstance(result, dict) and "error" not in result,
                f"响应结构或操作错误：{path}")
        return result


def plain_bytes(result):
    """Serialize the canonical JSON response value for byte-level checks.

    Decrypt endpoints now return ``plain_json`` for JSON payloads.  Keeping
    the conversion here lets the acceptance checks compare compact JSON even
    when the server pretty-prints its response, without requiring the old
    duplicate base64/text fields.
    """
    if "plain_json" in result:
        try:
            return json.dumps(result["plain_json"], separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            raise SmokeFailure("响应中的 plain_json 无法序列化") from None
    if "plain_value" in result and isinstance(result["plain_value"], str):
        return result["plain_value"].encode("utf-8")
    raise SmokeFailure("响应缺少可读明文")


def check_plain(result, expected):
    require("plain_b64" not in result and "plain_text" not in result,
            "响应仍包含冗余的 base64/text 明文字段")
    require(plain_bytes(result) == expected, "解密明文与本地预期不一致")


def load_sample(sample_path, expected_path):
    try:
        sample = json.loads(Path(sample_path).read_text(encoding="utf-8"))
        if isinstance(sample, dict) and "mtgsig" in sample:
            sample = sample["mtgsig"]
        if isinstance(sample, str):
            sample = json.loads(sample)
        require(isinstance(sample, dict) and all(isinstance(sample.get(k), str)
                                                for k in ("a1", "a9")),
                "样本必须包含字符串 a1/a9")
        expected = Path(expected_path).read_bytes()
    except (OSError, ValueError, UnicodeError):
        raise SmokeFailure("读取样本或预期明文失败") from None
    # Deliberately discard all authentication and unrelated captured fields.
    return {"a1": sample["a1"], "a9": sample["a9"]}, expected


def run_checks(client, *, sample=None, profile="default", report=print):
    require(ROOT is not None, "找不到项目 mtgsig/a9_codec.py")
    from Crypto.Cipher import AES
    from mtgsig import a9_codec as codec, envelope_codec, mtg_crypto

    health = client.request("/health")
    require(health.get("a9_ready") is True and health.get("a9_requires_v73") is False,
            "服务尚未更新：a9 未就绪或仍依赖 v73")
    require(set(health.get("a9_modes", [])) == set(codec.MODES)
            and set(health.get("a9_profiles", [])) == {"default", "legacy"},
            "服务尚未更新：a9 模式或配置不完整")
    report("通过：健康状态，a9 已就绪且无需 v73 文件")
    require(health.get("envelope_sdk_ready") is True
            and health.get("envelope_requires_session_key") is True
            and set(health.get("envelope_modes", [])) == set(codec.MODES)
            and set(health.get("envelope_profiles", [])) == {"default", "legacy"},
            "服务尚未更新：envelope SDK 或会话解密边界不完整")

    legacy = json.loads((ROOT / "mtgsig/a9_legacy_profile.json").read_text())
    configs = {"default": {}, "legacy": {"salt": bytes.fromhex(legacy["salt_hex"]),
                                          "a1_shift": legacy["a1_shift"]}}
    ciphertexts = {}
    for name, options in configs.items():
        for mode in codec.MODES:
            expected = codec.encode(TEXT, A1, mode=mode, **options)
            encoded = client.request("/a9/encode", {"a1": A1, "siua_json": PLAIN,
                                                      "profile": name, "mode": mode})
            require(encoded.get("a9") == expected, "a9 加密与本地预期不一致")
            decoded = client.request("/a9/decode", {"a1": A1, "a9": expected,
                                                      "profile": name})
            check_plain(decoded, TEXT.encode())
            require(decoded.get("mode") == mode and decoded.get("profile") == name,
                    "a9 解密未返回正确模式/配置")
            ciphertexts[name, mode] = expected
    report("通过：a9 三种算法 × default/legacy 加密、自动识别解密")

    # a5 expectations use only the small constant file, without loading signer
    # tables or the application module.
    constants = json.loads((ROOT / "mtgsig/keeta_const.json").read_text())
    k2 = codec.derive_mask(A1, salt=bytes.fromhex(constants["salt"]), a1_shift=12)
    a3, a4 = 25, 1700000000
    a5 = mtg_crypto.a5_encrypt(TEXT.encode(), A1, a3, a4, k2)
    encoded = client.request("/a5/encrypt", {"a1": A1, "a3": a3, "a4": a4,
                                              "plain_obj": PLAIN})
    require(encoded.get("a5") == a5, "a5 加密与本地预期不一致")
    for name in configs:
        mt = {"a0": "2.5", "a1": A1, "a2": "synthetic-one-way-signature",
              "a3": a3, "a4": a4, "a5": a5, "a6": 0,
              "a7": "synthetic-device-field", "a8": "synthetic-device-field",
              "a9": ciphertexts[name, "twofish"], "a10": "3,1", "x0": 2}
        for value in (mt, json.dumps(mt)):
            result = client.request("/decrypt", {"mtgsig": value, "profile": name})
            fields = result.get("fields", {})
            for field in ("a5", "a9"):
                require(fields.get(field, {}).get("decryptable") is True,
                        "整组 mtgsig 未能解密 a5/a9")
                check_plain(fields[field], TEXT.encode())
            for field in ("a2", "a7", "a8"):
                require(fields.get(field, {}).get("decryptable") is False,
                        "整组 mtgsig 对不可解字段的标记不正确")
    # a5 can use the current provider while a9 remains a legacy cached value.
    # Verify both direct-body auto detection and an explicit a9-only selector.
    current_a5 = mtg_crypto.a5_encrypt(TEXT.encode(), A1, a3, a4, codec.derive_mask(A1))
    encoded_current = client.request("/a5/encrypt", {
        "a1": A1, "a3": a3, "a4": a4, "plain_obj": PLAIN, "profile": "default",
    })
    require(encoded_current.get("a5") == current_a5 and encoded_current.get("profile") == "default",
            "当前配置 a5 加密与本地预期不一致")
    mixed = dict(mt, a5=current_a5, a9=ciphertexts["legacy", "twofish"])
    for request in (mixed, {"mtgsig": mixed, "profile": "legacy"}):
        fields = client.request("/decrypt", request).get("fields", {})
        for field, selected in (("a5", "default"), ("a9", "legacy")):
            decoded = fields.get(field, {})
            require(decoded.get("decryptable") is True and decoded.get("profile") == selected,
                    "a5 配置未独立于缓存 a9 识别")
            check_plain(decoded, TEXT.encode())
    explicit_wrong = client.request("/decrypt", {"mtgsig": mixed, "signing_profile": "legacy"})
    require(explicit_wrong.get("fields", {}).get("a5", {}).get("decryptable") is False,
            "显式错误 signing_profile 未被拒绝")
    report("通过：当前 a5 与缓存 legacy a9 独立识别，错误 signing_profile 拒绝")

    wrong = client.request("/decrypt", {"mtgsig": {"a1": A1,
                                                    "a9": ciphertexts["legacy", "aes"]},
                                         "profile": "default"})
    rejected = wrong.get("fields", {}).get("a9", {})
    require(rejected.get("decryptable") is False and
            "plain_b64" not in rejected and "plain_text" not in rejected,
            "错误配置未被拒绝")
    report("通过：a5、本体/字符串完整 mtgsig，以及错误配置拒绝")

    fp_plain = b'{"m1":"rpc-smoke","synthetic":true}'
    pad = 16 - len(fp_plain) % 16
    for key in (b"meituan1sankuai0", b"34281a9dw2i701d4"):
        fp = AES.new(key, AES.MODE_CBC, codec.IV).encrypt(fp_plain + bytes([pad]) * pad)
        result = client.request("/fingerprint/decrypt",
                                {"fingerprint": base64.b64encode(fp).decode("ascii")})
        check_plain(result, fp_plain)
    # Verify the I-series B-line encoder as well as decryption.  This uses a
    # small synthetic object so the deployment check never sends captured
    # identity material.
    fp_obj = {"I17": "rpc-smoke", "I18": "synthetic"}
    encoded_fp = client.request("/fingerprint/encrypt", {"plain_obj": fp_obj})
    require(isinstance(encoded_fp.get("fingerprint"), str)
            and encoded_fp.get("key_used") == "34281a9dw2i701d4",
            "fingerprint I-series 加密响应异常")
    result = client.request("/fingerprint/decrypt", encoded_fp)
    check_plain(result, json.dumps(fp_obj, separators=(",", ":"), ensure_ascii=False).encode())
    report("通过：fingerprint 两种已知格式自动解密及 I-series 加密")

    # Retain the pre-SDK explicit AES interface compatibility check.
    env_plain = {"m153": "rpc-smoke", "m162": "synthetic"}
    env_key = "0123456789abcdef"
    env_iv = "0102030405060708"
    env_session = "hex:6af9acba772fc9ff3243c59b4e0fbbc3"
    encoded_env = client.request("/envelope/encode", {
        "session_material": env_session,
        "plaintext": env_plain,
        "key": env_key,
        "iv": env_iv,
    })
    require(isinstance(encoded_env.get("envelope"), str)
            and encoded_env.get("part1_bytes") == 128
            and encoded_env.get("part2_bytes", 0) > 0,
            "envelope 编码响应异常")
    decoded_env = client.request("/envelope/decode", {
        "envelope": encoded_env["envelope"],
        "key": env_key,
        "iv": env_iv,
    })
    check_plain(decoded_env, json.dumps(env_plain, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8"))
    report("通过：envelope 显式 key/IV 编解码")

    # Validate the recovered SDK route with known synthetic session keys.
    # Repeated text avoids the native SDK's short compression buffer bug.
    env_plain = {"synthetic": True, "sample": "abcd" * 64}
    env_text = json.dumps(env_plain, separators=(",", ":")).encode()
    session_key = bytes(range(16))
    material = envelope_codec.derive_session_material(session_key, A1)
    for mode in codec.MODES:
        expected = envelope_codec.encode_sdk(env_text, A1, session_key=session_key, mode=mode)
        encoded = client.request("/envelope/encode", {
            "a1": A1, "plain_json": env_plain, "session_key_hex": session_key.hex(), "mode": mode,
        })
        require(encoded.get("envelope") == expected and encoded.get("codec") == "sdk"
                and encoded.get("session_key_generated") is False,
                "SDK envelope 加密与本地预期不一致")
        for field, value in (("session_key_hex", session_key.hex()),
                             ("session_material_hex", material.hex())):
            decoded = client.request("/envelope/decode", {
                "a1": A1, "envelope": expected, field: value,
            })
            check_plain(decoded, env_text)
            require(decoded.get("mode") == mode and decoded.get("rsa_verified") is True,
                    "SDK envelope 解密未通过 RSA 核对或模式识别")
    generated = client.request("/envelope/encode", {"a1": A1, "plain_json": env_plain})
    require(generated.get("session_key_generated") is True
            and isinstance(generated.get("session_key_hex"), str)
            and len(generated["session_key_hex"]) == 32,
            "SDK envelope 自动生成会话 key 未返回可复用结果")
    decoded = client.request("/envelope/decode", {
        "a1": A1, "envelope": generated["envelope"],
        "session_key_hex": generated["session_key_hex"],
    })
    check_plain(decoded, env_text)
    report("通过：envelope SDK 三种算法、已知会话材料解密及自动生成 key")

    if sample is not None:
        mt, expected = sample
        result = client.request("/decrypt", {"mtgsig": mt, "profile": profile})
        decoded = result.get("fields", {}).get("a9", {})
        require(decoded.get("decryptable") is True, "实际样本 a9 解密失败")
        actual = plain_bytes(decoded)
        equal = actual == expected
        if not equal:
            try:
                equal = json.loads(actual) == json.loads(expected)
            except (ValueError, UnicodeError):
                pass
        require(equal, "实际样本明文与预期文件不一致")
        report("通过：实际样本 a9 与预期明文内容一致（未输出明文或标识）")
    report(f"验收成功：{client.requests} 个 HTTP 请求全部通过")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="RPC 基础地址，可带路径前缀")
    parser.add_argument("--token-env", help="保存 X-Token 的环境变量名")
    parser.add_argument("--timeout", type=float, default=8, help="每请求超时秒数，最多 10")
    parser.add_argument("--sample", help="可选：包含 a1/a9 的本地样本 JSON")
    parser.add_argument("--expected-plaintext", help="样本预期明文文件；JSON 允许格式差异")
    parser.add_argument("--profile", choices=("default", "legacy"), default="default",
                        help="仅用于实际样本，合成检查始终覆盖两种配置")
    args = parser.parse_args(argv)
    try:
        require(bool(args.sample) == bool(args.expected_plaintext),
                "--sample 与 --expected-plaintext 必须同时提供")
        token = None
        if args.token_env:
            token = os.environ.get(args.token_env)
            require(bool(token), "指定的认证环境变量未设置或为空")
        client = Client(args.url, token=token, timeout=args.timeout)
        sample = load_sample(args.sample, args.expected_plaintext) if args.sample else None
        run_checks(client, sample=sample, profile=args.profile)
        return 0
    except SmokeFailure as exc:
        print(f"验收失败：{exc}", file=sys.stderr)
    except Exception as exc:
        # Do not leak request, server response, key, token or captured plaintext
        # through a third-party exception's repr/traceback.
        print(f"验收失败：本地检查异常（{type(exc).__name__}）", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""用账号自己的 passport 请求模板及本地签名检查登录身份。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from farm.fullsign import FullSigner
from farm.registry import account_front_proxy, account_proxy, curl_proxy_args
from farm.proxy import ProxyRoute

CHECK_HOST = "passport-eu.mykeeta.com"
CHECK_PATH = "/api/user/v1/info/homepage"


def assess_response(http_status, response, expected_user_id):
    """HTTP 200 不代表有效账号；成功响应须包含同一账号的 user.idStr。"""
    result = {"valid": False, "http_status": http_status}
    if http_status != 200:
        return dict(result, reason="http_error")
    if not isinstance(response, dict):
        return dict(result, reason="non_json_object")
    if response.get("error") or ("code" in response and response["code"] != 0):
        return dict(result, reason="business_error")
    user = response.get("user")
    if not isinstance(user, dict):
        return dict(result, reason="missing_user")
    user_id = user.get("idStr")
    if not isinstance(user_id, str) or not user_id.isascii() or not user_id.isdigit() or int(user_id) <= 0:
        return dict(result, reason="missing_user_id")
    if "id" in user and (type(user["id"]) is not int or str(user["id"]) != user_id):
        return dict(result, reason="inconsistent_user_id")
    if not expected_user_id:
        return dict(result, reason="missing_expected_user_id")
    if user_id != str(expected_user_id):
        return dict(result, reason="account_mismatch")
    return dict(result, valid=True, reason="verified", user_id=user_id)


def save_private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else (
        json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    fd, stage = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        os.replace(stage, path)
    finally:
        if os.path.exists(stage):
            os.unlink(stage)


def check_account(account_dir):
    account_dir = Path(account_dir).resolve()
    proxy = account_proxy(account_dir)
    request = json.loads((account_dir / "account_check_request.json").read_text())
    identity = json.loads((account_dir / "identity.json").read_text())
    parsed = urlsplit(request["url"])
    if (request.get("method") != "GET" or request.get("body") or
            parsed.scheme != "https" or parsed.hostname != CHECK_HOST or
            parsed.path != CHECK_PATH or parsed.username or parsed.password or
            parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError("account check requires the captured passport GET endpoint")
    headers = {k.lower(): v for k, v in request["headers"].items()}
    if not identity.get("token") or headers.get("token") != identity["token"]:
        raise ValueError("account check template token does not match this account")
    if headers.get("host") != CHECK_HOST:
        raise ValueError("account check template Host does not match its URL")
    if any(not isinstance(v, str) or any(c in k + v for c in "\r\n")
           for k, v in headers.items()):
        raise ValueError("invalid account check header")
    signer = FullSigner(account_dir / "device_id.json")
    headers["mtgsig"] = signer.sign("GET", request["url"], "")
    # 先落盘序号；即使连接失败或进程中断，下次也不重复本次序号。
    save_private(account_dir / "device_id.json", dict(
        signer.dev, counter=signer.counter, sign_sequence=signer.counter,
        signature_counter=signer.signature_counter))
    front_proxy = account_front_proxy(account_dir)
    with ProxyRoute(proxy, front_proxy) as route_proxy:
        with tempfile.TemporaryDirectory(prefix="keeta-account-check-") as temp:
            temp = Path(temp)
            header_path, response_path = temp / "headers", temp / "response"
            header_path.write_text("".join(
                (k + ": " + v if v else k + ";") + "\n"
                for k, v in headers.items()))
            proc = subprocess.run([
                "curl", "-q", "--silent", "--show-error", "--compressed",
                "--connect-timeout", "8", "--max-time", "22", "--request", "GET",
                "--header", "@" + str(header_path), "--output", str(response_path),
                "--write-out", "%{http_code}",
            ] + curl_proxy_args(route_proxy) + [request["url"]], capture_output=True, text=True, timeout=25)
            raw = response_path.read_bytes() if response_path.exists() else b""
    try:
        response = json.loads(raw)
    except ValueError:
        response = None
    status = int(proc.stdout.strip()) if proc.stdout.strip().isdigit() else 0
    result = assess_response(status, response, identity.get("userid"))
    if proc.returncode:
        result.update(valid=False, reason="transport_error")
    result.update(account=account_dir.name, checked_at=datetime.now(timezone.utc).isoformat(),
                  curl_exit=proc.returncode, endpoint=CHECK_PATH,
                  proxy_configured=bool(route_proxy), front_proxy_configured=bool(front_proxy))
    save_private(account_dir / "validation/account-check-latest.response.json", raw)
    save_private(account_dir / "account_check_latest.json", result)
    if result["valid"]:
        user = response["user"]
        save_private(account_dir / "account.json", {
            "account": account_dir.name, "user_id": result["user_id"],
            "username": user.get("username"), "email": user.get("email"),
            "register_region": user.get("registerRegion"),
            "verified_at": result["checked_at"], "verification_endpoint": CHECK_PATH,
        })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account-dir", type=Path, required=True,
                        help="含本账号 account_check_request.json 的工作区")
    args = parser.parse_args()
    try:
        result = check_account(args.account_dir)
    except Exception as exc:
        # 异常字符串可能携带 URL 或认证材料，终端只输出异常类型。
        print(json.dumps({"valid": False, "error_type": type(exc).__name__}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

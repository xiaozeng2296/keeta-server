"""Keeta 邮箱协议构造与顺序执行。

请求字段与响应路径来自 mtgsig.login_protocol 的静态恢复。抓包提供区域 URL、
公共 query/header/body 上下文；risk 模板足以构造 apply/submit，不要求成功抓包。
显式 overrides 接受旧 camelCase 入参，最终请求始终使用 snake_case。
不会从历史模板继承 userTicket、serialNumber、emailCode 或挑战结果。

本模块不生成完整新设备画像。device_id 是 IDFA，不回退到 IDFV；调用方需提供
本次 fingerprint/签名及公共上下文。离线构造不是服务端注册成功的证明。
"""
import argparse
import json
import os
from pathlib import Path
import stat
import time
import urllib.parse

import requests
import mailbox as MB
from mtgsig import login_protocol as protocol

PSEUDO = {":method", ":scheme", ":path", ":authority"}
DROP_HDR = {"content-length", "host", "mtgsig", "accept-encoding"}
CAPTURE_CREDENTIAL_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "token",
    "incog-token", "incog-accountid", "csecuserid", "userid",
}
SEG = {
    "risk": "emaillogin/v1/userriskcheck",
    "signup_apply": "emaillogin/v1/emailsignupapply",
    "login_apply": "emaillogin/v1/emailloginapply",
    "signup": "emaillogin/v1/emailsignup",
    "login": "emaillogin/v1/emaillogin",
}
PATHS = {"risk": protocol.RISK_PATH, "signup_apply": protocol.SIGNUP_APPLY_PATH,
         "login_apply": protocol.LOGIN_APPLY_PATH, "signup": protocol.SIGNUP_PATH,
         "login": protocol.LOGIN_PATH}
ALIASES = {"userTicket": "user_ticket", "serialNumber": "serial_number",
           "emailCode": "email_code", "requestCode": "request_code",
           "responseCode": "response_code"}


def load_templates(chlsj):
    """Extract exact paths; an apply request must not also become a submit template."""
    from keeta_offline_flow import capture_authority

    with open(chlsj, encoding="utf-8") as f:
        flows = json.load(f)
    tpl = {}
    for flow in flows:
        req = flow.get("request")
        if not req:
            continue
        raw_headers = req.get("header", {}).get("headers", [])
        path = flow.get("path") or ""
        pseudo = next((h["value"] for h in raw_headers if h["name"] == ":path"), "")
        parsed = urllib.parse.urlsplit(pseudo or path)
        for name, suffix in SEG.items():
            if parsed.path.endswith("/" + suffix) and name not in tpl:
                headers = {h["name"]: h["value"] for h in raw_headers
                           if h["name"] not in PSEUDO
                           and h["name"].lower() not in DROP_HDR | CAPTURE_CREDENTIAL_HEADERS}
                tpl[name] = {"name": name, "host": capture_authority(flow), "path": parsed.path,
                             "query": parsed.query or flow.get("query", ""), "headers": headers,
                             "body": (req.get("body") or {}).get("text", "")}
    return tpl


def _body_fields(body):
    if not body:
        return {}
    if body.lstrip().startswith(("{", "[")):
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            raise ValueError("passport body must be an object")
        return parsed
    return dict(urllib.parse.parse_qsl(body, keep_blank_values=True))


def set_field(body, key, val):
    """Legacy generic body utility; protocol constructors use named model fields."""
    fields = _body_fields(body)
    fields[key] = val
    if body and body.lstrip().startswith("{"):
        return json.dumps(fields, ensure_ascii=False)
    return urllib.parse.urlencode(fields)


def get_field(body, key):
    return _body_fields(body).get(key)


def _signed_value(signer, url, body):
    """Normalize device sign(method,url,body) and offline sign(url,body) APIs."""
    if signer is None:
        return None
    try:
        result = signer.sign("POST", url, body)
    except TypeError:
        result = signer.sign(url, body)
    return result[0] if isinstance(result, tuple) else result


def _overrides(values):
    result = {}
    for key, value in (values or {}).items():
        canonical = ALIASES.get(key, key)
        if canonical in result and result[canonical] != value:
            raise ValueError(f"conflicting aliases for {canonical}")
        result[canonical] = value
    return result


def _segment_name(seg):
    if seg.get("name") in SEG:
        return seg["name"]
    path = urllib.parse.urlsplit(seg["path"]).path
    return next((name for name, suffix in SEG.items() if path.endswith("/" + suffix)), None)


def _request_body(seg, email, overrides):
    name = _segment_name(seg)
    if name is None:
        raise ValueError("unknown email protocol segment")
    captured = _body_fields(seg.get("body", ""))
    values = _overrides(overrides)
    if values.get("password") is not None and values.get("encrypted_password") is not None:
        raise ValueError("supply plaintext password or encrypted_password, not both")
    # Only these common fields survive template migration. No IDFV fallback.
    common = {key: values.get(key, captured.get(key))
              for key in ("device_id", "tk_context_plain", "fingerprint")}
    if name == "risk":
        return protocol.build_risk_body(
            email if email is not None else values.get("email"),
            request_code=values.get("request_code"), response_code=values.get("response_code"),
            token_id=values.get("token_id", captured.get("token_id", "")), common=common)
    kwargs = {"signup": name.startswith("signup"), "common": common}
    if kwargs["signup"]:
        # The successful native signup sends these two keys as empty strings.
        # Defaults belong to this orchestration layer; protocol None still
        # means omit, and captured account fields are never inherited.
        kwargs["username"] = values.get("username", "")
        if values.get("encrypted_password") is not None:
            kwargs["encrypted_password"] = values["encrypted_password"]
        elif "password" in values:
            kwargs["password"] = values["password"]
        else:
            kwargs["encrypted_password"] = values.get("encrypted_password", "")
    ticket = values.get("user_ticket")
    if name.endswith("_apply"):
        return protocol.build_apply_body(ticket, **kwargs)
    return protocol.build_submit_body(
        ticket, values.get("email_code"), values.get("serial_number"),
        request_code=values.get("request_code"), response_code=values.get("response_code"), **kwargs)


def plan_segment(seg, email=None, overrides=None, signer=None):
    """Construct a model-derived request without HTTP/mailbox access.

    Explicit legacy camelCase override names are accepted, but captured state
    values are not reused. Construction/signing errors remain visible in plan.
    A supplied device-backed signer can itself contact the device.
    """
    result = {"segment": _segment_name(seg), "signed": False}
    try:
        body = _request_body(seg, email, overrides)
        headers = protocol.passport_headers({k: v for k, v in (seg.get("headers") or {}).items()
                                             if k not in PSEUDO and k.lower() not in DROP_HDR})
        query = seg.get("query", "")
        url = f"https://{seg['host']}{seg['path']}" + (f"?{query}" if query else "")
        result.update(method="POST", url=url, headers=headers, body=body)
    except (KeyError, TypeError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    if signer is not None:
        try:
            signed = _signed_value(signer, url, body)
            if not isinstance(signed, str) or not signed:
                raise ValueError("missing signature")
            headers["mtgsig"] = signed
            result["signed"] = True
        except Exception as exc:
            result["sign_error"] = f"{type(exc).__name__}: {exc}"
    return result


def _segment(tpl, name):
    """Reuse regional context; model constructors supply uncaptured endpoints."""
    if name in tpl:
        return dict(tpl[name], name=name)
    if "risk" not in tpl:
        raise ValueError("抓包缺 userriskcheck 上下文")
    return dict(tpl["risk"], name=name, path=PATHS[name])


def plan_signup_flow(tpl, email, *, user_ticket=None, serial_number=None,
                     email_code=None, request_code=None, response_code=None,
                     signer=None, signup=None, username=None, password=None,
                     encrypted_password=None, common=None):
    """Render risk/apply/verify with explicitly supplied current state.

    signup=None preserves template-based branch selection for old callers.
    Execution must instead select from the new risk response. Missing state
    yields an error and stops; no historical ticket/code fallback is allowed.
    """
    if "risk" not in tpl:
        return [{"segment": "risk", "error": "抓包缺 userriskcheck 上下文"}]
    if signup is None:
        signup = "signup_apply" in tpl or "login_apply" not in tpl
    if type(signup) is not bool:
        raise ValueError("signup must be bool")
    values = dict(common or {})
    values.update(user_ticket=user_ticket, serial_number=serial_number, email_code=email_code,
                  request_code=request_code, response_code=response_code)
    for key, value in (("username", username), ("password", password),
                       ("encrypted_password", encrypted_password)):
        if value is not None:
            values[key] = value
    if password is not None and encrypted_password is not None:
        raise ValueError("supply plaintext password or encrypted_password, not both")
    names = ["risk", "signup_apply" if signup else "login_apply", "signup" if signup else "login"]
    out = []
    for name in names:
        item = plan_segment(_segment(tpl, name), email=email, overrides=values, signer=signer)
        out.append(item)
        if "error" in item or "sign_error" in item:
            break
    return out


def dig(obj, *keys):
    """Legacy inspection utility; execution never uses recursive success lookup."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in keys and isinstance(value, (str, int)):
                return value
            found = dig(value, *keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = dig(item, *keys)
            if found is not None:
                return found
    return None


def send(signer, seg, email=None, overrides=None, proxies=None):
    """Build the final form, sign it once, then POST; no stale state fallback."""
    request = plan_segment(seg, email=email, overrides=overrides, signer=signer)
    if "error" in request or not request["signed"]:
        raise ValueError(request.get("error") or request.get("sign_error") or "缺少签名器")
    response = requests.post(request["url"], headers=request["headers"],
                             data=request["body"].encode("utf-8"), timeout=25, proxies=proxies)
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, response.text[:300]


def _token_at(response, http_status, token_path=None, *, expected_email=None):
    """Read the verified user token; legacy paths cannot bypass user validation."""
    account = protocol.parse_submit_response(
        response, http_status=http_status, expected_email=expected_email)
    if not account:
        return None
    if token_path is None:
        return account["token"]
    node = response
    for key in token_path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return account["token"] if isinstance(node, str) and node == account["token"] else None


def run_one(signer, tpl, email, path, proxies=None, poll=120, *, username=None,
            password=None, common=None, request_code=None, response_code=None,
            token_path=None):
    """Risk -> response-selected apply -> code -> submit, with strict transitions.

    The recovered user model must authenticate this email before success.
    An optional legacy token_path must resolve to that same verified token.
    """
    if "risk" not in tpl:
        print("  风控步骤缺请求上下文")
        return None
    values = dict(common or {})
    values.update(request_code=request_code, response_code=response_code)
    status, risk = send(signer, _segment(tpl, "risk"), email=email, overrides=values, proxies=proxies)
    state = protocol.parse_risk_response(risk, http_status=status)
    if not state:
        print(f"  风控未返回有效票据，HTTP {status}；停止")
        return None
    signup = state["is_signup"]
    apply_name, submit_name = ("signup_apply", "signup") if signup else ("login_apply", "login")
    values["user_ticket"] = state["user_ticket"]
    if signup:
        if username is not None:
            values["username"] = username
        if password is not None:
            # Keep the same encrypted password across the two registration steps.
            values["encrypted_password"] = protocol.encrypt_password(password)
    # Snapshot immediately before apply.  Applying before the snapshot leaves
    # a race in which an old mailbox code can be mistaken for this request.
    try:
        mailbox_before_apply = MB.snapshot_mailbox(email, path=path, search="Keeta")
    except Exception as exc:
        print(f"  发码前邮箱快照失败，停止 ({type(exc).__name__})")
        return None
    status, response = send(signer, _segment(tpl, apply_name), overrides=values, proxies=proxies)
    applied = protocol.parse_apply_response(response, http_status=status, expected_email=email)
    if not applied:
        print(f"  发码未返回本邮箱的有效序号，HTTP {status}；停止")
        return None
    print("  发码响应有效，等待验证码")
    code = MB.get_code(email, path=path, poll=poll, since=mailbox_before_apply)
    if not code:
        print("  未收到验证码；停止")
        return None
    values.update(email_code=code, serial_number=applied["serial_number"])
    status, response = send(signer, _segment(tpl, submit_name), overrides=values, proxies=proxies)
    token = _token_at(response, status, token_path, expected_email=email)
    if token:
        print("  已验证本邮箱的登录账号")
        return token
    print(f"  已提交，HTTP {status}；未验证账号 token，不能判为登录成功")
    return None


def _append_token(path, token):
    """Append account credentials with private creation and existing-file modes."""
    target = Path(path)
    for parent in reversed(target.parents):
        parent.mkdir(mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(target, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("token output must be a regular file")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as output:
            output.write(token + "\n")
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", required=True, help="区域与公共参数的 Charles 请求上下文")
    parser.add_argument("--mail", default="mail.txt")
    parser.add_argument("--email", help="仅执行此邮箱")
    parser.add_argument("--all", action="store_true", help="执行 mail.txt 中所有邮箱")
    parser.add_argument("--tokens-out", default="交付数据/tokens.txt")
    parser.add_argument("--proxies", help="HTTP 传输代理")
    parser.add_argument("--list-templates", action="store_true")
    parser.add_argument("--attach", action="store_true", help="attach 运行中的 App 签名器")
    parser.add_argument("--token-path", help="可选兼容路径，值必须与已验证的 user.token 一致")
    args = parser.parse_args()
    templates = load_templates(args.capture)
    print("抓包含链路段:", list(templates))
    if args.list_templates:
        for name, item in templates.items():
            print(f"[{name}] {item['host']}{item['path']}")
        return
    if "risk" not in templates:
        parser.error("抓包缺 userriskcheck 上下文")
    emails = [args.email] if args.email else [x["email"] for x in MB.load_accounts(args.mail)] if args.all else []
    if not emails:
        parser.error("指定 --email 或 --all")
    try:
        import keeta_client as KC
    except ImportError:
        parser.error("此 CLI 使用 keeta_client；离线签名器请传给 plan_signup_flow/run_one")
    proxies = {"http": args.proxies, "https": args.proxies} if args.proxies else None
    signer = KC.Signer(spawn=not args.attach)
    succeeded = 0
    try:
        for email in emails:
            token = run_one(signer, templates, email, args.mail, proxies=proxies,
                            token_path=tuple(args.token_path.split(".")) if args.token_path else None)
            if token:
                succeeded += 1
                _append_token(args.tokens_out, token)
            time.sleep(3)
    finally:
        signer.close()
    print(f"成功 {succeeded}/{len(emails)} 个")


if __name__ == "__main__":
    main()

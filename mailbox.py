#!/usr/bin/env python3
"""outlook 邮箱取件：mail.txt 的 refresh_token -> IMAP(XOAUTH2) 读收件箱 -> 提验证码。

mail.txt 每行：email----password----client_id----refresh_token
这批 token 授权范围是 IMAP(outlook.office.com/IMAP.AccessAsUser.All)，
不是 Graph，所以走 imaplib(stdlib) + XOAUTH2，无需 mail.chatai.codes。
显式 proxy 同时约束 OAuth HTTP 与 IMAP CONNECT，代理失败不会直连。
"""
import base64
import email
import imaplib
import re
import sys
import time
from email.header import decode_header
import requests

TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
IMAP_HOST = "outlook.office365.com"
CODE_RE = re.compile(r"\b(\d{4,8})\b")  # ponytail: 通用数字码; 若误抓改成 Keeta 专用上下文


def get_token(client_id, refresh_token, *, proxy=None, http_session=None):
    """refresh_token 换 IMAP access_token。返回 (access_token, new_refresh_token)。"""
    data = {
        "client_id": client_id,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": SCOPE,
    }
    if proxy is not None:
        from mtgsig.http_transport import configure_http_session
        if http_session is None:
            with requests.Session() as session:
                configure_http_session(session, proxy)
                return get_token(client_id, refresh_token, http_session=session)
        configure_http_session(http_session, proxy)
    transport = http_session if http_session is not None else requests
    r = transport.post(TOKEN_URL, data=data, timeout=30)
    r.raise_for_status()
    j = r.json()
    return j["access_token"], j.get("refresh_token", refresh_token)


def imap_login(email_addr, access_token, *, proxy=None):
    """XOAUTH2 登录，返回只读 select INBOX 的 IMAP4_SSL 连接。"""
    auth = f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01"
    if proxy is None:
        conn = imaplib.IMAP4_SSL(IMAP_HOST, timeout=30)
    else:
        from mtgsig.mail_transport import ProxyIMAP4SSL
        conn = ProxyIMAP4SSL(IMAP_HOST, proxy=proxy, timeout=30)
    try:
        conn.authenticate("XOAUTH2", lambda _: auth.encode())
        typ, _ = conn.select("INBOX", readonly=True)
        if typ != "OK":
            raise RuntimeError("IMAP INBOX selection failed")
    except Exception:
        try:
            conn.logout()
        except Exception:
            pass
        raise
    return conn


def _decode(s):
    if not s:
        return ""
    return "".join(
        (b.decode(enc or "utf-8", "replace") if isinstance(b, bytes) else b)
        for b, enc in decode_header(s)
    )


def _body_text(msg):
    """取纯文本正文（优先 text/plain，退化到 text/html 去标签）。"""
    parts = msg.walk() if msg.is_multipart() else [msg]
    html = ""
    for p in parts:
        ct = p.get_content_type()
        if ct == "text/plain":
            return p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8", "replace")
        if ct == "text/html" and not html:
            html = p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8", "replace")
    return re.sub(r"<[^>]+>", " ", html)


def fetch_messages(conn, top=10, search=None):
    """返回最新 top 封 {subject, from, date, text}，按新到旧。search 命中主题或正文。"""
    if search:
        crit = ["OR", "SUBJECT", f'"{search}"', "TEXT", f'"{search}"']
    else:
        crit = ["ALL"]
    typ, data = conn.search(None, *crit)
    ids = data[0].split()[-top:][::-1]
    out = []
    for i in ids:
        typ, raw = conn.fetch(i, "(RFC822)")
        msg = email.message_from_bytes(raw[0][1])
        out.append({
            "subject": _decode(msg.get("Subject")),
            "from": _decode(msg.get("From")),
            "date": msg.get("Date", ""),
            "text": _body_text(msg),
        })
    return out


def _search_criteria(search):
    """Return IMAP search arguments shared by sequence and UID searches."""
    if search:
        return ("OR", "SUBJECT", f'"{search}"', "TEXT", f'"{search}"')
    return ("ALL",)


def _uid_validity(conn):
    """Read the selected mailbox UIDVALIDITY, when the server exposes it."""
    values = getattr(conn, "untagged_responses", {}).get("UIDVALIDITY", [])
    if isinstance(values, (bytes, str)):
        values = [values]
    for value in values or ():
        if isinstance(value, bytes):
            value = value.decode("ascii", "ignore")
        match = re.search(r"\d+", str(value))
        if match:
            return int(match.group(0))
    return None


def _search_uids(conn, search=None):
    """Search the selected mailbox using stable IMAP UIDs."""
    typ, data = conn.uid("search", None, *_search_criteria(search))
    if typ != "OK":
        raise RuntimeError("IMAP UID search failed")
    raw = data[0] if data else b""
    if isinstance(raw, str):
        raw = raw.encode("ascii", "ignore")
    return [int(item) for item in raw.split() if item.isdigit()]


def _account(email_addr, path):
    acc = next((a for a in load_accounts(path)
                if a["email"].lower() == email_addr.lower()), None)
    if not acc:
        raise ValueError("requested mailbox is not in the account file")
    return acc


def snapshot_mailbox(email_addr, path="mail.txt", search="Keeta", *, proxy=None,
                     http_session=None):
    """Record all current INBOX UIDs before sending a code request.

    The returned object contains only mailbox position metadata.  It is safe
    to persist alongside a login attempt and does not contain access tokens,
    message bodies, subjects, or credentials.  Pass it as ``since`` to
    :func:`get_code` after the apply request so an old code cannot be reused.
    ``search`` is retained for caller compatibility, but the baseline always
    covers all mail so delayed search indexing cannot expose an old code.
    """
    acc = _account(email_addr, path)
    token_options = {'proxy': proxy, 'http_session': http_session} if proxy is not None or http_session is not None else {}
    access, _ = get_token(acc["client_id"], acc["refresh_token"], **token_options)
    conn = imap_login(acc["email"], access, **({'proxy': proxy} if proxy is not None else {}))
    try:
        uids = _search_uids(conn)
        return {
            "uidvalidity": _uid_validity(conn),
            "uids": sorted(set(uids)),
            "highest_uid": max(uids, default=0),
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _fetch_uid_message(conn, uid):
    typ, data = conn.uid("fetch", str(uid), "(BODY.PEEK[])")
    if typ != "OK":
        return None
    raw = next((part[1] for part in (data or ())
                if isinstance(part, tuple) and len(part) > 1
                and isinstance(part[1], bytes)), None)
    if raw is None:
        return None
    msg = email.message_from_bytes(raw)
    return {
        "uid": int(uid),
        "subject": _decode(msg.get("Subject")),
        "from": _decode(msg.get("From")),
        "date": msg.get("Date", ""),
        "text": _body_text(msg),
    }


def fetch_new_messages(conn, since, top=10, search="Keeta"):
    """Fetch matching UIDs beyond the pre-apply INBOX high-water mark.

    UIDVALIDITY changes invalidate an old snapshot rather than silently
    treating every existing message as new.  A missing UIDVALIDITY is allowed
    for small/fake IMAP servers that do not advertise the response code.
    """
    if not isinstance(since, dict):
        raise TypeError("since must be a snapshot_mailbox result")
    expected = since.get("uidvalidity")
    current = _uid_validity(conn)
    if expected is not None and current is not None and expected != current:
        raise RuntimeError("IMAP mailbox UIDVALIDITY changed; take a new snapshot")
    baseline = set()
    for value in since.get("uids", ()):
        try:
            baseline.add(int(value))
        except (TypeError, ValueError):
            raise ValueError("invalid mailbox snapshot UID") from None
    try:
        highest_uid = int(since.get("highest_uid", max(baseline, default=0)))
    except (TypeError, ValueError):
        raise ValueError("invalid mailbox snapshot highest UID") from None
    if highest_uid < max(baseline, default=0):
        raise ValueError("mailbox snapshot highest UID precedes baseline")
    # UID monotonicity also excludes old mail whose search index was delayed
    # and therefore absent from an earlier keyword-filtered result.
    fresh = [uid for uid in _search_uids(conn, search)
             if uid > highest_uid and uid not in baseline]
    out = []
    for uid in reversed(sorted(fresh)):
        message = _fetch_uid_message(conn, uid)
        if message is not None:
            out.append(message)
            if len(out) >= top:
                break
    return out


def extract_code(msg):
    """从主题+正文提第一个 4-8 位数字码。"""
    m = CODE_RE.search(f"{msg.get('subject','')} {msg.get('text','')}")
    return m.group(1) if m else None


def parse_line(line):
    parts = line.strip().split("----")
    if len(parts) < 4:
        return None
    return {"email": parts[0], "password": parts[1], "client_id": parts[2], "refresh_token": parts[3]}


def load_accounts(path="mail.txt"):
    with open(path, encoding="utf-8") as f:
        return [a for a in (parse_line(l) for l in f if l.strip()) if a]


def get_code(email_addr, path="mail.txt", search="Keeta", top=10, poll=0,
             interval=5, since=None, *, proxy=None, http_session=None):
    """按邮箱取验证码。

    ``since`` 应传给 :func:`snapshot_mailbox` 在发码前生成的快照；传入
    后只接受快照之后出现的 UID，避免把邮箱中的旧验证码误用于本次登录。
    未传 ``since`` 时保留旧的“取最新匹配邮件”兼容行为。
    ``poll>0`` 时轮询等新码到达（秒）。返回 code 或 None。
    """
    acc = _account(email_addr, path)
    token_options = {'proxy': proxy, 'http_session': http_session} if proxy is not None or http_session is not None else {}
    access, _ = get_token(acc["client_id"], acc["refresh_token"], **token_options)
    conn = imap_login(acc["email"], access, **({'proxy': proxy} if proxy is not None else {}))
    try:
        deadline = time.time() + poll
        while True:
            messages = (fetch_new_messages(conn, since, top=top, search=search)
                        if since is not None else
                        fetch_messages(conn, top=top, search=search))
            for msg in messages:
                code = extract_code(msg)
                if code:
                    return code
            if time.time() >= deadline:
                return None
            time.sleep(interval)
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def demo():
    """离线自检：解析 + 提码逻辑，不联网。"""
    a = parse_line("foo@outlook.com----pw123----cid-uuid----M.C500_BAY.token")
    assert a["email"] == "foo@outlook.com" and a["refresh_token"] == "M.C500_BAY.token", a
    assert parse_line("bad line") is None
    assert extract_code({"subject": "Keeta code: 481902", "text": ""}) == "481902"
    assert extract_code({"subject": "hi", "text": "your PIN is 5566 thanks"}) == "5566"
    assert extract_code({"subject": "no digits", "text": "hello"}) is None
    print("demo ok")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python mailbox.py <email> [search|all] [poll_seconds]")
        print("     python mailbox.py --demo")
        sys.exit(0)
    if sys.argv[1] == "--demo":
        demo()
        sys.exit(0)
    email_addr = sys.argv[1]
    search = sys.argv[2] if len(sys.argv) > 2 else "Keeta"
    poll = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    code = get_code(email_addr, search=(None if search in ("-", "all") else search), poll=poll)
    print(code or "(未找到验证码)")

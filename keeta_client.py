"""Keeta 店铺接口 Python 客户端 —— 设备端 frida RPC 签 mtgsig,直接请求业务接口。

链路:
  1) frida spawn/attach Keeta(rootless 越狱靠 `jbctl proc_set_debugged <pid>` 放行 agent 注入);
  2) 加载 keeta_sign_rpc.js,调 Keeta 自身 +[SAKRequestSignatureProcessor signaturedWithMutableURLRequest:] 签名;
  3) 用 chlsj 里的真实请求当模板(token/uuid/静态头复用),只换 body(shopId 等) + 新 mtgsig,发出去。

前置:
  - 配置 SSH Host keeta-device（或 KEETA_DEVICE_SSH_TARGET），指向测试设备。
  - 安装与设备 frida-server 匹配的 Frida Python 包。

用法:
  python3 keeta_client.py --self-test                 # 用 captured body 原样签+发,验证链路
  python3 keeta_client.py --shop 159480097            # 取任意店铺 shopInfo
  python3 keeta_client.py --path /api/v1/shop/productList --shop 159480097
  python3 keeta_client.py --spawn                      # 冷启动 Keeta 再签(默认 attach 运行中的)
"""
import argparse, json, os, subprocess, sys, time
import requests
import frida

HERE = os.path.dirname(os.path.abspath(__file__))
CHLSJ = os.environ.get("KEETA_CAPTURE", os.path.join(HERE, ".private", "template.chlsj"))
RPC_JS = os.path.join(HERE, "keeta_sign_rpc.js")
HOST = "fooddelivery-eu.mykeeta.com"
BID = "com.sankuai.sailor.ifooddelivery"
PSEUDO = {":method", ":scheme", ":path", ":authority"}
SSH = ["ssh", os.environ.get("KEETA_DEVICE_SSH_TARGET", "keeta-device")]


def jbctl_debug(pid):
    r = subprocess.run(SSH + [f"jbctl proc_set_debugged {pid}"], capture_output=True, text=True, timeout=15)
    return (r.stdout + r.stderr).strip()


# ---------- chlsj 模板 ----------
def load_flow(path):
    for f in json.load(open(CHLSJ, encoding="utf-8")):
        if f.get("host") == HOST and f["path"].split("?")[0] == path:
            return f
    sys.exit(f"chlsj 无 {path}")


def template(path):
    """返回 (full_path_with_query, headers_no_pseudo_no_mtgsig, body)。"""
    f = load_flow(path)
    fp, headers = None, {}
    for h in f["request"]["header"]["headers"]:
        n, v = h["name"], h["value"]
        if n == ":path":
            fp = v
        if n in PSEUDO or n.lower() == "mtgsig":
            continue
        headers[n] = v
    body = (f["request"].get("body") or {}).get("text", "")
    return fp, headers, body


# ---------- frida 注入 + 签名会话 ----------
class Signer:
    def __init__(self, spawn=False, init_wait=6, extra_js=None):
        self.dev = frida.get_usb_device(timeout=10)
        js = open(RPC_JS, encoding="utf-8").read()
        self.extra = None
        if spawn:
            for a in self.dev.enumerate_applications():
                if a.identifier == BID and a.pid:
                    try: self.dev.kill(a.pid); time.sleep(1)
                    except Exception: pass
            self.pid = self.dev.spawn([BID])
            print(f"[frida] spawned pid={self.pid}, jbctl:", jbctl_debug(self.pid), file=sys.stderr)
            self.session = self.dev.attach(self.pid)
            self.script = self._mk(js)
            if extra_js:                      # resume 前注入(如 IDFV hook 需早于采集)
                self.extra = self._mk(extra_js)
            self.dev.resume(self.pid)
            print(f"[frida] resumed, 等 {init_wait}s 初始化 SAKGuard...", file=sys.stderr)
            time.sleep(init_wait)
        else:
            self.pid = next((a.pid for a in self.dev.enumerate_applications()
                             if a.identifier == BID and a.pid), 0)
            if not self.pid:
                sys.exit("Keeta 未前台运行,用 --spawn 冷启动,或先在手机上打开 Keeta")
            print(f"[frida] attach 运行中 pid={self.pid}, jbctl:", jbctl_debug(self.pid), file=sys.stderr)
            self.session = self.dev.attach(self.pid)
            self.script = self._mk(js)

    def _mk(self, js):
        sc = self.session.create_script(js)
        sc.on("message", lambda m, d: print("[js]", m.get("payload") or m, file=sys.stderr)
              if m.get("type") == "error" or (m.get("payload") or {}).get("tag") != "ready" else None)
        sc.load()
        return sc

    def sign(self, method, url, body):
        r = self.script.exports_sync.sign(method, url, body or "")
        if r.get("err"):
            raise RuntimeError(f"签名失败: {r}")
        return r["mtgsig"]

    def close(self):
        try: self.session.detach()
        except Exception: pass


# ---------- 发请求(签名器可复用:一次 spawn 批量签发) ----------
# identity JSON -> 覆盖这些请求头（一整套自洽身份，来自 keeta_token_dump --out）
IDENT_HDRS = ["token", "incog-token", "uuid", "csecuuid", "userid", "csecuserid"]


def send_one(signer, path, body_mod=None, identity=None):
    fp, headers, body = template(path)
    if identity:
        for k in IDENT_HDRS:
            if identity.get(k):
                headers[k] = identity[k]
    if body_mod:
        body = body_mod(body)
    url = f"https://{HOST}{fp}"
    mtg = signer.sign("POST", url, body)
    headers["mtgsig"] = mtg
    r = requests.post(url, headers=headers, data=body.encode("utf-8"), timeout=20)
    try:
        j = r.json(); return r.status_code, j.get("code"), j.get("message"), j
    except Exception:
        return r.status_code, None, None, r.text[:300]


def show(tag, st, code, msg, data):
    print(f"\n[{tag}] HTTP {st}  code={code}  message={msg!r}")
    if code == 0 and isinstance(data, dict):
        d = data.get("data") or {}
        name = d.get("name") or d.get("shopName")
        print(f"  ✅ 通! 店铺={name}  shopId={d.get('shopId')}  data字段数={len(d) if isinstance(d,dict) else '-'}")
    else:
        print("  返回:", (json.dumps(data, ensure_ascii=False)[:300]) if isinstance(data, dict) else data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/api/v1/shop/shopInfo")
    ap.add_argument("--shop", help="替换 body 里的单个 shopId")
    ap.add_argument("--shops", help="逗号分隔多个 shopId,一次 spawn 全部签发(批量)")
    ap.add_argument("--spawn", action="store_true", help="冷启动 Keeta(默认;attach 运行中易被 iOS 挂起超时)")
    ap.add_argument("--attach", action="store_true", help="附着运行中的 Keeta(需前台活跃)")
    ap.add_argument("--self-test", action="store_true", help="用 captured body 原样签+发")
    ap.add_argument("--identity", help="identity JSON（keeta_token_dump --out），覆盖 token/uuid/userid 等头")
    a = ap.parse_args()

    ident = json.load(open(a.identity, encoding="utf-8")) if a.identity else None
    if ident:
        print(f"[identity] 覆盖头: userid={ident.get('userid')} uuid={(ident.get('uuid') or '')[:16]}…", file=sys.stderr)

    import re
    def mod(shop):
        return (lambda b: re.sub(r'"shopId":"\d+"', f'"shopId":"{shop}"', b)) if shop else None

    signer = Signer(spawn=not a.attach)   # 默认 spawn,更可靠
    try:
        if a.shops:
            for sid in [s.strip() for s in a.shops.split(",") if s.strip()]:
                show(f"{a.path} shop={sid}", *send_one(signer, a.path, mod(sid), ident))
        else:
            body_mod = None if a.self_test else mod(a.shop)
            show(f"{a.path} shop={a.shop or 'captured'}", *send_one(signer, a.path, body_mod, ident))
    finally:
        signer.close()


if __name__ == "__main__":
    main()

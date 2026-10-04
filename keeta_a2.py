"""Keeta mtgsig a2 纯离线实现(算法=国内 a2.go 同构,常量=Keeta 提取)。
- a2Mix: 9 轮 T 网络(Keeta T.bin)+ M 表(=国内 M.bin,字节级一致)
- a2Substitute: tableA/tableB(Keeta)
- pass1/pass2: 残差常量(KK=k1^k2buf, c9/c14/c15)从 oracle 样本反解
密钥:直接注入运行时捕获的 36B K(固定 counter),digest=HMAC-SHA1(K, canonical+body+payload)。
"""
import hmac, hashlib, struct, os, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
TDIR = os.path.join(HERE, "mtgsig", "data")
DOM = os.path.join(HERE, "mtgsig", "ref_domestic")

def _load():
    T = open(os.path.join(TDIR, "T.bin"), "rb").read()             # 144KB Keeta
    tableA = open(os.path.join(TDIR, "tableA.bin"), "rb").read()   # 4KB Keeta
    tableB = open(os.path.join(TDIR, "tableB_const.bin"), "rb").read()  # 768B Keeta
    M = open(os.path.join(DOM, "M.bin"), "rb").read()              # 1KB = 国内(已验证一致)
    assert len(T) == 147456 and len(tableA) == 4096 and len(tableB) == 768 and len(M) == 1024
    return T, M, tableA, tableB

tblT, tblM, tableA, tableB = _load()

def _u32le(b, off): return struct.unpack_from("<I", b, off)[0]
def mod16(x): return ((x % 16) + 16) % 16

def pMix(s):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[4*c+r] = s[4*((c+r) % 4)+r]
    return bytes(out)

def invpMix(out):
    """pMix 逆:out[4c+r]=s[4*((c+r)%4)+r] → 复原 s。"""
    s = bytearray(16)
    for c in range(4):
        for r in range(4):
            s[4*((c+r) % 4)+r] = out[4*c+r]
    return bytes(s)

def a2Mix(digest16):
    s = pMix(digest16)
    for r in range(9):
        tmp = bytearray(16)
        for c in range(4):
            word = 0
            for k in range(4):
                i = 4*c + k
                b = s[i]
                tv = _u32le(tblT, (r*4+c)*0x1000 + k*0x400 + b*4)
                t = r + i + b + 1
                u = r * i * b
                row = mod16(u - t)
                col = mod16(11*t + u)
                word ^= tv ^ _u32le(tblM, (row*16+col)*4)
            struct.pack_into(">I", tmp, 4*c, word & 0xffffffff)
        s = pMix(tmp)
    return s

def a2Substitute(s9):
    out = bytearray(16)
    for i in range(16):
        d = s9[i]
        t = i + d + 10
        hi = (t*0x44f + 9*i*d) % 16
        lo = (t*0x70b + 9*i*d) % 16
        out[i] = tableA[i*256 + d] ^ tableB[hi*16 + lo]
    return bytes(out)

def pctNonASCII(s):
    out = []
    for ch in s.encode("utf-8"):
        out.append(chr(ch) if ch < 0x80 else "%%%02X" % ch)
    return "".join(out)

def canonicalString(method, url):
    u = urllib.parse.urlparse(url)
    path = u.path or "/"
    items = []
    if u.query:
        for pair in u.query.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            items.append((k, v))
    items.sort(key=lambda kv: kv[0])
    parts = ["%s=%s" % (pctNonASCII(k), pctNonASCII(v)) for k, v in items]
    return method.upper() + " " + path + " " + "&".join(parts)

# Native 2.5 / SDK 5.21.10: observed at the message-copy boundary, including
# UTF-8 characters split at byte 16200. This limits signing input, not HTTP data.
SIGNING_BODY_LIMIT = 16200


def signing_message(method, url, body, payloadJSON=""):
    return (canonicalString(method, url).encode("utf-8")
            + (body or "").encode("utf-8")[:SIGNING_BODY_LIMIT]
            + payloadJSON.encode("utf-8"))


def digest_of(K, method, url, body, payloadJSON=""):
    msg = signing_message(method, url, body, payloadJSON)
    return hmac.new(bytes(K), msg, hashlib.sha1).digest()  # 20B

def a2_prefix(K, method, url, body, payloadJSON=""):
    """返回 (digest, sub) —— pass1/pass2 之前的确定部分。"""
    digest = digest_of(K, method, url, body, payloadJSON)
    s9 = a2Mix(digest[:16])
    sub = a2Substitute(s9)
    return digest, sub

# pass1: out1[i] = ((sub[i]+digest[i])&0xff) ^ KK[i]      (KK=k1^k2buf, 从样本反解 i=0..7)
# a2[0:8] = out1[0:8]  → KK[i] = a2[i] ^ ((sub[i]+digest[i])&0xff)
def solve_KK(samples):
    """samples: [(K,method,url,body,payload,a2hex)] → KK[0:8](若一致)。"""
    KK = [None]*8
    for (K, m, u, b, p, a2hex) in samples:
        a2 = bytes.fromhex(a2hex)
        digest, sub = a2_prefix(K, m, u, b, p)
        for i in range(8):
            v = a2[i] ^ ((sub[i] + digest[i]) & 0xff)
            if KK[i] is None: KK[i] = v
            elif KK[i] != v: return None, f"KK[{i}] 不一致 {KK[i]:02x} vs {v:02x}"
    return KK, "ok"

if __name__ == "__main__":
    import math
    from collections import Counter
    def ent(b):
        c = Counter(b); n = len(b)
        return -sum(v/n*math.log2(v/n) for v in c.values())
    print("表就绪: T %dB(ent%.3f) tableA %dB tableB %dB M %dB" %
          (len(tblT), ent(tblT), len(tableA), len(tableB), len(tblM)))
    # 自检:a2Mix/a2Substitute 在随机 digest 上不崩、输出 16B
    import os as _os
    dg = _os.urandom(20)
    s9 = a2Mix(dg[:16]); sub = a2Substitute(s9)
    assert len(s9) == 16 and len(sub) == 16
    print("self-check ok: s9=%s sub=%s" % (s9.hex(), sub.hex()))

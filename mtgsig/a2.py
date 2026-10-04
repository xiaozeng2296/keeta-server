"""Keeta mtgsig a2 纯离线实现(算法=国内 a2.go 同构,常量=Keeta 提取)。
- a2Mix: 9 轮 T 网络(Keeta T.bin)+ M 表(=国内 M.bin,字节级一致)
- a2Substitute: tableA/tableB(Keeta)
- pass1/pass2: 残差常量(KK=k1^k2buf, c9/c14/c15)从 oracle 样本反解
密钥:直接注入运行时捕获的 36B K(固定 counter),digest=HMAC-SHA1(K, canonical+body+payload)。
"""
import struct, os, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
TDIR = os.path.join(HERE, "data")
DOM = os.path.join(HERE, "ref_domestic")

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

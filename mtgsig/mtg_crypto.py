"""a5/fingerprint primitives and Twofish blocks for the shared offline codecs."""
import zlib, base64, struct, json



# B-line login fingerprint (the I-series JSON sent as the form field
# ``fingerprint``) is a separate fixed-key AES-CBC format.  It is not the
# compressed/custom a9 format below.  These defaults were byte-checked against
# the captured userriskcheck request and are overridable for other SDK builds.
FINGERPRINT_I_KEY = b"34281a9dw2i701d4"
FINGERPRINT_IV = b"0102030405060708"


def fingerprint_plain_bytes(plain) -> bytes:
    """Convert an I-series value to its exact UTF-8 JSON bytes.

    A string is treated as already serialized JSON so callers can preserve
    captured key order and number/string formatting.  Mapping/list values are
    serialized compactly with Unicode kept as UTF-8, matching the app wire
    representation.
    """
    if isinstance(plain, bytes):
        return plain
    if isinstance(plain, str):
        return plain.encode("utf-8")
    if isinstance(plain, (dict, list)):
        return json.dumps(plain, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    raise TypeError("fingerprint plaintext must be bytes, JSON text, object or array")


def fingerprint_encrypt(plain, key: bytes = FINGERPRINT_I_KEY,
                        iv: bytes = FINGERPRINT_IV) -> str:
    """Encode I-series login fingerprint as base64(AES- CBC + PKCS7).

    ``plain`` may be exact JSON text, bytes, or a dict/list.  The function
    returns the URL/form-safe standard base64 string used by ``fingerprint``.
    """
    from Crypto.Cipher import AES

    data = fingerprint_plain_bytes(plain)
    if isinstance(key, str):
        key = (bytes.fromhex(key) if len(key) == 32 and
               all(c in "0123456789abcdefABCDEF" for c in key)
               else key.encode("utf-8"))
    if isinstance(iv, str):
        iv = (bytes.fromhex(iv) if len(iv) == 32 and
              all(c in "0123456789abcdefABCDEF" for c in iv)
              else iv.encode("utf-8"))
    if len(iv) != AES.block_size:
        raise ValueError("fingerprint IV must be 16 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("fingerprint AES key must be 16, 24 or 32 bytes")
    pad = AES.block_size - (len(data) % AES.block_size)
    padded = data + bytes([pad]) * pad
    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(padded)).decode("ascii")


# ---------------- a5: RC4变体 + zlib ----------------
def rc4_variant(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    n = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % n] + i) & 0xff   # 变体 KSA: 多加了 + i
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for idx, c in enumerate(data):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[idx] = c ^ s[(s[i] + s[j]) & 0xff]
    return bytes(out)


def a5_derive_key(a1: str, a3: int, a4: int, k2buf: bytes) -> bytes:
    seed = f"{a1}{a3}{a4}".encode()
    return bytes(seed[i] ^ k2buf[i % 16] for i in range(len(seed)))


def a5_decrypt(a5_b64: str, a1: str, a3: int, a4: int, k2buf: bytes) -> bytes:
    key = a5_derive_key(a1, a3, a4, k2buf)
    return zlib.decompress(rc4_variant(key, base64.b64decode(a5_b64)))


def a5_encrypt(collect_json: bytes, a1: str, a3: int, a4: int, k2buf: bytes, level: int = 6) -> str:
    key = a5_derive_key(a1, a3, a4, k2buf)
    return base64.b64encode(rc4_variant(key, zlib.compress(collect_json, level))).decode()


# ---------------- a9: Feistel 分组密码 + CBC ----------------
A9_IV = b"0102030405060708"


class TwofishCipher:
    def __init__(self, schedule: bytes):
        if len(schedule) != 4256:
            raise ValueError("Twofish schedule requires 4256 bytes")
        self.v = list(struct.unpack("<1064I", schedule))

    def _tn(self, y):
        v = self.v
        return v[y & 0xff] ^ v[256 + ((y >> 8) & 0xff)] ^ v[512 + ((y >> 16) & 0xff)] ^ v[768 + ((y >> 24) & 0xff)]

    def _tef(self, x):  # 偶lane 首轮 E0: 无 ror
        return self._tn(x)

    def _te(self, x):   # 偶lane 后续 E1+: 先 ROR(x,1)
        return self._tn(_ror(x, 1))

    def _to(self, x):   # 奇lane: 字节轮换
        v = self.v
        return v[(x >> 24) & 0xff] ^ v[256 + (x & 0xff)] ^ v[512 + ((x >> 8) & 0xff)] ^ v[768 + ((x >> 16) & 0xff)]

    def _rk(self, i):
        return self.v[1024 + i]

    def enc_block(self, a):  # a: [4]uint32 明文 -> [4]uint32 密文
        M = 0xffffffff
        E = [a[0] ^ self._rk(0), (a[2] ^ self._rk(2) ^ (self._to(a[1] ^ self._rk(1)) + self._tef(a[0] ^ self._rk(0)) + self._rk(8))) & M]
        O = [a[1] ^ self._rk(1), (((self._tef(a[0] ^ self._rk(0)) + 2 * self._to(a[1] ^ self._rk(1)) + self._rk(9)) & M) ^ _ror((a[3] ^ self._rk(3)) & M, 31))]
        for m in range(2, 17):
            tfe = self._te(E[m - 1]); tfo = self._to(O[m - 1])
            xin = E[m - 2] if m == 2 else _ror(E[m - 2], 1)
            E.append(((tfo + tfe + self._rk(2 * m + 6)) & M) ^ xin)
            O.append(((tfe + 2 * tfo + self._rk(2 * m + 7)) & M) ^ _ror(O[m - 2], 31))
        return [(self._rk(4) ^ _ror(E[15], 1)) & M, (self._rk(5) ^ O[15]) & M,
                (self._rk(6) ^ _ror(E[16], 1)) & M, (O[16] ^ self._rk(7)) & M]

    def dec_block(self, out):  # 密文 -> 明文
        M = 0xffffffff
        E = [0] * 17; O = [0] * 17
        E[15] = _rol(out[0] ^ self._rk(4), 1); O[15] = out[1] ^ self._rk(5)
        E[16] = _rol(out[2] ^ self._rk(6), 1); O[16] = out[3] ^ self._rk(7)
        for m in range(16, 1, -1):
            tfe = self._te(E[m - 1]); tfo = self._to(O[m - 1])
            eterm = E[m] ^ ((tfo + tfe + self._rk(2 * m + 6)) & M)
            E[m - 2] = eterm if m == 2 else _ror(eterm, 31)
            O[m - 2] = _ror(O[m] ^ ((tfe + 2 * tfo + self._rk(2 * m + 7)) & M), 1)
        a = [0] * 4
        a[0] = E[0] ^ self._rk(0)
        a[1] = O[0] ^ self._rk(1)
        tfe0 = self._tef(E[0]); tfo0 = self._to(O[0])
        a[2] = E[1] ^ self._rk(2) ^ ((tfo0 + tfe0 + self._rk(8)) & M)
        a[3] = _ror((O[1] ^ ((tfe0 + 2 * tfo0 + self._rk(9)) & M)) & M, 1) ^ self._rk(3)
        return [x & M for x in a]

    def _cbc_dec(self, blob: bytes) -> bytes:
        out = bytearray(); prev = A9_IV
        for i in range(0, len(blob), 16):
            c = blob[i:i + 16]
            d = struct.pack("<4I", *self.dec_block(list(struct.unpack("<4I", c))))
            out += bytes(d[k] ^ prev[k] for k in range(16)); prev = c
        return bytes(out)

    def _cbc_enc(self, data: bytes) -> bytes:
        out = bytearray(); prev = A9_IV
        for i in range(0, len(data), 16):
            p = bytes(data[i + k] ^ prev[k] for k in range(16))
            c = struct.pack("<4I", *self.enc_block(list(struct.unpack("<4I", p))))
            out += c; prev = c
        return bytes(out)




def _ror(x, n): x &= 0xffffffff; return ((x >> n) | (x << (32 - n))) & 0xffffffff
def _rol(x, n): return _ror(x, 32 - n)

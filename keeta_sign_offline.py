"""Keeta 历史取样重签实验(无设备、无 RPC；完整签名使用 farm/fullsign.py)。
用提取的 T/tableA/tableB/M + K(HMAC密钥)+ pass1 KK + pass2 k2buf/c14/c15,
对任意 (path, body) 计算 a2,组装 mtgsig,请求店铺/菜品接口。
设备静态字段(a1/a5/a7/a8/a9)+ K + a4/a10 来自一次真机取样(多设备:每设备一份样本)。"""
import json, os, sys, hmac, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keeta_a2 as A2
from mtgsig.registration_state import apply_registration_response

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "fooddelivery-eu.mykeeta.com"

# ---- 提取到的算法常量 ----
KK = bytes.fromhex("2e68feb6423cde96")          # pass1 掩码 k1^k2buf[0:8]
K2 = {1: 0xd5, 2: 0xa0, 3: 0x05, 15: 0xed}       # pass2 k2buf(完整位)
K2_MASK = {4: (0x68, 0x7e), 5: (0x9c, 0xbd), 6: (0xca, 0xdb)}  # (值, 掩码)
C14, C15 = 0x02, 0x20

def a2_pass2(out1_08, c9=0):
    """历史 pass2 近似；未纳入完整 k2/序号，不能作为当前验收实现。"""
    o = out1_08
    a = [0]*8  # a[8..15]
    k0 = 0  # 历史占位；当前正确构造见 farm.fullsign._a2_pass2。
    a[1] = o[1] ^ o[6] ^ K2[1]          # a2[9]? 不, 见下映射
    # 按域内 pass2 公式(a 索引 8..15)
    A9 = k0 ^ o[0] ^ o[7] ^ c9
    A10 = o[1] ^ o[6] ^ K2[1]
    A11 = o[2] ^ o[5] ^ K2[2]
    A12 = o[3] ^ o[4] ^ K2[3]
    A13 = 0x7e & (o[3] ^ o[4] ^ K2_MASK[4][0])
    A14 = C14 | (0xbd & (K2_MASK[5][0] ^ o[4] ^ o[5]))
    A15 = C15 | (0xdb & (K2_MASK[6][0] ^ o[5] ^ o[6]))
    A8 = A9 ^ A10 ^ A11 ^ A12 ^ A13 ^ A14 ^ A15 ^ K2[15]
    return bytes([A8, A9, A10, A11, A12, A13, A14, A15])

def compute_a2(method, url, body, payloadJSON, K):
    message = A2.signing_message(method, url, body, payloadJSON)
    digest = hmac.new(K, message, hashlib.sha1).digest()
    d16 = digest[:16]
    s9 = A2.a2Mix(d16)
    sub = A2.a2Substitute(s9)
    out1 = bytes(((sub[i] + d16[i]) & 0xff) ^ KK[i] for i in range(8))
    a2 = out1 + a2_pass2(out1)
    return a2.hex()


class OfflineSigner:
    def __init__(self, sample_path):
        """sample: keeta_K.json(含 K、抓到的 message/mtgsig 作为设备模板)。"""
        with open(sample_path, encoding="utf-8") as fh:
            d = json.load(fh)
        self.K = bytes.fromhex(d["K"])
        self.mt = d["mtgsig"]
        # 从 message 取 payload 模板(精确字段序/格式)
        msg = bytes.fromhex(d["msg_hex"]).decode("latin1")
        self.pay_template = msg[msg.find('{"a0"'):]  # 含该样本 a4/a5/a10

    def payloadJSON(self):
        return self.pay_template   # 复用设备样本 payload(a1/a5/a7/a8/a9/a4/a10)

    def apply_registration_response(self, endpoint, response, *, http_status):
        # Validate on copies before committing both representations together.
        identity = dict(self.mt)
        patch = apply_registration_response(identity, endpoint, response,
                                            http_status=http_status)
        if patch:
            payload = json.loads(self.pay_template)
            for key in ("a7", "a8"):
                if key in patch:
                    payload[key] = patch[key]
            self.pay_template = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            self.mt = identity
        return patch

    def sign(self, url, body):
        pay = self.payloadJSON()
        a2 = compute_a2("POST", url, body, pay, self.K)
        mt = json.loads(pay)
        mt["a2"] = a2
        return json.dumps(mt, separators=(",", ":"), ensure_ascii=False), a2


if __name__ == "__main__":
    # 自检: 复现 K-crack 样本的 a2[0:8]
    signer = OfflineSigner("/tmp/keeta_K.json")
    url = "https://%s/api/v1/shop/shopInfo?ci=102302389&userid=10000057250195" % HOST
    mt, a2 = signer.sign(url, '{"shopId":"159610224"}')
    print("offline a2 =", a2)
    print("device  a2 =", signer.mt["a2"])
    print("a2[0:8] match:", a2[:16] == signer.mt["a2"][:16])

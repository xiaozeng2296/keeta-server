"""AccountEnv: 单账号自包含工作区。所有每账号状态都在 workspace/<acct>/ 下。"""
import json
import os
import tempfile
from pathlib import Path

# 需从 identity.json 覆盖到采集请求头的字段
IDENT_HDRS = ("token", "incog-token", "uuid", "csecuuid", "userid", "csecuserid")


class AccountEnv:
    """一个账号的隔离环境：路径推导 + identity/proxy/ci + 进度记录。

    可 pickle（进程池要传给子进程）：只含简单属性。
    """

    def __init__(self, acct_id, workspace_root, device=None, proxy=None,
                 front_proxy=None, ci=None):
        self.acct_id = str(acct_id)
        self.root = Path(workspace_root) / self.acct_id
        self.device = device      # provision 用的 frida host:port（离线运行不需要）
        self.proxy = proxy        # 动态出口，如 http://${PROXY_USERNAME}:${PROXY_PASSWORD}@ip:port
        self.front_proxy = front_proxy  # 本地前置，如 http://127.0.0.1:7897
        self.ci = ci              # 城市 id（请求 URL 用）

    # ---- 路径（约定推导，工作区自包含可整体拷贝）----
    @property
    def identity_path(self): return self.root / "identity.json"

    @property
    def sample_path(self): return self.root / "sample_K.json"

    @property
    def device_id_path(self): return self.root / "device_id.json"   # 全离线签名的设备身份档

    @property
    def raw_dir(self): return self.root / "raw"

    @property
    def done_path(self): return self.root / "done.jsonl"

    @property
    def errors_path(self): return self.root / "errors.jsonl"

    @property
    def out_path(self): return self.root / "out.xlsx"

    @property
    def progress_path(self): return self.root / "progress.json"

    @property
    def specifics_dir(self): return self.root / "specifics"

    def specifics_path(self, shop_id, spu_id):
        if not str(shop_id).isdigit() or not str(spu_id).isdigit():
            raise ValueError("shop and product IDs must be decimal digits")
        return self.specifics_dir / str(shop_id) / (str(spu_id) + ".json")

    @staticmethod
    def save_json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=False)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def request_context(self):
        if not (self.root / "request.json").exists():
            return None
        from farm.request_context import RequestContext
        return RequestContext(self.root)

    def save_progress(self, progress):
        self.save_json(self.progress_path, progress)

    def raw_path(self, shop_id): return self.raw_dir / f"{shop_id}.json"

    # ---- 就绪与身份 ----
    def ensure_dirs(self):
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def is_ready(self):
        """账号身份加 FullSigner 身份档，或兼容旧冻结样本。"""
        return self.identity_path.exists() and (
            self.device_id_path.exists() or self.sample_path.exists())

    def load_identity(self):
        if not self.identity_path.exists():
            return {}
        return json.loads(self.identity_path.read_text(encoding="utf-8"))

    def ident_headers(self):
        """从 identity 取可覆盖的请求头子集。"""
        ident = self.load_identity()
        return {k: ident[k] for k in IDENT_HDRS if ident.get(k)}

    # ---- 进度（jsonl，权威断点）----
    def done_ids(self):
        s = set()
        if self.done_path.exists():
            for line in self.done_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    s.add(json.loads(line)["shop_id"])
        return s

    def mark_done(self, shop_id):
        with open(self.done_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"shop_id": str(shop_id)}) + "\n")

    def log_error(self, shop_id, stage, msg):
        with open(self.errors_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"shop_id": str(shop_id), "stage": stage,
                                "msg": str(msg)[:200]}, ensure_ascii=False) + "\n")

    def error_count(self):
        if not self.errors_path.exists():
            return 0
        return sum(1 for ln in self.errors_path.read_text(encoding="utf-8").splitlines() if ln.strip())

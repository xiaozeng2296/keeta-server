# m239 的实际来源

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`m239` 是一组成功读取的文件 birthtime 按固定顺序拼接后的 MD5。
它与同次 `m251` 明细绑定，生成链没有读取 localID 或 IDFV。
旧笔记“随 localid 变化，所以是 MD5(localID)”是相关性误判。

## 二进制输入链

1. 字段 collector `0x34eaa4` 使用 switch 表 `0x350e8c`；
   `table[239 - 122]` 的目标是 `0x34f88c`，调用 `0x354660`。
2. `0x354660` 调用 `+[SAKDFPIDTimeStamp getTimeStampID]`，再读取字典的 `m239`。
   类引用为 `0x4b38a00`，selector 引用为 `0x4aa83c8`；`m239` 常量由
   `0x333f9bc` 经 XOR seed `0xaa` 解出。
3. ObjC 方法 IMP `0x327bf0` 解密内置路径数组，按数组顺序逐条查询文件。
   `0x327fc8..0x327fcc` 把 UTF8 路径与 stat 缓冲传给 `0x363fb4`。
   后者在 `0x363fec..0x36400c` 通过 syscall 338 (`stat64`) 查询。
   非零返回值在 `0x327fd0` 跳过该记录，不进入明细或摘要。
4. 成功路径从 `stat + 0x50/+0x58` 读取 birthtime 的秒/纳秒。
   明细格式常量 `0x3305ed8` 解出 `%ld%09ld`，摘要拼接格式常量
   `0x33141d2` 解出 `%ld%ld`。两处区别是**摘要中的纳秒不补零**。
5. `0x328114..0x328128` 追加当前秒和纳秒；循环后转 UTF-8。
   `0x3281e0` 调用 `0x30ea0d8`；其绑定指针 `0x438cf20` 的 Mach-O 符号
   是 `_CC_MD5`。取 16 字节，经 `byte2HexString` 得到 m239。
   输入为空时写入 `unknown`。另一个字典键 `m251` 保存 JSON 明细。

这条链的文件路径、inode (`si`) 和成功标志 (`st`) 是明细，不直接进入 MD5。
但路径列表的顺序、成功过滤决定参与拼接的时间顺序，因此不能排序 m251。

## 离线复现

```python
from mtgsig.timestamp_identity import m239_from_m251

fields["m239"] = m239_from_m251(fields["m251"])
```

函数接收 JSON 文本或解析后的列表，仅使用明确提供的 m251 观测，不读取或修改任何文件时间。
每条 `tm` 末尾九位是纳秒；摘要材料为秒文本加去掉前导零的纳秒文本，记录之间无分隔。
零纳秒仍追加字符 `0`；空列表返回 `unknown`。

## 独立验证

`tools/verify_m239.py` 检查 dispatch、ObjC 绑定、字符串常量和 `_CC_MD5` 导入，
然后从实际二进制提取两个格式串，使用 libc `snprintf` 生成五组合成边界向量，
与 Python helper 对拍。合成 fixture 不含真实路径、标识或时间观测。

五份真实样本各含 21 条 m251 记录，m239 值彼此不同，复算 **5/5 完全匹配**：
项目 encoded corpse、dual A/B、历史 mode0 envelope、当前 mode0 cache。
将 m251 的已补零 tm 直接拼接计算 MD5 无法匹配当前样本，排除了仅靠外观猜格式。

```sh
python3 tools/verify_m239.py
python3 -m unittest tests.test_timestamp_identity -v
```

证据集中于 `dump/m239_recovery/`：三份相关汇编、dispatch 片段和 `verification.json`。
当前结果允许维护 m239/m251 内部一致性，不允许从新 UUID 推导不存在的文件时间观测，
也不证明完整设备画像或线上注册已经成功。全过程没有手机或网络操作。

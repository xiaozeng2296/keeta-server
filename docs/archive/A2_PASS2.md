# a2 收尾序号恢复

> 2026-10-02 原生续证：b2 为 32 位原子签名序号；b17 仅在 POST 签名前置流程递增；b18 在 SDK userID 为 nil 时递增。下文按 b2 数值关系跟随 b17/b18 的实现说明是历史启发式，不能作为原生语义。新任务 render 的严格对照另定位到 b16，见 [新报告](../research/B_COUNTERS_RENDER_20261002.md)。

> 2026-10-01 原生续证：下文保留的 bio 大 Body 例外已定位并修复。当前 SDK 的签名消息只纳入 Body UTF-8 的前 16,200 字节，canonical URL/payload 保持完整；实际 HTTP Body 不截断。字节跨界与原生消息拷贝已验证，七份抓包的 566 条原生签名完整对拍通过。详见 `docs/research/NATIVE_FIELDS_20261001.md` 的 a2 大请求体章节。下文 2026-09-29 的失败计数是修复前记录。

> 2026-09-29 批量边界修正：序号不只使用低 8 位，而是以小端 4 字节进入 a2 的第 9..12 字节（从 0 起算）。
> 旧实现遗漏高 3 字节，菜单在序号超过 255 后出现 403；只修正这些字节及第 8 字节的异或校验，
> 同一请求即恢复 200 / code 0。序号 255、256、65536、16777216 均已通过真实菜单接口验证。

当前差异并非缺少另一把密钥：旧 `_a2_pass2` 把第 9 字节中的
`mask[0] ^ sign_sequence` 固定为零。正确项为：

```python
A9 = mask[0] ^ prefix[0] ^ prefix[7] ^ (sign_sequence & 255)
A10 = mask[1] ^ prefix[1] ^ prefix[6] ^ ((sign_sequence >> 8) & 255)
A11 = mask[2] ^ prefix[2] ^ prefix[5] ^ ((sign_sequence >> 16) & 255)
A12 = mask[3] ^ prefix[3] ^ prefix[4] ^ ((sign_sequence >> 24) & 255)
```

其他第 13..15 字节表达式保持不变，第 8 字节仍是这些字节与 `mask[15]` 的异或。
`tools/verify_a2_pass2.py:pass2` 提供独立参考，不修改 FullSigner。

## 序号的独立证据

对两个真实抓包和 legacy K 样本分别解密 a5，从 **a5.b2** 取序号，
然后独立计算 HMAC、pass1 和 pass2；没有从期望 a2 提取序号作为输入。

| 输入 | 签名数 | 前 8 字节重算 | 全部 16 字节重算 | 给定原前 8 字节的 pass2 |
|---|---:|---:|---:|---:|
| 新机之后尝试登录.chlsj | 73 | 73 | 73 | 73 |
| 从app初次打开到登录被拦截.chlsj | 65 | 64 | 64 | 65 |
| /tmp/keeta_K.json | 1 | 1 | 1 | 1 |

新包 73 条的 a10 均为 `3,250`，旧包 65 条均为 `3,162`；它的第二段不是
每请求递增的序号。a5.b2 分别覆盖 4..81 和 12..85，缺号和网络顺序交错存在。
legacy K 样本 a10 为 `3,253`，a5.b2 为 26，完整签名同样匹配。

这 139 条中 b2=b17=b18，b3 恒为 1，因此不能用 b3 初始化签名序号。
用户另贴 legacy 签名样本的 b2=b17=6，而 b18=0；其 a2 反推序号也是 6。
所以 b18 与序号的关系不能从这批抓包推广到所有状态。优先使用 b2，
保留显式的 profile/采集状态语义，不强制让未知版本的 b18 跟随。

a10 第一段在这些样本中均为 3，目前未恢复与 a5 某字段的普遍关系。
b12 恒为 2；旧包 b13 取 2/3/5，不能用 b13 直接重建 a10 第一段。

## 唯一完整消息例外

旧包索引 777 是 `/fingerprint/v1/app/bio/info/report`，请求体 50688 字节。
前 8 字节已不匹配，但从原前 8 字节与独立 a5.b2 可完整复现后 8 字节，
故该例外位于签名消息或 pass1 输入处，并非 pass2。
已确认重建 path+query 与 HTTP/2 `:path` 完全相等，method/scheme一致，
声明 Content-Length 等于抓包 UTF-8 body 长度。没有按猜测截断请求体或掩盖失败。
这批离线验证不证明服务端注册/登录成功。

## 当前实现与迁移限制

- FullSigner 与 provision 已分开保存 `signature_counter`（a10 第二段/HMAC 输入）
  和 `sign_sequence`（a5.b2）。新 provision 从同条样本的 a10 和解密 a5.b2 初始化，
  签下一条时只递增序号，a10 session 值保持不变。
- b17/b18 只有在原缓存值与原 b2 相等时才跟随；b18=0 等独立状态值保持原样。
  b3 不再作为签名序号更新。b7/b8/b9 均保留缓存采集时间，没有真实刷新事件时不改成 a4。
- RPC `/a2` 未指定 profile 时，独立解密同 payload 的 a5 选择 signing profile，
  不使用缓存 a9 的 profile。显式 `signing_profile` / `profile` 不自动回退。
  缺少显式 `sign_sequence` 时，从同 a5.b2 取得；原生重放已验证全部 73 条新包。
- 序号低 32 位按小端进入 pass2，完整序号保留用于 b2。实际接口已验证跨字节边界；原生进程重置语义尚未直接观测。
- 不再声称 a2 后半“服务端不校验”；当前离线证据只证明构造算法。

旧 identity 若只有 `counter`，加载器分别用该值初始化两个计数：sign_sequence 下一签
递增，signature_counter 固定；落盘后写入两个独立字段。若连 counter 也缺失，则兼容
回退为 1000。这只是明确的兼容行为，**无法恢复已经丢失的原始 a10 session 值**，
也不证明该默认 session 是原生值。缺 signing_profile 的旧档仍按 legacy 解释；无法
从已解码 base_collect 或缓存 a9 可靠判断 a5 曾用的 provider。需要精确迁移时，应以
保留的原始签名重新 provision，或显式补入已验证的 profile、session 和序号。

测试 `tests/test_signing_profiles.py` 覆盖当前 RPC 自动选型、显式错误 profile 拒绝、
旧档 counter 回退及重载、显式新 metadata 优先、服务端已接受请求的字节边界 fixture。
旧 a2_pass2_synthetic.json 保留为历史产物，不再当作边界正确性的依据：它复制了旧实现漏高位的假设。

新证据位于 workspace/curl_02/validation/menu-a2-carry-20260929T114839-* 和
menu-sequence-boundary-20260929T114941-*；脱敏回归向量只保留 pass2 输入与期望输出，不含认证材料。

```sh
python3 tools/verify_a2_pass2.py \
  新机之后尝试登录.chlsj 从app初次打开到登录被拦截.chlsj /tmp/keeta_K.json
```

该命令遇到上述旧包例外会返回非零，审计输出保留所有成功和失败计数。
结果存 `dump/pass2_recovery/verification.json`。

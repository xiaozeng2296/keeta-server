# NativeBridge regionPath 的事件时间

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`regionPath` 保存区域观测事件序列。值是**该事件相对固定 SDK 启动秒的累计毫秒**，
不是区域停留时长、距离上一个事件的间隔或 Unix 时间戳。所有条目沿用同一基线。
本说明依据当前 `dump/Keeta.dec` 的原始指令及已有捕获；没有新增手机或网络实验。

## 基线与计算

`0x2fe1d0` 返回 `K+0x4d3a178` 指向的8字节启动秒对象。它的首次构造
`0x2fe210..0x2fe294` 执行 `NSDate.date → timeIntervalSince1970 →
NSNumber.numberWithDouble: → integerValue`，再将 int64 写入对象。因此基线是
首次初始化时的整数 Unix 秒，不是每个请求的 a4。

`-[NativeBridge regionMonitor]` 位于 `0x30e414`。它先读取当前 Compass 区域，
`0x30e5b4..0x30e5bc` 保存上述基线，随后取得当前 NSDate 时间。
`0x30e63c..0x30e650` 的核心为：

```text
SCVTF  D0, X8          ; launch int64 -> double
FSUB   D0, D8, D0      ; event NSDate seconds - launch seconds
FMUL   D0, D0, D1      ; D1 = 1000.0 at RVA 0x32ef788
FCVTZS X24, D0         ; truncate toward zero
```

值用 NSString `%ld` 格式化为十进制**字符串**。格式串由 `0x3313097`、seed `0x54`
解混淆得到。region 作为单键字典的键，整条追加到事件数组。

`0x30e7a4` 把同一个启动秒捕获到监听 block `+0x28`。回调 `0x30e8dc`
的 `0x30ead8` 重新取这个固定值，`0x30eb28..0x30eb3c` 执行同一组
SCVTF/FSUB/FMUL/FCVTZS。回调没有把基线改成前一事件时刻。

对应 Python 数值规则：

```python
elapsed_ms = math.trunc((event_epoch_seconds - launch_seconds) * 1000.0)
events.append({region: str(elapsed_ms)})
```

这里 `math.trunc` 对应 FCVTZS 的向零截断；不是 round，也不能在减法之前先把
event时间取整秒。若需要复现浮点边界，保存事件的原始 double 秒值。
只保存 `event_at_ms` 已丢失亚毫秒精度：可明确以 `event_at_ms / 1000.0`
作为该协议实现记录的事件输入，但不能声称重建了历史 NSDate 的精确 double。
简单整数 `event_at_ms - launch_seconds*1000` 是毫秒精度的等价语义，浮点边界可能差1毫秒。

## 事件规则与输出

- 初始 `regionMonitor` 将 `regionPath` 清为空串，创建新的 regions 数组；当前区域
  非空时添加初始事件。随后订阅 `listenCompassChangeEventAtCallbackQueue:withBlock:`。
- 回调从 `event.value.region` 取区域。非空且当前数量不大于1023时追加，证据
  `0x30ea5c` 与 `0x30ea9c..0x30eaa0`。因此最多1024条，超过上限不再追加。
- 此回调没有比较末条区域，也没有 same-region 去重。重复区域、重访区域都应保留；
  但这只描述收到回调后的处理，不能推断 Compass 必定对每次配置更新发通知。
- `0x30ec18` 调 `safeToJson`，`0x30ec3c` 调 `setRegion:` 保存完整序列。
  `0x30f154..0x30f1a0` 的 setter 用读写锁替换 regionPath；读取时不重算事件时间。
- 字段是一个 JSON **字符串**，其中顶层数组按事件顺序排列，每项为一个区域/十进制字符串对。
  最小输出如 `[{"GG":"1001"},{"HK":"15066"}]`。

该示例表示启动约1.001秒时记录GG、15.066秒时记录HK。差值14.065秒可以描述
两次观测之间的间隔，但它不是原字段存储的两个值，也不等于已证明的区域停留时长。

## a5.b22 与 bio

bio 外层 `0x31b110` 加载的 selector 已解析为 `regionPath`，从
`NativeBridge.sharedInstance` 读取。非空时 `0x31b18c..0x31b1a0` 写入
字典 key `regionPath`，空值则跳过。

现有新机抓包中索引16/65/97/161/205的 a5.b22 为单条GG；索引248的
a5.b22 与同请求 bio body.regionPath 逐字相同，均为GG→HK两条；随后296/478
仍保留相同事件值，没有随上报时间增长。该独立捕获与静态事件存储语义一致。

协议实现显式应用区域状态时，应先建立同一事件快照，同时更新
`base_collect.b22` 和 bio外层regionPath，然后重新计算a5/a2。不要只更新
请求头region/city而保留旧b22，也不要每次上报都把HK值更新为当前经过时长。

bio外层index是另一套状态：`0x31b1b8..0x31b1c0` 对collector `+0x30` 的
uint32先加1，再于 `0x31b1e0` 用 `%d` 输出。高位为1时应解释为有符号int32：
`0x80000000 → "-2147483648"`，`0xffffffff → "-1"`。
它与bio内部m313的 `+0x90`、事件时间和a5.b2均不同。
`mtgsig/registration_reporting.py` 接收已递增的显式计数并按该wire规则输出；
接口仍拒绝0，未新增整个计数器回绕生命周期的支持。

## 当前协议会话的证据边界

`current_registration_context_01.json`、`current_registration_context_02.json`
均实测 `launch_seconds=1790590620`，各自 a5.b7 同值；b8/b9分别为
1790618760和1790618880，故不能把b8/b9当regionPath基线。
当前复用身份的初始a5.b22为 `[{"GG":"639"}]`，来源是对应原生观测。

`session_02/send-started.json` 的1790619779401是协议请求发送开始时间，
不是该身份的SDK首次初始化时间。沿用这个身份及b7时，不把它替换为新的计时基线。

`region_10_current_local_info/send-started.json` 保存请求开始1790625300231ms，
真实响应已确认HK，但没有单独保存当时将响应应用为区域事件的精确时刻。
所以历史事件只能确定发生在请求开始之后，相对b7下界为34680231ms；
没有据此虚构精确值，也不把文件mtime当执行事件。

当前最小续接方式是：在协议状态机**现在明确应用已接受HK状态**时记录新的
事件时间（优先同时保存原始double秒、整数毫秒、基线、来源响应路径和事件类型），
在已有GG观测后追加该HK应用事件，同步b22和bio。该值表示本次状态应用时刻，
不是追认之前HTTP响应到达的时刻，更不是复制旧包 `GG:1001/HK:15066`。
这样保留了当前复用画像的历史来源与协议状态应用事件之间的明确边界。

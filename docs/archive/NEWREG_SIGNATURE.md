# `/sdkapi/newreg` signature 离线复现

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`newreg.signature` 已从 iOS 初始化调用链还原，并通过两份真实抓包逐字验证。
实现位于 `mtgsig/newreg.py`，入口为 `newreg_signature(random_value, *, app_name, password)`。
本次只证明该字段的生成规则；尚未据此证明完整注册、风控或登录链已成功。

## 算法与输入来源

签名使用三个字符串：

- `app_name`：`-[PSEnvironment appName]` 返回 `NSBundle.mainBundle.bundleIdentifier`。
  当前抓包与二进制对应 `com.sankuai.sailor.ifooddelivery`。
- `password`：`-[SLHighPriorityLanucher setupPushService]` 从 `+[SLAppInfo pushPassword]`
  取得固定 SDK 常量，传给 `PSPushService initWithPassword:...`，再由
  `setupPushWithPassword:...` 写入 `PSEnvironment.password`。
  实现中保留显式参数覆盖，默认常量只对应当前分析版本。
- `random`：请求正文中的原始字符串。当前两份抓包都是十进制时间值字符串。

原生代码用 `NSArray.sortedArrayUsingSelector:@selector(compare:)` 升序排列三项，
以 `-` 连接，再调用 `sha1:`，返回小写 40 字符十六进制。

```python
from mtgsig.newreg import newreg_signature

signature = newreg_signature("1790496483")
```

该公式不使用 `deviceid`、`mac`、`apnstoken` 或整个 JSON。只更新这些字段不会改变该签名；
修改 `random` 时必须按最终发送文本重算。

`+[SLAppInfo appName]` 和 `-[PSEnvironment appName]` 是不同方法。
前者返回展示/业务名称，不能代替这里使用的 bundle identifier。

## 两份真实向量

| 抓包 | `random` | 抓到的 `signature` | 本地结果 |
|---|---|---|---|
| `从app初次打开到登录被拦截.chlsj` | `1790130775` | `7397bba0b97f7ad0788c3f7d39554b5b49a2630e` | 完全一致 |
| `新机之后尝试登录.chlsj` | `1790496483` | `ae87cbec81387ad1f76c13f7e76c47591a7a8e9b` | 完全一致 |

测试保留了两个最小向量，不依赖完整抓包和手机：

```bash
python3 -m unittest discover -s tests -p test_newreg_signature.py -v
```

## 原生证据

证据源为已存在的 `dump/Keeta.dec.asm`，没有为此重启、清空或 hook 手机。

| 位置 | 决定性行为 |
|---|---|
| `dump/Keeta.dec.asm:13644212` | `+[SLAppInfo pushPassword]` 直接返回固定 CFString |
| `dump/Keeta.dec.asm:13660919` | `setupPushService` 调用 `pushPassword` |
| `dump/Keeta.dec.asm:13660941` | 该值传入 `initWithPassword:...configDictionary:` |
| `dump/Keeta.dec.asm:16008310` | 初始化函数调用 `setupPushWithPassword:...` |
| `dump/Keeta.dec.asm:16008477` | 调用 `PSEnvironment setPassword:` |
| `dump/Keeta.dec.asm:15992704` | `PSEnvironment.appName` 读取 `bundleIdentifier` |
| `dump/Keeta.dec.asm:15982797` | 读取三项、排序、连接、调用 `sha1:` |
| `dump/Keeta.dec.asm:15982887` | `sha1:` 使用 `CC_SHA1` 与 `%02x` 输出 |

## 算法边界

当前验证域是 ASCII。原生 `sha1:` 先通过 `cStringUsingEncoding:4` 取得 UTF-8 C 字符串，
却使用 `NSString.length` 作为 `NSData dataWithBytes:length:` 的字节数量。
`NSString.length` 是 UTF-16 单元数，含非 ASCII 内容时可能截断 UTF-8 字节。
因此不能把这个原生 helper 泛化成任意 Unicode 字符串的普通 UTF-8 SHA-1。
`NSString compare:` 的非 ASCII 排序细节也未在当前任务中验证。

Python 实现明确拒绝非 ASCII 输入，接受 `random` 为字符串或整数；整数转为十进制文本。
它不删除空格、不消除前导零、不接受浮点数/布尔值/任意对象的隐式字符串化。
字符串和整数间的方便转换不代表可改变最终请求正文类型；抓包中的 `random` 是 JSON 字符串。

已执行的是静态调用链检查和离线真实向量比对。本次未发送 `newreg` 请求，未新建服务端设备身份，
也未验证其他 App/SDK 版本复用此默认常量。


## 成功响应门

`parse_newreg_response(response, *, http_status)` 只消费顶层 `pushtoken`，返回
`{"push_token": ...}` 或 `{}`。两份真实 success（新包索引 21、旧包 221）都没有 code，
不能以通用 code=0 判断 newreg 成功；只有 `{"code":0}` 的响应必须拒绝。

接受条件是整数 HTTP 2xx、非空且无空白/控制字符的字符串 pushtoken，以及不存在已识别
的明确失败信号。若响应包含 code、errcode 或 errorCode，要求整数 0；error 非空或
success 明确非 true 则拒绝。不递归搜索 data，不读取 push_token 别名，不自动生成值。

此 token 是 push 支线状态，与 OneID、a7、a8 分开。新包中它与后续 102/220 bind 的
PushToken header 相等；没有据此声称它决定首个 v5/sign 或登录风控是否接受。
`tests/test_newreg_signature.py` 当前 11 项测试包含两份已有响应，无网络或 token 输出。

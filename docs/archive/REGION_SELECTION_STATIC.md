# 选区结果到 currentLocalInfo 的静态数据流

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本页仅分析本地 `dump/Keeta.dec`，没有连接手机、调用接口、修改地区响应或执行选区。
二进制 SHA-256：`0900cac89f75fc4f75279c708785bf2c7a03c228301a8e75ce62f93e3ad88488`。
地址均为模块 RVA；读取使用 Mach-O 段映射，不能一概视为文件偏移。
派生汇编位于 `dump/region_selection_static/`，由 `tools/inspect_login_static.py` 生成。

## 结论与尚未验证的边界

原生侧处理位置选择的有效入口是 `SLUserAddressChanged`，其 `parameters` 携带位置字典。
`SLSelectedLocation` 明确支持两种坐标形式：独立 `latitude`/`longitude`，或者
`location="经度,纬度"`。原生代码没有在此根据 `region="HK"` 自动重查或更正坐标。

所以，检查“用户点 HK，但 currentLocalInfo 发出 BR 坐标”时，应同时观测位置桥接字典、
`SLSelectedLocation` 解析结果以及最终请求 body。只改 region header 无法说明原生状态已经切换。
当前尚未读取 MachPro 页面自身的点击处理代码，因此**没有证明用户点错，也没有证明页面实现有 bug**。
`getOpenServiceRegion` 返回的城市候选如何变成桥接参数，仍须一次正常人工选区的观察闭合。

## 已恢复的原生调用链

```text
MachPro 页面调用 SLMPUserAddressModule.didSelectLocation:
  或 KSI 调用 SLUserAddressContext.__msi__api__didSelectLocation:...
  → NSNotificationCenter 发布 SLUserAddressChanged
  → SLHomeViewController.handleAddressSelected:
  → SLSelectedLocation.initWithDictionary:error:
  → 内部 block 0x2d26834
  → SLHomeViewController.didPickAddress:addressLocation:withCoordinate:...
     ├─ enableNewLocate=true
     │  → SLHomeLocateManager.startLocateWithSelectedLocation:
     │  → SLLocateTask + SLPositionInfoModel
     │  → SLLocateControlCenter.startLcoateTask:
     └─ enableNewLocate=false
        → SLPlacemark 的选定坐标 + 现有 actualLatitude/actualLongitude
        → SLHomeViewController.updateCoreModel:changeRegion:...
        → SLRegionSelectionRequest.locationParams
        → SLRegionSelectionManager.requsetLocalInfoWithLocationParams:
        → SailorCoreModel.currentLocalInfoWithBodyParams:finished:
```

本轮追到了 v3 的 `startLcoateTask:` 入口；未再次展开它到 `SLCoreParamsService` 的全部后续路径。
旧分支从字典到 `currentLocalInfoWithBodyParams:` 已静态连接。当前手机走哪条分支尚未观测。

## 桥接参数和通知格式

`-[SLMPUserAddressModule didSelectLocation:]`（`0x25c9548`）的 x2 是参数数组，
不是直接的位置字典：先 `firstObject`，再 `toDictionary`。该字典成为以下 `parameters`：

```json
{
  "source": "location",
  "parameters": {
    "name": "候选位置名称",
    "address": "候选位置地址",
    "location": "114.169773,22.3203648",
    "is_change_region": true
  },
  "isChangedRegionArea": false
}
```

这只是原生解析器接受的格式示例，不是一次实际捕获的 UI payload。无需为了观察而投递此通知。
顶层 `isChangedRegionArea` 和内层 `is_change_region` **不是同一值的简单复制**：
顶层仅在内层为真且调用页面 bundle 名等于
`mach_pro_sailor_c_address_change_region_popup` 时为真。
`mach_pro_sailor_choose_location_page` 本身不满足该 bundle 判断。

KSI 对应方法为
`-[SLUserAddressContext __msi__api__didSelectLocation:name:address:latitude:longitude:is_change_region:]`
（`0x25e7320`）。x2 是带 `params`/`referrer` 的调用对象；代码取它的 `params` 作为
同一通知的 `parameters`。不要仅按 selector 的每个具名参数猜测最终字典。

`-[SLHomeViewController addUserAddressChangedNotification]`（`0x2d1f21c`）注册响应式观察者，
block `0x2d26ec8` 将通知交给 `handleAddressSelected:`。后者 x2 是 `NSNotification`，
取 `userInfo.source` 和 `userInfo.parameters`；`source="location"` 分支在
`0x2d2412c` 用 parameters 创建 `SLSelectedLocation`。

## 坐标解析和状态传递

`-[SLSelectedLocation initWithDictionary:error:]`（`0x2e256f8`）：

1. 先调父类 JSON 模型解析。
2. 若字典不含 `latitude`，且含 `location`，按 `,` 分割；仅当结果为两个元素时继续。
3. `0x2e257ac`：第一个元素写 `longitude`；`0x2e257c8`：最后一个元素写 `latitude`。
4. 再用 `sl_serverLatitudeLongitudeToDouble` 生成两个 double 属性。
5. 否则直接读取独立的 `longitude`/`latitude` 并转换 double。
6. `0x2e25868` 保存 `originalDictionary`。模型字段 `locationId` 映射 JSON `id`。

不能只看 `location`：如果同一字典另含 `latitude`，代码会优先走独立字段分支。
候选 `location` 为 HK，但独立字段为 BR，是应重点排查的数据不一致形式；目前没有其运行证据。

`didPickAddress:...`（`0x2d244f8`）中新定位分支接到 `SLSelectedLocation` 后，调用
`-[SLHomeLocateManager startLocateWithSelectedLocation:]`（`0x2cfd850`）：

- 新建 `SLLocateTask`，`isNeedUserAddress=false`、`scene="0"`、`isUserTrigger=true`。
- 从 `selectedLocation.originalDictionary.is_change_region` 读取布尔值；为真则
  `regionRequestType=1`。
- 新建 `SLPositionInfoModel`，`saveType=2`、`positionInfoTypeClass=selectedLocation.class`，
  `positionInfoData=selectedLocation`，存入任务的 `alreadyCachePositionInfoModel`。
- 将任务传给 `SLLocateControlCenter.startLcoateTask:`（保留原 selector 拼写）。

旧定位分支 `updateCoreModel:changeRegion:...`（`0x2d233d8`）组装四项：
`latitude`、`longitude`、`actualLatitude`、`actualLongitude`；缺失值变成空字符串。
它创建 `SLRegionSelectionRequest`，`0x2d23530` 写入 locationParams，
`0x2d235d8` 调 `requsetLocalInfoWithLocationParams:`。

后者（`0x2e4e2a8`）x2 **是 request 对象，不是 NSDictionary**。它复制
request.locationParams，再合并 `systemLocale`、固定空字符串 `systemRegion`、
`systemTimeZone` 和 `clientType`，于 `0x2e4e4b0` 发给
`+[SailorCoreModel currentLocalInfoWithBodyParams:finished:]`。
完成 block `0x2e4ea1c` 取响应 data，构造 `SLRegionSelectionResponse`；必要时暂存，
否则交给 delegate 的 `regionSelectionRequest:finished:`。这不是坐标选择来源。

## 不应误当作选区坐标来源的入口

- `-[SLRegionSelectionManager regionSelection]`（`0x2e4e64c`）只是懒加载对象。
- `-[SLRegionSelection handleRegionSelectionPageNotification:]`（`0x2e4ddd4`）
  只读取 userInfo 并检查类型，没有进行坐标转换。
- `openRegionSelectionPageWithDisableClose:openReason:openCompletion:resultCompletion:`
  （`0x2e4d9f4`）打开 MachPro 选区页，传 `fromPage=2`、`changeLocationReason`、
  `disableClosePage` 等配置；不会直接设置 HK 或 BR。
- 首次安装两个调用 block（`0x2d1ed8c`、`0x2d1ef14`）设 disableClose=1、openReason=6。
  它们传入的 resultCompletion（`0x2d1f19c`、`0x2d1f188`）只调用
  `checkCoreParamsErrorCheckMonitor`。不能把此完成回调当成坐标变换函数。
- 中转 resultCallback `0x2e4dfb8` 从 x3 接收字典并转发，但上面这两个消费者不读取位置字段。

## 最小运行时观测建议

| 观测点 | 只需记录的内容 | 能排除的歧义 |
|---|---|---|
| `SLMPUserAddressModule didSelectLocation:` 或 KSI 对应入口 | bundle/referrer；转换后的 payload 中 name、location、latitude、longitude、is_change_region | 页面向原生交付了哪个位置 |
| `SLHomeViewController handleAddressSelected:` | x2.userInfo 的 source、parameters 中位置字段、isChangedRegionArea | 通知与 UI 桥接是否一致 |
| `SLSelectedLocation initWithDictionary:error:` | 输入位置字段；返回对象的 latitude/longitude | 组合 location 与独立字段是否冲突 |
| `SailorCoreModel currentLocalInfoWithBodyParams:finished:` | x2 中四项坐标及 systemLocale/systemTimeZone/clientType | 最终选区请求构造结果 |

这些是正常 ObjC 入口。首次只记录一轮人工选区，不需要替换返回值、改 body、改响应、
清 keychain 或插入 CFF 基本块。若最终请求使用另一个入口，以实际 HTTP body 为准。
日志按上表筛选位置字段，避免打印整个调用对象、请求 headers 或设备身份。

复核坐标参考来自完整包的 `getOpenServiceRegion`，而不是硬编码选区结果：

| 候选 | cityId | location（经度,纬度） |
|---|---:|---|
| HK | 810001 | 114.169773,22.3203648 |
| BR | 102302389 | -46.6332165,-23.5489841 |

完整包实际发送的 BR 坐标证据及时间顺序见 `docs/REGION_SELECTION_TRACE.md`。

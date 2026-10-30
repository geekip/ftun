# 变更记录

## 1.0.5

- 代理出口准备阶段不再解析服务器域名。离线时服务和无关SOCKS入站可启动；DNS上游首次打开出口时异步解析，失败返回SERVFAIL，网络恢复后新查询自动恢复。解析沿用请求期限和取消机制，不会退回直连。
- 出口打开接口接纳逻辑编号及已固定编号，组选择在出口内部完成；明确代理与未来Mesh的编号区间。
- 移除wolfSSL的OpenSSL兼容层。证书链、有效期及域名继续由wolfSSL校验；数值IPv4/IPv6地址严格匹配iPAddress SAN，不接受同文本的DNS SAN或CN。
- macOS编译CI覆盖util、platform、core及公共libs，仍不提供macOS原生服务。修正缺少网络测试工具时的跳过判定，以及浅克隆无tag的依赖校验。

### 配置迁移

旧JSON配置可继续使用。`base.ipv6`默认`false`；设为`true`时域名解析同时查询A/AAAA，数值IPv6目标和双栈监听不依赖此开关。TUN需要IPv6时增加`"ipv6":{"address":"fd00::1/64"}`并保证MTU至少1280，未配置时保留IPv4行为。IPv6监听/带端口地址使用`[::1]:端口`。FakeIP地址池及FRS IP数据仍使用IPv4。字段与示例见[配置说明](docs/configuration.md)。

### 二进制体积基线

Linux x86_64，GCC 14.2.0/glibc，MinSizeRel、`FTUN_OPTIMIZATION=size`（`-Os`）、`FTUN_LTO=OFF`、`FTUN_SECTION_GC=ON`、`FTUN_HARDENING=ON`，动态链接、未strip、关闭测试。同一工具链和设置：

| 档位 | 内置模块 | ELF字节数 |
|---|---|---:|
| DNS-only | DNS | 342,640 |
| Proxy-only | Proxy | 843,792 |
| 全模块 | Proxy、DNS、FakeIP、TUN、FRS | 1,157,368 |

复现：`cmake -S . -B build/size-profile -DCMAKE_BUILD_TYPE=MinSizeRel -DFTUN_OPTIMIZATION=size -DFTUN_LTO=OFF -DFTUN_SECTION_GC=ON -DFTUN_HARDENING=ON -DBUILD_TESTING=OFF`，再显式设置五个`FTUN_MODULE_{PROXY,DNS,FAKEIP,TUN,FRS}`为表中模块`BUILTIN`、其余`OFF`，执行`cmake --build build/size-profile --target ftun`和`stat -c %s build/size-profile/ftun`。体积随工具链及链接方式变化，不与静态musl产物混用。

## 1.0.4

### 新增

- **断网不退出，网络恢复后自动恢复服务**：统一的恢复调度器管理监听、DNS 上游、UDP 出口、FRS 下载与 TUN；内核网络事件（链路、地址、路由、策略规则）去抖后提前触发恢复。启动时没有网络也能正常启动，`run` 以降级状态运行。
- **心跳看门狗**与 systemd 集成：`base.watchdog`（默认 30 秒）；`Type=notify`；服务样例见 `examples/service/`。
- **TUN 路由对账**：启动清理崩溃遗留的路由和规则；运行中补回缺失的自有对象；TUN 设备被外部删除后自动重建。
- **连接存活检测**：`base.timeouts`（握手、建连、回复、TCP keepalive、写入进展、空闲回收）；转发连接按累计确认字节判定停滞，慢速但仍在读取的对端不会被误关。
- **日志**：时间戳、实例标识、序号与关联 ID；按大小轮转（`log.max-size`、`log.max-files`）；`SIGUSR1` 重新打开日志文件；生命周期事件目录。
- **DNS** 多地址上游的被动健康检查；响应事务 ID 校验。
- **可配置的网络标识**：`tun.route-table`、`tun.rule-priority`、`base.routing-mark`。
- **重载保留**：`base.reload-retain` 限制同时保留的旧代次数量。
- **文档**：[实现符合度矩阵](docs/conformance.md)、[部署与运维手册](docs/operations.md)、[配置参考](docs/configuration.md)。
- **工程**：`FTUN_TSAN` 构建；CI 在 PR 上运行 Debug、ASan/UBSan、TSan、静态 musl 与 fuzz 冒烟；八个 fuzz 目标（`tests/fuzz/`）；`FTUN_FUZZ` libFuzzer 构建。

### 不兼容变更

1. 日志行格式改变，增加了时间戳等字段。
2. 退出码细分：新增 3（运行时致命错误）和 4（看门狗触发）。
3. FRS 更新也会推进公开的 `generation`，此前取得的代次校验值在 FRS 更新后会失效。
4. 没有网络时启动的语义改变：FRS 以未就绪状态启动，命中其规则的连接被拒绝；监听可能处于等待恢复。
5. TUN 默认路由表号由 51820 改为 18004，避免与 WireGuard 冲突。
6. 新增配置字段；空闲回收默认关闭。
7. SOCKS5 回复中的 IPv6 BND 地址现在会被接受。
8. 删除 `inbounds[]` 下的旧版 TUN 设备字段；设备字段只能写在顶层 `tun` 下，出现旧字段时配置校验直接报错。
9. 转发连接不再使用 `TCP_USER_TIMEOUT`，`base.timeouts.write-progress` 改为应用层按确认进展判定（语义不变，回收时刻最多延后一个 1 秒扫描周期）。

### 修复

- 慢速但仍在读取的连接在 `write-progress` 之后被误关。
- FRS 更新失败可能撤销宿主正在进行的重载准备，造成半提交。
- TUN 设备被外部删除后服务报错而不是恢复。
- 文件描述符耗尽后，执行 FRS 更新的后台线程可能永久卡死：FD 释放后 FRS 更新不再继续，停止时要等到期限并以退出码 1 结束。

## 迁移说明

1. **配置**：如果配置里有 `inbounds[]` 下的旧版 TUN 设备字段，改写到顶层 `tun`；`ftun check` 会报配置无效（不会指出具体字段，请对照 [配置参考](docs/configuration.md)）。
2. **路由表号**：默认表号改为 18004。如果有外部脚本引用 51820，请改为引用 18004，或在配置里显式设置 `tun.route-table`。
3. **日志解析**：日志行新增时间戳、实例标识、序号和关联 ID 字段；依赖旧格式的解析规则需要更新。
4. **退出码**：监控脚本把非 0 当作失败即可；需要区分时，3 为运行时致命错误，4 为看门狗触发。
5. **systemd**：可使用 `Type=notify` 与 `WatchdogSec`，样例见 `examples/service/`。
6. **嵌入使用方**：公开 C API 与 ABI 版本不变；FRS 更新后 `generation` 会推进，缓存的代次校验值需要重新取得。

## 已知限制与验证范围

- 24 小时故障注入长稳（R13）在私有网络命名空间里模拟网络故障，没有真机验证；组合、DNS-only、Proxy-only 三种配置各一个静态 musl 实例，ASan/UBSan 与 TSan 为补充实例。
- 场景 R9（监听错误注入）与 R11（owner 卡死注入）依赖测试钩子构建，产品构建里跳过，由单元测试覆盖；R10、R11 因本身要重启进程，不在长稳内。
- 覆盖率引导 fuzz 每个目标运行 600 秒（单核），不是持续 fuzz。
- 没有端到端吞吐和尾延迟的对照基线；本版本只核对了体积与空闲内存。
- `stop`/`reload` 向给定 PID 发信号，不校验进程身份；实例锁只对 TUN 自动路由按路由表号加锁。
- 仍然只支持 Linux x86_64 IPv4。

## 兼容矩阵

| 项目 | 1.0.3 | 1.0.4 |
|---|---|---|
| 公开 C API / ABI 版本 | 1 | 1（布局不变） |
| 配置 Schema | 基线 | 向后兼容的新增字段；删除旧版 TUN inbound 字段 |
| 默认路由表号 | 51820 | 18004 |
| 退出码 | 0 / 1 / 2 | 0 / 1 / 2 / 3 / 4 |
| 平台 | Linux x86_64 IPv4 | 同左 |

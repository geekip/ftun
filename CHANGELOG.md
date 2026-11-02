# 变更记录

## 1.1.0（未发布）

- CLI 新增实例状态、DNS/Proxy 状态查询、文本/JSON 操作结果、`--timeout` 与 `--no-wait`；本机 Unix 控制通道检查 uid、PID 和 boot，并等待重载提交或实际停止。结果未知使用退出码 5。
- 所有 run 实例持 PID 文件锁，状态缓存和日志文件分别持路径锁；多实例可通过不同 `-p`、缓存和日志路径隔离。崩溃残留文件按锁状态接管。
- 无 `-c` 的 run 首次创建最小回环 SOCKS5/DIRECT 配置；check 保持只读。POSIX 支持 `-b` 并等待就绪交接；`-v`/`-vv` 和禁色覆盖跨重载保留。Windows 明确拒绝后台化及本机管理 IPC。
- 持久 FakeIP 仅在整个状态目录不存在时自动创建身份。已有目录缺文件、损坏、锁冲突或地址池不符时拒绝启动；规范化 CIDR 后比较真实池身份。
- 日志默认改为 info/stderr，支持 file/both、终端颜色、NO_COLOR、模块和事件短语格式、sid/op/gen 关联。重复故障输出首次、60 秒汇总和真实恢复；表和队列均有界，writer 故障通过独立诊断报告。
- 完整接入启动/配置/控制、DNS、Proxy、FRS、FakeIP、TUN 和网络变化事件；保留实际 socket errno 名及 TLS 库错误码与文本。正常转发在 info 下不逐连接输出。
- 配置错误给出字段路径、处理阶段和原因；check 成功列出模块及只在启动时可验证的条件。更新 systemd、procd 与 Padavan 样例。
- 未选中 FakeIP 且关闭普通状态缓存时，不再因默认持久化开关而访问其状态目录；普通用户运行真实 DNS/Socket 配置不需要无关目录权限。
- 修正 Zig musl 发行构建中原子身份发布依赖 libc 包装函数声明的问题；Linux 直接使用同一内核原子无覆盖操作，不增加降级路径。
- FRS 下载故障后，成功取得相同规则或 HTTP 304 也会按实际完成阶段报告恢复，保持配置代次不变；没有重新执行文件发布时不误清除发布或耐久性故障。
- 日志文件写入失败的独立诊断保留原生错误码，可据此区分磁盘满等实际系统原因。
- 减少启动时未使用的 Operation、日志、控制连接和缓冲等待槽初始化；命令指针队列和早期日志只读取已发布项。完整容量仍一次准入和分配，首次使用前初始化。就绪快照交接后立即释放，降低空闲驻留内存。
- 后台启动管道在等待唤醒后重新检查绝对期限，避免恰在期限处的 EOF 被误报为提前退出，也不在期限后读写交接数据。
- 控制通道在最早期限不变时保留已有定时器，避免持续状态查询撤销已排队的到期回调，使未读客户端的写超时继续推进。

### 从 1.0.x 迁移

- 删除 `ftun fakeip init`；启动已有配置即可自动创建确实缺失的身份。不要删除损坏目录中的单个文件；备份或恢复应包含完整状态目录。
- 默认日志级别从 warn 改为 info，默认输出从文件改为 stderr。需要原来的方式时显式配置 `"log":{"level":"warn","output":"file","file":"/path/ftun.log"}`。后台仍使用文件。
- 日志行格式变化：脚本应解析模块、短语及键值；不再依赖每行 `event=`、`boot=` 或 `seq=`。boot 在启动行，序号及丢弃计数经 status 查询。
- 脚本应判断退出码和 JSON `result`，区分 committed、rejected、restart-required 和结果未知。`--no-wait` 的 accepted 只表示接纳；数字 PID 的信号式 reload 不能确认提交，返回 5。
- 默认 PID 路径一次只允许一个实例；多实例必须分配不同路径。systemd/procd 保持前台，不使用 `-b`。
- 公开 C ABI 仍为 1；FRS 1.0 与既有 FakeIP 身份/预留/快照格式保持不变。其他配置字段仍由当前 Schema 校验。

以下修正同时纳入本版本：

- 统一域名校验并清理未使用的内部接口；DNS缓存、查询及恢复调度在读取时钟失败时返回实际错误。

- 出口域名解析按节点合并在途请求；等待者独立超时和取消，最后一个等待者离开后才取消共享解析。
- 缓存使用DNS应答与CNAME的最小TTL，A/AAAA组合取最早过期时间；TTL为0不持久缓存，过期后的新连接按需刷新，已有连接不受影响。
- 解析失败复用恢复调度器指数退避，基准间隔从1秒递增至30秒，各次附加20%抖动；退避期间返回失败，不发起后台重试或改走直连。缓存和在途任务保持配置代次及出口保护策略隔离。

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

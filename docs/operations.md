# 部署与运维手册

本文面向在 Linux 网关、路由器上部署 FTUN 的人。字段含义见[配置参考](configuration.md)，各项功能的实现程度见[实现符合度矩阵](conformance.md)。

## 1. 运行条件

- 正式支持 Linux x86_64 IPv4；产物可构建为 musl 全静态程序（见 README）。
- 只使用 SOCKS5/Mixed 入站、DIRECT 或 SOCKS5 出站时，普通用户即可运行，需要监听端口、配置文件和状态文件的访问权限。
- 使用 TUN 与自动路由（`tun.auto-route`）需要 root 或 `CAP_NET_ADMIN`；绑定 1024 以下端口需要 `CAP_NET_BIND_SERVICE`。
- 系统无法建立必需的出口保护（socket 标记、路由规则）时，FTUN 在启动阶段失败并报告原因，不会降级为无保护运行。

## 2. 网络标识：标记、路由表与规则优先级

FTUN 自己的出站连接带 fwmark，TUN 自动路由用它把"FTUN 自己的流量"排除在捕获之外，避免回环。以下数值都可配置，默认值如下：

| 项目 | 配置 | 默认值 | 说明 |
|---|---|---|---|
| socket 标记 | `base.routing-mark` | 18004（0x4654） | 同机运行多个实例时必须各不相同 |
| 路由表号 | `tun.route-table` | 18004 | 旧版本默认 51820，与 WireGuard 的默认路由表冲突，已更换 |
| 规则优先级 | `tun.rule-priority` | 11000 | 保护规则使用该值，捕获规则紧随其后 |

规则与路由由 FTUN 创建并标记协议号 186，退出时只撤销自己创建的对象，不会清空系统路由或防火墙。

与 WireGuard 等其他网络工具同机运行时：不要让它们使用相同的路由表号、规则优先级或 fwmark；FTUN 的默认值已经避开 WireGuard 的默认值（表 51820、标记 0xca6c）。

### 实例互斥与崩溃后恢复

- 同一路由表号只允许一个 FTUN 实例：启动时对 `/run/ftun-net-<路由表号>.lock` 加独占锁，拿不到锁的第二个实例会启动失败，不改动任何网络对象。
- 进程被 `kill -9` 或崩溃后，遗留的路由、规则不会让下一次启动失败：启动时先清理同路由表、同优先级、协议号 186 的遗留对象，再按本次配置安装。TUN 地址若属于外部对象则按冲突拒绝，不会接管。
- 运行中如果路由或规则被外部删除，FTUN 在收到网络变化通知后补回缺失项，不会重启；TUN 设备被外部删除（例如 `ip link del`）后会自动重建。

## 3. 文件、目录与权限

| 内容 | 默认位置 | 说明 |
|---|---|---|
| 状态缓存 | `base.cache-file`，默认 `~/.ftun/ftun.cache` | Group/Health 状态；`base.state-cache` 为 false 时不使用 |
| FakeIP 状态目录 | `<base.cache-file>.fakeip` | `dns.fake-ip.persist` 为 true（默认）时，首次运行前必须先执行 `ftun fakeip init -c CONFIG`；缺失或损坏不会自动重建 |
| FRS 规则文件 | 由 `frs` 配置 | 规则引用 FRS 集合时，启动会校验文件及所有引用的集合；本地文件损坏会阻止启动 |
| 日志文件 | `log.file`，默认 `~/.ftun/ftun.log` | 见第 6 节 |
| 实例锁 | `/run/ftun-net-<路由表号>.lock` | 仅 TUN 自动路由使用 |

FTUN 以运行用户的权限读写以上文件，目录权限请确保该用户可写（状态、日志）或可读（配置、FRS、CA）。

## 4. TLS 与 CA

通过 HTTPS 下载 FRS 规则文件时，FTUN 总是校验服务端证书和主机名，没有关闭校验的选项。CA 证书包按下面的顺序取第一个存在的常规文件：

1. `/etc/ssl/certs/ca-certificates.crt`
2. `/etc/pki/tls/certs/ca-bundle.crt`
3. `/etc/ssl/ca-bundle.pem`

三个都不存在时下载被拒绝（精简系统请先安装 CA 证书包）。配置里目前没有自定义 CA 文件、证书固定或 IP SAN 校验的选项。

## 5. 进程管理

### 信号与命令

| 动作 | 命令 | 等价信号 |
|---|---|---|
| 停止 | `ftun stop PID` | `SIGTERM`（进程同样把 `SIGINT` 当作停止） |
| 重载配置 | `ftun reload PID` | `SIGHUP` |
| 重新打开日志文件 | `kill -USR1 PID` | `SIGUSR1` |

重载是事务性的：新配置整体通过校验与准备后才一起生效，失败时保持旧配置继续运行。`stop` 与 `reload` 只是对给定 PID 发送信号，不校验该 PID 是否是 FTUN 进程。

### 退出码

| 退出码 | 含义 | 是否应自动重启 |
|---|---|---|
| 0 | 正常停止 | 否 |
| 1 | 配置或启动失败 | 视情况 |
| 2 | 命令行用法错误 | 否 |
| 3 | 运行时致命错误（内部状态损坏） | 是 |
| 4 | 看门狗触发（主循环长时间无响应） | 是 |

### 看门狗与服务管理器

`base.watchdog` 默认 30 秒：主循环超过这个时长没有心跳，进程以退出码 4 停止，由服务管理器重启；设为 `null` 可以关闭。断网期间看门狗不会触发（恢复调度器不阻塞主循环）。

在 systemd 下使用 `Type=notify`，FTUN 直接写 `NOTIFY_SOCKET`（不依赖 libsystemd），启动完成时发送 `READY=1`，并按 `WATCHDOG_USEC` 喂狗。`WatchdogSec` 必须大于 FTUN 自己的心跳间隔（约为 `base.watchdog` 的三分之一）。可直接使用的样例：

- systemd：[packaging/systemd/ftun.service](../packaging/systemd/ftun.service)
- OpenWrt procd：[packaging/openwrt/ftun.procd](../packaging/openwrt/ftun.procd)

## 6. 日志

- `log.level`：`silent`、`error`、`warn`（默认）、`info`、`debug`、`trace`。
- 文件日志按大小轮转：`log.max-size`（默认 10 MiB，0 不轮转，否则不小于 64 KiB）和 `log.max-files`（含当前文件，默认 3，范围 1～32）。超限时依次改名为 `<file>.1`、`<file>.2`……，超出保留数量的最旧文件被覆盖；`max-files` 为 1 时直接截断重写。
- 配合外部 logrotate：它移走文件后向进程发送 `SIGUSR1`，之后的日志写入新建的文件。
- 每行带时间戳、实例启动标识（`boot`）、序号（`seq`）和阶段，对端文本里的控制字符会被转义，不会伪造日志行。
- 生命周期事件以 `event=` 字段记录，例如 `config.published`、`reload.committed`、`module.failed`、`network.changed`（网络监视器去抖后的变化批次）。

## 7. 断网、网络恢复与降级

FTUN 的设计目标是"断网不退出，网络恢复后自动恢复服务"，具体行为：

- **启动时没有网络**：进程正常启动。FRS 规则集合以未就绪状态启动，命中这些规则的新连接被拒绝，下载按退避重试；监听地址不存在时对应监听进入"等待恢复"，运行状态为降级。本地 FRS 文件损坏仍然会让启动失败，这与"没有网络"不同。
- **运行中断网**：已有连接按各自的存活检测回收（TCP keepalive、`base.timeouts.write-progress`），服务继续运行；DNS 上游多地址时按被动健康检查切换，单个上游失败不会让进程退出。
- **网络恢复**：内核网络事件（链路、地址、路由、策略规则）经约 500 毫秒去抖后，提前触发各恢复项（监听重新绑定、FRS 下载、url-test 重新探测、UDP 出口重试、TUN 对账），无需等待退避到期。事件风暴（60 秒内超过 30 批）会被计数并告警。
- **TUN**：断网期间保护规则保留，不会把 FTUN 自己的流量卷入 TUN；恢复时先保证保护再恢复可达性。
- **仍会导致进程退出的情况**：内部状态损坏（退出码 3）与看门狗触发（退出码 4）。其余故障按服务或对象隔离，不影响整个进程。

## 8. 排错线索

- `ftun check -c CONFIG`：只做配置解析与校验，不启动服务。
- `ftun version`：列出产物实际内置的模块。
- 启动失败时错误信息给出失败阶段（`stage N`）；`event=` 行记录模块 `preparing/prepared/active/failed` 的顺序，可据此判断卡在哪个模块。
- 断网期间"为什么某些连接被拒绝"：查日志里 FRS 是否仍未就绪（`frs-not-ready`）。

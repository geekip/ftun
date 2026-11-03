# 部署与运维手册

本文面向在 Linux 网关、路由器上部署 FTUN 的人。字段含义见[配置参考](configuration.md)，各项功能的实现程度见[实现符合度矩阵](conformance.md)。

## 1. 运行条件

- Linux 提供 amd64/arm64/armv7/mips/mipsel 的 IPv4/IPv6 musl 全静态程序。Darwin/Windows 用户态运行要求与限制见[平台构建说明](building.md)。
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
| 配置 | `~/.ftun/config.json` | 只有不带 `-c` 的 `run` 才在缺失时创建最小配置；新建目录 0700、文件 0600 |
| PID 文件 | POSIX root：`/run/ftun/ftun.pid`；其他用户：`~/.ftun/ftun.pid` | `-p FILE` 可指定；进程持独占锁到实际退出，残留文件本身不表示实例存活 |
| 本机控制端点 | PID 路径去掉末尾 `.pid` 后加 `.sock` | 例如 `/run/ftun/ftun.sock`；Unix 流套接字，权限 0600，仅相同 uid 或 root 可操作 |
| 状态缓存 | `base.cache-file`，默认 `~/.ftun/ftun.cache` | Group/Health 快照；`base.state-cache=false` 时不使用；使用时持 `<cache-file>.lock` |
| FakeIP 状态目录 | `<base.cache-file>.fakeip` | 持久模式只在整个目录不存在时自动创建；已有目录缺文件、损坏、池身份不符或锁冲突都拒绝启动 |
| FRS 规则文件 | `frs.path` | 启动校验文件与被引用集合；不存在且配置自动更新时可先以未就绪状态启动 |
| 日志文件 | `log.file`，默认 `~/.ftun/ftun.log` | file/both 或后台运行时使用，持 `<log.file>.lock`，防止不同实例混写 |
| TUN 网络锁 | `/run/ftun-net-<路由表号>.lock` | 仅 TUN 自动路由使用 |

配置中的相对文件路径以配置文件目录为基准。FTUN 以运行用户权限读写文件。多实例使用不同 PID、缓存、FakeIP、日志路径，并按第 2 节分配不同的网络标识。正常退出清理自身 PID 与控制端点；异常退出后可按锁状态接管残留路径。Unix 套接字路径受系统长度限制，实例目录应保持简短。

FakeIP 初始化会生成 UUID、预留记录和空快照；身份建立成功前不分配映射。首次创建要求内核和文件系统支持原子、无覆盖的目录发布；Linux 使用 `renameat2(RENAME_NOREPLACE)`，无法使用时明确失败。重启沿用既有身份与映射，释放会话不会回收或跨域复用 FakeIP。备份应包含整个 `.fakeip` 目录；不能只删除其中某个文件来“修复”身份。变更持久化模式或实际地址池需要重启；同一 CIDR 的主机位别名会规范化为同一个池。

## 4. TLS 与 CA

HTTPS 下载总是校验证书链、有效期和主机名；数值 IPv4/IPv6 目标按 IP SAN 校验。可通过运行环境变量 `SSL_CERT_FILE` 指定 CA 文件；未指定时依次查询 `/etc/ssl/certs/ca-certificates.crt`、`/etc/pki/tls/certs/ca-bundle.crt`、`/etc/ssl/ca-bundle.pem`、`/etc/ssl/cert.pem`。没有可用 CA 时下载失败，已有规则继续使用。日志中的 `tls_code` 和 `tls_reason` 保留实际 TLS 库错误；没有关闭校验的选项。

## 5. 运行、查询与控制

```sh
# 首次运行：缺失时创建默认配置，回环 SOCKS5 127.0.0.1:1080 + DIRECT
ftun run

# 检查现有配置，不绑定端口、不创建持久身份
ftun check -c /etc/ftun/config.json
ftun check -c /etc/ftun/config.json --json

# 独立实例：后台启动在就绪后返回；服务管理器应使用前台方式
ftun run -c /etc/ftun/config.json -p /run/ftun/edge.pid -b
ftun status -p /run/ftun/edge.pid
ftun dns status -p /run/ftun/edge.pid --json
ftun proxy status -p /run/ftun/edge.pid --json
ftun reload -p /run/ftun/edge.pid --timeout 30
ftun stop -p /run/ftun/edge.pid --timeout 15
```

`check` 的失败输出包含字段路径、阶段和原因；成功列出启用模块以及只在启动时才能验证的端口、权限、状态锁等条件。`check` 成功不保证网络可达。`run` 独立输出 `ready` 或 `ready (degraded: ...)`，即使日志设为 silent 也保留必要结果。`-b` 在 POSIX 上等待子进程完成就绪交接，启动期限为 60 秒；后台自动使用文件日志，输出实际文件位置。Windows 当前不支持 `-b` 和本机管理 IPC，直接前台运行；平台边界见[构建说明](building.md)。

省略定位参数时查询默认 PID 文件；`-p` 定位指定实例；数字 `PID` 与 `-p` 互斥。正常控制先检查 PID 文件锁，再核对控制端点的 PID/boot 身份。重载等待 `committed`、`merged`、`rejected` 或 `restart-required`；准备失败保留旧配置，已建立连接保持旧代次。在途重载期间到达的请求合并到唯一一批后续重载，在上一事务结束后重新读取配置；这批请求共享新的 `op_id`，成功回复 `merged` 并设置 `merged=true`，退出码为 0。排队批次未能提交时，`AGAIN`/`LIMIT` 回复 `busy` 并计入拒绝数。停止前尚未提交的请求回复 `rejected`、`status=not-executed`，CLI 退出 1；已在途但没有终态回调的请求仍报告结果未知（退出 5）。停止等待实际运行资源收尾。默认 stop 等待 15 秒、reload 等待 30 秒，`--timeout` 范围 1～3600 秒。

`--no-wait` 只取得接纳回执，不代表操作完成。命令带 `--json` 时 stdout 是单个 JSON 对象；操作的 `result`、`via`、`pid`、`op`、`generation`、`elapsed_ms` 等字段用于自动化。查询输出有数量和行数上限，超出标记 `truncated` 并保留总数；计数和模块状态来自同次 owner 快照。`status` 给出实例、配置代次、资源和日志账本；`dns status` 给出监听、上游、缓存与查询结果；`proxy status` 给出监听、组选择、出口计数及 FRS 状态。

只有显式数字 PID 无法对应默认实例时，stop/reload 才可走原生信号方式。它不提供本机 IPC 的身份校验：stop 等待原生进程退出，reload 无法确认提交结果。信号提交后的结果未知返回 5，不能当作重载成功。`-p` 端点不可用时直接报告失败，不猜测进程。

| 退出码 | 含义 |
|---|---|
| 0 | 查询/检查成功、已确认 committed/stopped；`--no-wait` 时仅表示 IPC 已接纳 |
| 1 | 配置校验、启动预检或操作失败、拒绝、需要重启、找不到实例 |
| 2 | 命令行用法错误 |
| 3 | 运行时致命错误或模块启动失败 |
| 4 | 看门狗触发 |
| 5 | 等待超时或信号提交后拿不到真实终态；结果未知 |

### 服务管理器与信号

前台模式支持 `SIGTERM`/`SIGINT` 停止、`SIGHUP` 重载、`SIGUSR1` 重开日志。信号处理器只通知安全控制通道；主循环处理配置和日志。

`base.watchdog` 默认 30 秒，主循环长时间没有心跳时退出 4；断网不应触发看门狗。systemd 使用 `Type=notify`，FTUN 直接写 `NOTIFY_SOCKET` 并按 `WATCHDOG_USEC` 喂狗，不依赖 libsystemd。服务管理器负责进程监督，FTUN 保持前台；不要同时使用 `-b`。

- [systemd 样例](../packaging/systemd/ftun.service)：显式 PID 文件，reload/stop 使用可等待终态的 CLI。
- [OpenWrt procd 样例](../packaging/openwrt/ftun.procd)：前台进程监督与 respawn。
- [Padavan 启停样例](../packaging/padavan/ftun.sh)：通过 `-b` 启动，使用同一 PID 文件查询和控制。

服务环境可能没有 `HOME`。三份样例头部均提供可合入配置的绝对缓存与日志路径；systemd 同时创建状态及日志目录。只在启用状态缓存、持久 FakeIP 或文件日志时需要相应路径，未使用的 `~` 默认值不会阻止启动。Padavan 的旧内核若不支持 `renameat2(RENAME_NOREPLACE)`，持久 FakeIP 首次创建会明确失败；可使用 `dns.fake-ip.persist=false` 的内存模式。

## 6. 日志

`log.level` 可选 silent、error、warn、info（默认）、debug、trace；`log.output` 可选 stderr（默认）、file、both。`-v` 覆盖为 debug、`-vv` 覆盖为 trace，并在重载后保留。后台将 stderr/both 改为 file；silent 保持静默。终端 stderr 可给级别着色，`--no-color` 或 `NO_COLOR` 关闭颜色，文件永不带颜色码。

```text
[2026-11-02 10:00:00.123 +0800][proxy ][WARN ] dial failed (first): sid=42 gen=1 err=rejected entity=DIRECT errno=ECONNREFUSED
[2026-11-02 10:01:00.123 +0800][proxy ][WARN ] dial failed: gen=1 err=rejected entity=DIRECT count=37 in=60s
[2026-11-02 10:01:03.123 +0800][proxy ][INFO ] dial recovered: gen=1 entity=DIRECT count=40 duration_ms=63000
```

每行是本地毫秒时间、UTC 偏移、模块、级别和事件短语，随后是键值字段。仅当 `JOURNAL_STREAM` 的设备与 inode 匹配实际 stderr 时省略 stderr 时间。`boot` 在启动行输出，序号由状态中的日志账本查询，不在每行重复；`sid` 关联 DNS 查询或代理会话，`op` 关联管理操作，`gen` 标识配置代次。对端文本经过控制字符转义和长度限制，密码不进入日志。

info 记录生命周期、状态变化和故障恢复，正常转发不逐连接输出；debug 可见 DNS query/answer/cache hit 及 Proxy connect/rule matched/closed。详细日志可能因队列压力丢弃，应查看 `status --json` 中日志计数。重复故障按配置实体聚合：首次告警、60 秒窗口汇总、真实恢复后记录次数与持续时间；停止或实体退休时汇总未完成窗口，不伪报恢复。聚合表有固定容量，溢出使用模块计数，不按任意域名或客户端创建无限标签。

文件轮转由 `log.max-size`（默认 10 MiB，0 不轮转，否则至少 64 KiB）和 `log.max-files`（含当前文件，默认 3，范围 1～32）控制。超限前依次移动到 `.1`、`.2` 等；只保留一个文件时截断重写。轮转失败后继续写原文件句柄，后续写入每隔至少 1 秒尝试自动恢复；先重开原路径，再继续未完成的改名，不重做已完成步骤，避免反复移动或覆盖历史文件。外部 logrotate 移走文件后发送 `SIGUSR1` 重开。writer 的丢弃、轮转和写入失败通过独立诊断报告，不递归入日志队列；计数仍可查询。文件写入的系统调用失败时，`native` 保留实际 POSIX errno 或 Windows 错误码，例如 Linux 的 `native=28` 表示 ENOSPC。日志写入成功不等同于文件已耐久落盘。

## 7. 断网、网络恢复与降级

- 启动时没有网络：进程可降级运行。FRS 缺失但有自动更新配置时先未就绪，命中 FRS 规则的新连接被拒绝；本地 FRS 损坏仍拒绝启动。监听地址尚未配置时进入 waiting。
- 运行中断网：连接按 TCP keepalive、写入进展和期限回收；DNS 多地址按健康状态切换。拨号、解析和下载故障聚合报告，其他入口继续工作。
- 网络恢复：Linux 网络事件约 500 毫秒去抖后提前触发监听绑定、FRS 下载、URL-Test、UDP 出口及 TUN 对账。60 秒内超过 30 个变化批次形成风暴告警。
- TUN：保护规则缺失会明确告警，对账补回后报告恢复；设备被删除后重建。关闭自动路由的平台仍需自行维护路由。
- 内部状态损坏与看门狗可能结束实例；不能把一次超时直接理解为整个服务已停止。

## 8. 排错流程

1. 先执行 `ftun check -c CONFIG --json`，按 `field`、`stage`、`message` 修正配置；检查只读，不修复损坏状态。
2. 执行 `ftun status -p PIDFILE --json`，核对 `boot`、配置路径、`generation`、各服务状态及资源拒绝/日志丢弃计数。
3. DNS 故障查看 `dns status` 的监听、上游和缓存，结合 `upstream failures`、`response invalid`、`group switched` 与恢复事件判断。
4. 代理故障查看 `proxy status` 的监听、出口和组选择；`frs-not-ready` 表示规则未就绪，`errno`/`tls_code`/`tls_reason` 给出实际底层原因。需要会话细节时用 `run -v`。
5. reload 返回 `rejected` 或 `restart-required` 时活动代次保持原值；返回 5 时保留不确定结论，再查询状态和同一 `op` 的结果日志。
6. 停止卡住时查看最后的 quiesced/drained/stopped 事件与剩余资源，不把信号已经发出视为资源已完成清理。

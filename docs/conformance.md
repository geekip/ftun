# 实现符合度矩阵

本文逐项说明 FTUN 当前实现了什么、实现到什么程度，以及用哪些测试佐证。"状态"取值：**已实现**（功能完整并有自动化测试）、**部分实现**（有明确的缺口，见说明）、**未实现**（规范目标，当前版本没有）。测试名是 `ctest` 里的名字（`ctest -N` 可列出）；带 `resilience-` 前缀的是在私有网络命名空间里运行的真实内核场景，需要 root。

版本：1.1.0。Linux 提供五种架构的 musl 构建；Darwin/Windows 提供用户态构建。下表的完整内核与长期稳定性证据来自 Linux，其他平台的能力和验证范围见[平台构建说明](building.md)。24 小时长稳一项保留 1.0.x 的历史验证口径，不代表本次 1.1 候选已重新完成 24 小时资格。

## 入站与出站

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| SOCKS5 入站（CONNECT、UDP ASSOCIATE） | 已实现 | 支持用户名密码认证；不加密；`allow-lan` 控制非回环客户端 | `protocol-socks5-contract`、`inbound-socks5-contract`、`fuzz-socks5` |
| Mixed 入站（HTTP 代理 + SOCKS5） | 已实现 | HTTP 仅支持 absolute-form 与 CONNECT；拒绝 userinfo、重复 Host 等歧义请求 | `protocol-http-contract`、`inbound-mixed-contract`、`fuzz-http` |
| TUN 入站（TCP/UDP） | 已实现 | IPv4；TCP 经 lwIP 终结；自动路由需要 root 或 `CAP_NET_ADMIN` | `tun-owner-composition-contract`、`tun-service-contract`、`resilience-R10`、`resilience-R14` |
| DIRECT / REJECT 出站 | 已实现 | | `outbound-direct-contract`、`outbound-reject-contract` |
| SOCKS5 出站（TCP、UDP） | 已实现 | 域名或 IPv4 服务器地址；失败不回退为直连 | `outbound-socks5-contract`、`protocol-socks5-client-contract`、`outbound-contract` |
| Select / URL-Test 代理组 | 已实现 | URL-Test 失败退避，网络变化时提前重新探测 | `route-router-contract`、`group-cache-contract` |
| IPv6 | 已实现 | Socket、DNS A/AAAA、SOCKS5、TUN 与 CIDR 规则双栈；FakeIP 池和现有 FRS IP 数据格式保留 IPv4 | `ipv6-product`、`ipv6-tun-production`、`resolver-dual-contract` |
| AnyTLS、VLESS、VMess、QUIC、混淆 | 未实现 | | |
| Full Cone NAT、Mesh、NAT 穿透、P2P/Relay | 未实现 | | |
| 管理 HTTP API、Web 控制台 | 未实现 | 现有管理通过本机 Unix IPC、CLI 和宿主 C API | |

## 规则、DNS 与规则集合

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| 顺序规则（源 IP、IP、域名、后缀、关键字、端口、网络、MATCH） | 已实现 | | `route-rule-contract`、`route-router-contract` |
| FRS 规则集合（二进制格式 1.0） | 已实现 | 读取时校验边界、环与校验和；引用的集合缺失、类型错误或为空会阻止启动 | `fuzz-frs`、`untrusted-parsers-regression` |
| FRS 自动更新（HTTP/HTTPS） | 已实现 | 总是校验证书与主机名；系统 CA 或 `SSL_CERT_FILE`，下载、校验与发布分别可见 | `http-fetch-production`、`maintenance-events-product`、`resilience-R1`、`resilience-R3` |
| 无网络启动 | 已实现 | FRS 以未就绪状态启动，命中其规则的新连接被拒绝，后台退避下载 | `resilience-R1`、`resilience-R3` |
| DNS 监听（UDP、TCP） | 已实现 | 监听地址不存在时进入等待恢复，不让进程退出 | `resilience-R1`、`resilience-R5` |
| DNS 上游（UDP、TCP，多地址） | 部分实现 | 多地址按被动健康检查切换，单次查询最多换一个地址；没有主动测速；不支持 DoT/DoH | `resilience-R4` |
| DNS 响应校验 | 已实现 | 校验事务 ID/Question；非关联应答忽略至期限，关联但畸形的应答记为校验失败 | `fuzz-dns`、`dns-events-product` |
| FakeIP | 已实现 | 持久目录不存在时自动创建身份；已有状态拒绝静默重建；实际池范围或持久化模式更改需要重启 | `fuzz-fakeip`、`fakeip-startup-product`、`fakeip-cidr-product`、`fakeip-events-product` |
| TLS SNI / HTTP Host 嗅探 | 已实现 | | `sniff-tls-contract`、`sniff-http-contract`、`fuzz-sniff` |

## 运行时可靠性

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| 断网不退出，恢复后自动恢复 | 已实现 | 恢复调度器统一管理监听、FRS、url-test、UDP 出口与 TUN；网络变化事件提前触发 | `resilience-R1` 至 `resilience-R5` |
| 网络变化监视（netlink） | 已实现 | 链路、地址、路由、策略规则；500 毫秒去抖，缓冲溢出按"全部变化"处理 | `netmon-contract`、`resilience-R3` |
| TUN 崩溃后对账、增量修复、设备重建 | 已实现 | 启动清理同表同优先级协议号 186 遗留对象；运行中补回缺失的自有对象；设备被外部删除后重建 | `platform-linux-route-async`、`resilience-R10`、`resilience-R14` |
| 连接存活与空闲回收 | 已实现 | TCP keepalive；转发连接按累计确认字节判定停滞；可选 `tcp-idle` | `liveness-product`、`resilience-R8` |
| 心跳看门狗与 systemd 集成 | 已实现 | 默认 30 秒，退出码 4；`NOTIFY_SOCKET`/`WATCHDOG_USEC` | `watchdog-contract`、`watchdog-product`、`resilience-R2` |
| 故障隔离 | 部分实现 | 收尾失败的流转入隔离区重试；两个依赖测试钩子的场景（监听错误注入、owner 卡死注入）在产品构建里无法运行，由单元测试覆盖 | `app-service-fault-contract`、`resilience-R9`（跳过）、`resilience-R11`（跳过） |
| 事务性重载 | 已实现 | 新配置整体准备后才提交，失败保持旧配置；旧代次数量由 `base.reload-retain` 限制 | `app-host-contract`、`resilience-R6` |
| 24 小时长稳 | 已实现 | 同一进程连续 24 小时，约 430 次故障注入（断网、地址变化、链路抖动、FD 耗尽、重载风暴、DNS 上游故障、慢读与静默失联），最大恢复 7.5 秒，稳态探测零失败；组合、DNS-only、Proxy-only 三种配置各一个静态 musl 实例，另有 ASan/UBSan 与 TSan 实例。不含 R9/R10/R11 | `tests/resilience/soak.py` |

## 可观测性与进程管理

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| 模块日志与关联 | 已实现 | 本地毫秒时间、UTC 偏移、模块、级别、短语和键值；boot 在启动行，序号由状态查询，sid/op/gen 关联业务与操作；对端文本转义，队列满时丢弃计数 | `logger-contract`、`event-log-contract`、`fuzz-log`、`dns-events-product`、`proxy-events-product` |
| 日志文件轮转与重新打开 | 已实现 | 按大小轮转；`SIGUSR1` 重新打开 | `logger-contract`、`log-rotation-product` |
| 生命周期和业务故障聚合 | 已实现 | 首次、窗口汇总、真实恢复及退休汇总；固定表和模块溢出计数 | `event-log-contract`、`log-aggregate-contract`、`maintenance-events-product`、`network-events-product` |
| 状态与计数查询 | 已实现 | status/dns status/proxy status 的有界文本和 JSON；尚无 HTTP/Prometheus 接口 | `cli-status`、`ctl-status-contract` |
| 实例身份与实例锁 | 已实现 | PID/缓存/日志/FakeIP 锁；Unix IPC 校验 uid、PID/boot；数字 PID 的信号方式按实际结果报告不确定性 | `cli-instances`、`cli-file-locks`、`ctl-server-product`、`cli-control` |
| 首次配置与后台化 | 已实现 | 无 -c 的 run 创建缺失配置；POSIX -b 等待真实就绪，Windows 明确不支持后台化和本机 IPC | `run-startup-product`、`background-product` |
| 配置诊断 | 已实现 | check/run/reload 包含字段、阶段、原因；check 保持只读 | `config-errors-product` |
| 退出码 | 已实现 | 0 / 1 / 2 / 3 / 4 / 5；5 表示结果未知，见[部署与运维手册](operations.md) | `cli-v05-contract`、`cli-control`、`cli-results-product` |

## 集成

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| 公开 C API | 已实现 | ABI 版本 1，布局固定为 v1.0.2 已发布版本；`options` 通过 `struct_size` 接受较短输入 | `c-api-abi-v102`、`c-api-abi-current` |
| 构建时裁剪模块 | 已实现 | DNS、FakeIP、TUN、FRS 可选；全静态 musl 产物 | `build-modules-matrix`、`release-elf-contract` |
| 配置 Schema | 已实现 | 结构与取值范围；字段间关系由 `ftun check` 校验 | `config-schema`、`docs-configuration` |

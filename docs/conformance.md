# 实现符合度矩阵

本文逐项说明 FTUN 当前实现了什么、实现到什么程度，以及用哪些测试佐证。"状态"取值：**已实现**（功能完整并有自动化测试）、**部分实现**（有明确的缺口，见说明）、**未实现**（规范目标，当前版本没有）。测试名是 `ctest` 里的名字（`ctest -N` 可列出）；带 `resilience-` 前缀的是在私有网络命名空间里运行的真实内核场景，需要 root。

版本：1.0.x。Linux 提供五种架构的 musl 构建；Darwin/Windows 提供用户态构建。下表的完整内核与长期稳定性证据来自 Linux，其他平台的能力和验证范围见[平台构建说明](building.md)。

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
| 管理 HTTP API、Web 控制台 | 未实现 | 进程控制只有信号与 `ftun stop/reload` | |

## 规则、DNS 与规则集合

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| 顺序规则（源 IP、IP、域名、后缀、关键字、端口、网络、MATCH） | 已实现 | | `route-rule-contract`、`route-router-contract` |
| FRS 规则集合（二进制格式 1.0） | 已实现 | 读取时校验边界、环与校验和；引用的集合缺失、类型错误或为空会阻止启动 | `fuzz-frs`、`untrusted-parsers-regression` |
| FRS 自动更新（HTTP/HTTPS） | 已实现 | 总是校验证书与主机名；CA 路径固定为系统常见位置 | `http-fetch-production`、`resilience-R1`、`resilience-R3` |
| 无网络启动 | 已实现 | FRS 以未就绪状态启动，命中其规则的新连接被拒绝，后台退避下载 | `resilience-R1`、`resilience-R3` |
| DNS 监听（UDP、TCP） | 已实现 | 监听地址不存在时进入等待恢复，不让进程退出 | `resilience-R1`、`resilience-R5` |
| DNS 上游（UDP、TCP，多地址） | 部分实现 | 多地址按被动健康检查切换，单次查询最多换一个地址；没有主动测速；不支持 DoT/DoH | `resilience-R4` |
| DNS 响应校验 | 已实现 | 校验事务 ID，不匹配或畸形响应按上游失败处理 | `fuzz-dns` |
| FakeIP | 已实现 | 池范围与持久化模式更改需要重启；持久化需先 `ftun fakeip init` | `fuzz-fakeip` |
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
| 结构化日志（时间戳、实例标识、序号、关联 ID） | 已实现 | 对端文本转义；日志满时丢弃并计数，不阻塞主循环 | `logger-contract`、`event-log-contract`、`fuzz-log` |
| 日志文件轮转与重新打开 | 已实现 | 按大小轮转；`SIGUSR1` 重新打开 | `logger-contract`、`log-rotation-product` |
| 生命周期事件目录 | 已实现 | | `event-log-contract` |
| 指标（计数查询） | 部分实现 | 日志与服务故障计数可经控制查询读取；没有对外的指标接口 | `app-control-contract` |
| 实例身份与实例锁 | 部分实现 | TUN 自动路由按路由表号加锁；`stop`/`reload` 只是向给定 PID 发信号，不校验进程身份 | `resilience-R10` |
| 退出码 | 已实现 | 0 / 1 / 2 / 3 / 4，见[部署与运维手册](operations.md) | `cli-v05-contract` |

## 集成

| 能力 | 状态 | 说明 | 佐证 |
|---|---|---|---|
| 公开 C API | 已实现 | ABI 版本 1，布局固定为 v1.0.2 已发布版本；`options` 通过 `struct_size` 接受较短输入 | `c-api-abi-v102`、`c-api-abi-current` |
| 构建时裁剪模块 | 已实现 | DNS、FakeIP、TUN、FRS 可选；全静态 musl 产物 | `build-modules-matrix`、`release-elf-contract` |
| 配置 Schema | 已实现 | 结构与取值范围；字段间关系由 `ftun check` 校验 | `config-schema`、`docs-configuration` |

# FTUN 1.0.1 发行说明

FTUN 1.0.1 是 Linux x86_64 IPv4 稳定性与性能修复版，保持 1.0 的公开 C ABI、
配置语义和 FRS 1.0 文件格式。

1.0.1 功能候选的短时全矩阵已经通过，但正式发布冻结仍要求在内容不变、已提交
且干净的候选上完成连续至少 24 小时长稳。本说明不表示该门槛已经完成。

## 主要修复

- FRS 结构校验安全拒绝环和越界节点，不再被合法 checksum 的异常文件触发越界。
- TUN 和 SOCKS5 UDP 共用 FakeIP 恢复、异步多地址解析和 First Match Wins 路由。
- 单个 UDP 报文、flow 或 association 错误限定在局部，不再停止整个进程。
- 生产数据面统一使用 libev 事件兴趣，空闲 TCP 不再持续订阅可写事件。
- 域名解析、FRS 下载/校验/Runtime 候选准备与持久化移出 owner loop，
  连接解析与后台维护使用隔离的有界队列。
- preread 改为按需分配，FRS view、worker 峰值和数据面对象纳入全局预算；
  Relay、UDP、lwIP wrapper 与 Operation 使用有界复用。
- UDP flow 和 SOCKS5 association 采用完整键索引与有界过期扫描，各入口使用公平配额。
- 只在启用 TUN 时要求 `SO_MARK`；SOCKS5/Mixed-only 部署可由无网络 capability
  的普通用户转发。

## 调优结论

- lwIP 默认 TCP 收发窗口调整为约 64 KiB，保持不启用窗口扩大；未引入
  多个有序在途 slice。
- Release 保持 `-O2` 与 section GC，`-Os` 保留为体积档，LTO 保留为独立
  验证档；发行包可剥离符号并单独保存调试符号。
- 实际 SOCKS5 UDP 负载未证明 `recvmmsg`/`sendmmsg` 足以抵消兼容和状态复杂度，
  因此 1.0.1 保持通用整包路径。

## 兼容与权限

IPv6、AnyTLS、管理 HTTP API、Full Cone、ARM/OpenWrt 和非 Linux 平台仍不在支持
声明内。TUN/自动路由需要 root 或等价网络能力；只启用 SOCKS5/Mixed 入站时
不需要 `CAP_NET_ADMIN` 或 `CAP_NET_RAW`。

构建、矩阵、性能和资源数据见[构建、交付与验证基线](build-release.md)。本文件不代表
已创建或推送 `v1.0.1` tag；提交、推送和打 tag 仍需仓库所有者明确授权。

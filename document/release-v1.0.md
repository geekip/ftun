# FTUN 1.0 发行说明

FTUN 1.0 冻结首个稳定的 Linux x86_64 IPv4 范围。源码版本、配置语义、FRS 1.0 reader、公开 C ABI 和发行门禁以仓库中的文档、Schema、依赖锁与验证记录为准。

## 支持范围

- TUN 本机与 LAN 透明 TCP/UDP，以及 SOCKS5 和 Mixed 显式入站。
- DIRECT、REJECT、SOCKS5、Select 和 URL-Test 出站/组策略。
- 顺序规则、DNS UDP/TCP、FakeIP 与持久化、TLS SNI/HTTP Host 嗅探。
- FRS IPv4/域名集合加载、查询、启动下载和自动更新。
- 事务重载、信号/CLI 控制、公开 C 生命周期、诊断与状态缓存。
- glibc 标准构建、Linux x86_64 musl 全静态构建及模块 OFF/BUILTIN 裁剪。

## 明确不包含

IPv6、AnyTLS、管理 HTTP API、Full Cone、ARM/OpenWrt、Windows、macOS 和移动平台不在 1.0 支持声明内。未知或未实现配置不会静默降级为其他行为。

## 兼容与运行边界

- 首版网络范围是 IPv4；FRS 文件格式为 1.0，并预留但不启用 IPv6 能力。
- 规则 First Match Wins；名称、label、域名归一化和 FRS 引用遵循公开配置文档与 Schema。
- TUN/自动路由需要 root 或等价网络能力。SOCKS5/Mixed-only 部署不要求创建 TUN。
- `ftun version` 输出产品版本、构建时源码 revision 和实际内置能力；正式发行产物应来自不带 `-dirty` 的固定 revision。

## 交付与许可

FTUN 使用 GNU GPL v3。当前 wolfSSL 也按 GPLv3 开放源码许可组合；商业闭源用途需另行取得合适的 wolfSSL 商业许可并复核整体分发条件。发行包包含根 `LICENSE`、第三方 notice、依赖锁和实际依赖许可证。

构建、测试、资源阈值、静态 ELF 与安装卸载证据见[构建、交付与验证基线](build-release.md)。本文件冻结发行内容，不代表仓库已经创建或推送 `v1.0.0` tag；提交、推送和打 tag 仍按仓库所有者的明确授权执行。

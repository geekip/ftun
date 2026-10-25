# FTUN

FTUN 是一个轻量、可裁剪的代理内核，面向 Linux 网关、透明代理和嵌入式宿主集成。它提供独立命令行程序和稳定的 C API，通过规则、DNS、FakeIP、FRS 规则集合与代理组处理 TCP/UDP 流量。

当前版本为 **1.0.3**，正式支持 Linux x86_64 IPv4。项目采用 C99 和 CMake，可生成 musl x86_64 全静态程序；功能在构建时选择并静态内置，运行时只为配置启用的服务分配资源。

## 主要能力

- TUN、SOCKS5 和 Mixed 入站，支持 TCP 与 UDP。
- DIRECT、REJECT、SOCKS5、Select 和 URL-Test 出站与代理组。
- 顺序匹配规则，支持域名、IP、端口、网络类型与 FRS 规则集合。
- DNS UDP/TCP 服务、Bootstrap、FakeIP 映射和状态持久化。
- TLS SNI 与 HTTP Host 嗅探。
- 配置检查、事务重载、进程控制和宿主 C API。
- Core、DNS、Proxy 与 TUN provider 模块化构建，可按组合裁剪。

FTUN 当前不提供 IPv6、AnyTLS、管理 HTTP API、Full Cone、Mesh、NAT 穿透、P2P/Relay、QUIC 或协议混淆。`ftun version` 会列出产物实际内置的能力。

## 快速开始

需要 C99 编译器和 CMake 3.21 或更新版本。配置与构建默认不联网，第三方源码按仓库锁定版本使用。

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug

./build/debug/ftun version
./build/debug/ftun check -c examples/minimal.json
./build/debug/ftun run -c examples/minimal.json
```

可用命令：

```text
ftun version
ftun help
ftun check -c CONFIG
ftun run -c CONFIG
ftun stop PID
ftun reload PID
ftun fakeip init -c CONFIG
```

TUN 与自动路由需要 root 或相应网络能力。只使用 SOCKS5/Mixed 入站时，普通用户只需具备监听端口、配置文件和状态文件权限。系统无法建立必需的出口保护时，FTUN 会在启动阶段失败并报告原因。

## 配置与集成

- [配置 JSON Schema](schema.json)
- [可运行配置样例](examples/)
- [公开 C API](include/ftun/ftun.h)

默认预设内置 DNS、FakeIP、TUN 和 FRS。可通过 `FTUN_MODULE_DNS`、`FTUN_MODULE_FAKEIP`、`FTUN_MODULE_TUN`、`FTUN_MODULE_FRS` 选择 `OFF` 或 `BUILTIN`；FakeIP 依赖 DNS。构建生成的 `ftun-build-modules.txt` 记录实际模块组合。

完整样例包含需要替换的测试地址、端点和探测 URL。运行前先阅读 [样例说明](examples/README.md)，再准备网络权限、CA、FRS 文件和 FakeIP 状态。

## 许可

FTUN 使用 [GNU GPL v3](LICENSE)。依赖版本、第三方许可选择与修改说明统一见 [third_party/LOCK.json](third_party/LOCK.json)。构建自动生成第三方告知，安装目录为 `share/doc/ftun/THIRD_PARTY_NOTICES.md`，发布包中位于 `docs/`，并附所用组件的许可原文。wolfSSL 当前按 GPLv3 开放源码许可组合分发；商业闭源分发需要另行取得合适许可并复核整体许可义务。

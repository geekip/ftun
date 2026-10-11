# FTUN

FTUN 的目标是成为轻量、可裁剪的跨平台代理内核，提供命令行程序与供宿主集成的 C 接口，并通过 TUN、规则、DNS、FakeIP、FRS 规则集合和代理组处理透明 TCP/UDP 流量。

架构采用核心加可选编译模块：功能在构建时选择并静态内置，取消运行时动态插件。已编译功能按配置激活资源；Linux musl 全静态交付继续保留。

## 当前状态

当前源码版本为 **1.0.0**，正式支持 Linux x86_64 IPv4。`ftun run` 会装配
TUN、SOCKS5、Mixed、DNS、FakeIP、FRS、规则、Select/URL-Test、DIRECT、
REJECT 和 SOCKS5 出站数据面，并支持 TCP/UDP、TLS SNI/HTTP Host 嗅探及
SIGHUP 事务重载。

首版不包含 IPv6、AnyTLS、管理 HTTP API、Full Cone 和非 Linux 平台。
TUN/自动路由需要 root 或相应网络能力；只使用 SOCKS5/Mixed 入站时可按监听权限运行。

## 文档

- [公开 C API](include/ftun/ftun.h)
- [CLI、运行与宿主控制](document/control.md)
- [v1.0 构建、交付与验证基线](document/build-release.md)
- [v1.0 发行说明](document/release-v1.0.md)
- [配置 JSON Schema](schema.json)
- [配置样例](examples/)
- [用户手册目录](document/)（随可用功能逐步补充）

## 构建与测试

需要 C99 编译器与 CMake 3.21 或更新版本。配置与构建默认不联网；所需第三方源码通过仓库锁定。项目预设启用 DNS、FakeIP、TUN 和 FRS 内置模块，也可以通过 `FTUN_MODULE_DNS`、`FTUN_MODULE_FAKEIP`、`FTUN_MODULE_TUN`、`FTUN_MODULE_FRS` 选择 `OFF` 或 `BUILTIN`；FakeIP 内置时要求 DNS 同时内置。

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug
./build/debug/ftun version
./build/debug/ftun check -c /path/to/config.json
./build/debug/ftun run -c /path/to/config.json
```

`ftun version` 同时报告构建时源码 revision（工作树有改动时带 `-dirty`）和实际
内置能力清单，便于把运行产物关联到固定源码与裁剪配置。

公开接口位于 [include/ftun/ftun.h](include/ftun/ftun.h)，内部接口位于各模块目录。FRS 配置和规则示例见 [examples/frs.json](examples/frs.json)；`.frs` 生成工具属于独立项目，不随 FTUN 构建或安装。

FTUN 采用 [GNU GPL v3](LICENSE)。依赖锁见
[third_party/LOCK.json](third_party/LOCK.json)，第三方许可说明见
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；wolfSSL 当前按 GPLv3 开放源码许可
组合分发，商业闭源用途需另行取得适当的商业许可。

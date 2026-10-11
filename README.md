# FTUN

FTUN 的目标是成为轻量、可裁剪的跨平台代理内核，提供命令行程序与供宿主集成的 C 接口，并通过 TUN、规则、DNS、FakeIP、FRS 规则集合和代理组处理透明 TCP/UDP 流量。

架构采用核心加可选编译模块：功能在构建时选择并静态内置，取消运行时动态插件。已编译功能按配置激活资源；Linux musl 全静态交付继续保留。

## 当前状态

当前源码版本为 **0.5.0-dev**。v0.5 已提供配置检查、进程信号控制、事务重载、Select 选择、组状态缓存、TLS SNI/HTTP Host 嗅探、有界异步日志，以及可由宿主调用的 C 生命周期接口；已有模块和受控集成测试覆盖 Linux TUN/lwIP、SOCKS5、DNS/FakeIP、顺序路由、Mixed 入站、代理组、FRS 1.0 和 wolfSSL TLS。

当前 `ftun run` 只运行已验证的控制面 Runtime，还没有自动装配生产 listener/socket/Event、Session、Router 与 Outbound 数据面，因此不会接管或代理实际流量。它适合验证配置、进程控制和重载边界，不应被当作可部署代理。Linux x86_64 仍是首个正式验收目标。

## 文档

- [公开 C API](include/ftun/ftun.h)
- [v0.5 CLI 与宿主控制](document/control.md)
- [配置 JSON Schema](schema.json)
- [配置样例](examples/)
- [用户手册目录](document/)（随可用功能逐步补充）

## 构建与测试

需要 C99 编译器与 CMake 3.21 或更新版本。配置与构建默认不联网；所需第三方源码通过仓库锁定。项目预设启用 DNS、TUN 和 FRS 内置模块，也可以通过 `FTUN_MODULE_DNS`、`FTUN_MODULE_TUN`、`FTUN_MODULE_FRS` 选择 `OFF` 或 `BUILTIN`。

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug
./build/debug/ftun version
./build/debug/ftun check -c /path/to/config.json
```

公开接口位于 [include/ftun/ftun.h](include/ftun/ftun.h)，内部接口位于各模块目录。FRS 配置和规则示例见 [examples/frs.json](examples/frs.json)；`.frs` 生成工具属于独立项目，不随 FTUN 构建或安装。

项目拟开源发布，最终许可证与依赖分发清单仍需发布前审核。当前依赖来源和许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；wolfSSL 的开放源码分发适用 GPLv3，也可另行取得商业许可。

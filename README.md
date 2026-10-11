# FTUN

FTUN 的目标是成为轻量、可裁剪的跨平台代理内核，提供命令行程序与供宿主集成的 C 接口，并通过 TUN、规则、DNS、FakeIP、FRS 规则集合和代理组处理透明 TCP/UDP 流量。

架构采用核心加可选编译模块：功能在构建时选择并静态内置，取消运行时动态插件。已编译功能按配置激活资源；Linux musl 全静态交付继续保留。

## 当前状态

命令行版本仍为 **0.1.0 开发预览**。内部模块已经推进到 v0.4 合约范围，包括 Linux TUN/lwIP、SOCKS5、DNS/FakeIP、顺序路由、Mixed 入站、代理组、FRS 1.0 loader/query/update 和 wolfSSL TLS，并有受控集成测试；生产 listener、Event、Session、Router、Outbound 与 CLI 的自动装配尚未完成，因此当前二进制仍不能作为实际代理运行。Linux x86_64 是首个正式验收目标。

## 文档

- [公开 C API](include/ftun/ftun.h)
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
```

公开接口位于 [include/ftun/ftun.h](include/ftun/ftun.h)，内部接口位于各模块目录。FRS 配置和规则示例见 [examples/frs.json](examples/frs.json)；`.frs` 生成工具属于独立项目，不随 FTUN 构建或安装。

项目拟开源发布，最终许可证与依赖分发清单仍需发布前审核。当前依赖来源和许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；wolfSSL 的开放源码分发适用 GPLv3，也可另行取得商业许可。

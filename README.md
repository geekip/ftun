# FTUN

FTUN 的目标是成为轻量、可裁剪的跨平台代理内核，提供命令行程序与供宿主集成的 C 接口，并通过 TUN、规则、DNS、FakeIP 和代理组处理透明 TCP/UDP 流量。

架构采用核心加可选编译模块：功能在构建时选择并静态内置，取消运行时动态插件。已编译功能按配置激活资源；Linux musl 全静态交付继续保留。

## 当前状态

当前版本为 **0.1.0 开发预览**，仅提供可构建的 C 工程骨架、版本与帮助信息，以及少量接口防御逻辑。运行、解析、转发和代理功能尚未实现，不能用于实际代理。Linux x86_64 是首个正式验收目标；本地骨架编译通过不代表网络功能已经可用。

## 文档

- [公开 C API](include/ftun/ftun.h)
- [配置 JSON Schema](schema.json)
- [配置样例](examples/)
- [用户手册目录](document/)（随可用功能逐步补充）

## 构建骨架

需要 C99 编译器与 CMake 3.21 或更新版本。配置与构建默认不联网；骨架不需要下载第三方依赖。

```sh
cmake --preset debug
cmake --build --preset debug --parallel
ctest --preset debug
./build/debug/ftun version
```

公开接口位于 [include/ftun/ftun.h](include/ftun/ftun.h)，内部接口位于各模块目录。当前骨架不宣称能完整校验或运行目标配置。

项目拟开源发布，最终许可证与依赖分发清单在实际引入上游代码前完成审核；当前没有复制或链接上游实现。

# v0.5 CLI 与宿主控制

FTUN 0.5 提供配置检查、控制进程、事务重载和宿主 C 生命周期接口。当前控制面可以实际运行，但生产 listener/socket/Event、Session、Router 与 Outbound 数据面尚未由 CLI 自动装配；`ftun run` 不会代理流量。

## 命令行

```text
ftun version
ftun help
ftun check -c CONFIG
ftun run -c CONFIG
ftun stop PID
ftun reload PID
ftun fakeip init -c CONFIG
```

- `check` 完成 JSON 解析、语义校验和候选 Runtime 准备，不发布运行代次；配置可不含入站。
- `run` 要求至少一个入站，启动控制面并阻塞。`SIGHUP` 或 `reload PID` 请求事务重载；`SIGINT`、`SIGTERM` 或 `stop PID` 请求停止。
- 重载先完整准备候选 Runtime。失败时报告阶段和错误，继续保留旧代；成功时只影响新连接语义，不迁移既有 Session。TUN 拓扑、FakeIP 范围/持久化模式等不兼容变化要求重启。
- `fakeip init` 为启用持久 FakeIP 的配置创建首次状态文件；已有状态不会被覆盖。

相对路径按配置文件目录解析。启用 FRS 规则时，检查和启动都要求所引用集合可用；文件缺失且允许自动下载时，下载失败会使启动失败。无 FRS 规则时不会加载或更新 FRS。

## C 接口

公开声明位于 [`include/ftun/ftun.h`](../include/ftun/ftun.h)。典型生命周期为：

1. 填写 `ftun_core_options_t` 的 `struct_size`、`abi_version`、内存上限、操作容量和旧 Runtime 保留上限，然后调用 `ftun_core_create`。
2. 在专用线程调用阻塞式 `ftun_core_run`；该线程成为 owner loop。
3. 其他线程可有界投递 `ftun_core_post`、`ftun_core_reload`、`ftun_core_select`，或读取 `ftun_core_get_info`。
4. 完成回调只在 owner loop 执行并恰好调用一次。成功接纳后，调用者须保持 `user` 有效至回调返回；借用的 operation 句柄在回调返回后失效。
5. 跨线程调用 `ftun_core_stop`，等待 `ftun_core_run` 返回，再调用 `ftun_core_destroy`。

0.x 的 ABI 仍允许不兼容调整。宿主必须核对 `FTUN_ABI_VERSION`，不得依赖内部 libev、lwIP 或 TLS 类型。

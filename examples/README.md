# FTUN v1 配置样例

这些文件展示目标配置语义；当前 0.1 骨架拒绝 run/check，不会创建代理服务。

三个样例均通过根字段 `"$schema": "../schema.json"` 引用 [FTUN Schema](../schema.json)，支持编辑器补全和静态校验。移动文件后按新位置调整路径；Schema 不会自动填写默认值，也不检查代理节点可达性。

- [minimal.json](minimal.json)：DNS关闭、回环SOCKS5入站、DIRECT，必要本地解析用系统；不需要FakeIP状态或Geo文件。
- [full.json](full.json)：三类入站、真实/假DNS、固定/策略入口、两种组、顺序规则；192.0.2.0/24 与 example.invalid 是待替换占位地址，不能直接联网运行。
- [geo.json](geo.json)：在完整例上增加私有Geo文件引用；标签必须由用户规则转换产生，当前不提供虚构的Geo数据文件。

完整示例使用 persist=true，实际实现后首次运行必须先显式初始化 FakeIP 状态；状态路径相对该配置文件目录。作为 LAN 网关使用时还需配置系统转发与受管路由，不把 Socket allow-lan 当作 TUN 网关开关。运行前替换真实端点、探测 URL，准备权限和 CA；这些准备不意味着当前骨架支持运行。

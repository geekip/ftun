# FTUN v1 配置样例

这些文件展示目标配置语义。

三个样例均通过根字段 `"$schema": "../schema.json"` 引用 [FTUN Schema](../schema.json)，支持编辑器补全和静态校验。移动文件后按新位置调整路径；Schema 不会自动填写默认值，也不检查代理节点可达性。

- [minimal.json](minimal.json)：DNS关闭、回环SOCKS5入站、DIRECT，必要本地解析用系统；不启动 FRS 模块。
- [full.json](full.json)：三类入站、真实/假DNS、固定/策略入口、两种组、顺序规则与本地 FRS；192.0.2.0/24 与 example.invalid 是待替换占位地址，不能直接联网运行。
- [frs.json](frs.json)：单个多集合 `.frs` 文件、大小写不敏感的 FRS 规则类型、大小写敏感的 label/出口名称以及 HTTP(S) 自动更新。示例 URL 和文件均为占位符。

完整示例使用 persist=true，首次运行必须先显式初始化 FakeIP 状态；状态路径相对该配置文件目录。只要规则引用 FRS 集合，启动就会校验 `.frs` 文件及所有引用集合；文件损坏、集合缺失、类型错误或空集合都会阻止完整 Runtime 就绪。作为 LAN 网关使用时还需配置系统转发与受管路由，不把 Socket allow-lan 当作 TUN 网关开关。运行前替换真实端点、探测 URL，准备权限和 CA。

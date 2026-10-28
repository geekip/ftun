# FTUN v1 配置样例

这些文件只展示当前版本已经支持并会通过 Schema 校验的配置语义。尚未实现的功能设计不放在本目录，避免被误认为可以直接运行。

三个样例均通过根字段 `"$schema": "../schema.json"` 引用 [FTUN Schema](../schema.json)，支持编辑器补全和静态校验。测试会校验本目录中的每个 JSON 文件；新增样例必须先成为当前 Schema 和运行时支持的配置。移动文件后按新位置调整路径；Schema 不会自动填写默认值，也不检查代理节点可达性。

- [minimal.json](minimal.json)：DNS关闭、回环SOCKS5入站、DIRECT，必要本地解析用系统；不启动 FRS 模块。
- [full.json](full.json)：顶层物理 TUN、三类入站、真实/假DNS、固定/策略入口、两种组、顺序规则与本地 FRS；192.0.2.0/24 与 example.invalid 是待替换占位地址，不能直接联网运行。
- [frs.json](frs.json)：单个多集合 `.frs` 文件、大小写不敏感的 FRS 规则类型、大小写敏感的 label/出口名称以及 HTTP(S) 自动更新。示例 URL 和文件均为占位符。

完整示例使用 persist=true，首次运行必须先显式初始化 FakeIP 状态；状态路径相对该配置文件目录。只要规则引用 FRS 集合，启动就会校验 `.frs` 文件及所有引用集合；文件损坏、集合缺失、类型错误或空集合都会阻止完整 Runtime 就绪。作为 LAN 网关使用时还需配置系统转发与受管路由，不把 Socket allow-lan 当作 TUN 网关开关。运行前替换真实端点、探测 URL，准备权限和 CA。

物理设备身份使用顶层 `tun` 配置，`inbounds[].type=tun` 只描述 Proxy 消费者。设备字段（`interface`、`ipv4`、`auto-route`、`strict-route`）只能写在顶层 `tun` 下，写在 TUN inbound 下会被拒绝。

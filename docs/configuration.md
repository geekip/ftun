# 配置参考

本文由 `schema/ftun.schema.json` 生成（`python3 tests/docs_configuration.py --write schema/ftun.schema.json docs/configuration.md`），
测试 `docs-configuration` 会在 Schema 变化而文档未更新时失败。Schema 只描述结构与取值范围；
字段之间的关系（例如端口冲突、时长大小关系）由 `ftun check -c CONFIG` 校验。

时长写作 `500ms`、`5s`、`5m`、`24h`，不接受 0、负数、小数或无单位。未列出的字段会被拒绝。

## `base`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `base` | 对象 |  |  |  |
| `base.allow-lan` | 布尔 | `false` |  | 允许 Mixed/SOCKS5 的非回环客户端；不控制 TUN 或 DNS Listener。 |
| `base.cache-file` | 字符串 | `~/.ftun/ftun.cache` | 最短 1；格式见 Schema | 状态逻辑路径；普通快照与 FakeIP 耐久身份分开存储。 |
| `base.capacity` | 对象 | `{}` |  | Proxy 运行时对象容量。三个维度分别计数。 |
| `base.capacity.tcp-flows` | 整数 | `256` | 最小 1；最大 10000 | 同时存活的普通 TCP 流上限；仅启动时生效。 |
| `base.capacity.udp-associations` | 整数 | `256` | 最小 1；最大 10000 | 同时存活的 SOCKS5 UDP 关联上限；仅启动时生效。 |
| `base.capacity.udp-flows` | 整数 | `256` | 最小 1；最大 10000 | 同时存活的 UDP 五元组流上限；仅启动时生效。 |
| `base.ipv6` | 布尔 | `false` |  | 为域名解析同时查询 A/AAAA，默认仅查询 A；数值 IPv6 目标与双栈监听独立可用。 |
| `base.reload-retain` | 对象 | `{}` |  |  |
| `base.reload-retain.count` | 整数 | `4` | 最小 1；最大 64 | 同时保留的旧代次数量；满了以后拒绝 reload。只在启动时读取，修改需要重启。 |
| `base.routing-mark` | 整数 | `18004` | 最小 1；最大 4294967295 | 出站 socket 的 fwmark，同时是 TUN 路由保护规则匹配值；同机多实例必须不同。 |
| `base.state-cache` | 布尔 | `true` |  | Group/Health 状态持久化开关，独立于 FakeIP persist 和未来 api.cache。 |
| `base.timeouts` | 对象 | `{}` |  | 握手、建连、存活探测与空闲回收期限。 |
| `base.timeouts.connect` | 字符串 | `10s` | 格式见 Schema | 出站建连期限。 |
| `base.timeouts.handshake` | 字符串 | `10s` | 格式见 Schema | 入站协议握手期限。 |
| `base.timeouts.reply` | 字符串 | `5s` | 格式见 Schema | 协议失败回复的排空期限。 |
| `base.timeouts.tcp-idle` | 多选一 | `null` |  | TCP 两个方向都没有活动多久后回收。null 关闭（默认）。 |
| `base.timeouts.tcp-keepalive` | 多选一 | `{}` |  | TCP 存活探测。设为 false 关闭。 |
| `base.timeouts.tcp-keepalive（变体 2）` | 对象 |  |  |  |
| `base.timeouts.tcp-keepalive（变体 2）.count` | 整数 | `4` | 最小 1；最大 20 | 连续无应答多少次判为失联。 |
| `base.timeouts.tcp-keepalive（变体 2）.idle` | 字符串 | `30s` | 格式见 Schema | 空闲多久后开始探测，取整秒。 |
| `base.timeouts.tcp-keepalive（变体 2）.interval` | 字符串 | `15s` | 格式见 Schema | 探测间隔，取整秒。 |
| `base.timeouts.udp-idle` | 字符串 | `120s` | 格式见 Schema | UDP 流空闲回收期限。 |
| `base.timeouts.write-progress` | 字符串 | `120s` | 格式见 Schema | 已发送的数据有积压且在此期限内没有被对端确认任何新字节，则判为失联；慢速但仍在读取的对端不受影响。必须大于 keepalive 判定失联所需的总时长。 |
| `base.watchdog` | 多选一 | `30s` |  | owner 心跳看门狗：超过这个时长没有响应就停止进程（退出码 4）；null 关闭，范围 1s～10m。 |

## `dns`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `dns` | 对象 |  |  | 关闭后仍检查字段形状和语法，但不建立失效 DNS 引用或资源依赖。 |
| `dns.bootstrap` | 数组 | `[]` |  | 空数组/省略使用系统解析配置，不硬编码公共 DNS。显式来源失败不静默切换来源。 |
| `dns.bootstrap[]` | 字符串 |  | 格式见 Schema | IPv4 或 [IPv6]，可带端口，默认 53；始终真实直连解析。 |
| `dns.cache` | 布尔 | `true` |  | 缓存真实答案；不控制 FakeIP 身份寿命。 |
| `dns.default-server` | 多选一 | `` |  | 默认服务及路由前 REAL 解析器；空值/省略为 Bootstrap。 |
| `dns.enable` | 布尔 | `true` |  | false 时停用 FTUN DNS 入口、缓存、Hijack 与 FakeIP；必要本地解析使用系统解析器。 |
| `dns.fake-ip` | 对象 |  |  | 所有 fake-ip server 共用域名身份池；不自动复用，满池拒绝新映射。 |
| `dns.fake-ip.enable` | 布尔 | `true` |  | 是否允许合成 FakeIP；dns.enable=false 时本开关不生效。 |
| `dns.fake-ip.persist` | 布尔 | `true` |  | 先耐久预留地址，再批量保存映射；首次显式初始化，缺失/损坏不自动重建。池范围与持久化模式更改需要重启。 |
| `dns.fake-ip.range` | 字符串 | `198.18.0.0/15` | 格式见 Schema | IPv4 地址/前缀，前缀 0–32；网络地址规范化、地址冲突及用途检查由运行时执行。 |
| `dns.listeners` | 数组 | `[]` |  |  |
| `dns.listeners[]` | 对象 |  |  |  |
| `dns.listeners[].listen（必填）` | 字符串 |  | 格式见 Schema | IPv4:port 或 [IPv6]:port，端口 1–65535；IPv6 地址合法性由运行时校验。 |
| `dns.listeners[].server` | 多选一 | `` |  | 非空为固定 DNS Server；空值或省略为策略入口。 |
| `dns.servers` | 数组 | `[]` |  |  |
| `dns.servers[]` | 对象 |  |  |  |
| `dns.servers[].address（必填）` | 数组 |  | 至少项数 1；至多项数 4 | 上游地址，配置顺序就是优先级；最多 4 个。网络类失败的地址进入退避，查询自动换到下一个。 |
| `dns.servers[].address[]` | 字符串 |  | 格式见 Schema | IPv4、[IPv6] 或 ASCII 域名，可带端口，默认 53；上游域名由 Bootstrap 解析。 |
| `dns.servers[].fake-ip` | 布尔 | `false` |  | 客户端回答策略；内部 REAL 查询仍通过 address/outbound 获取真实地址。 |
| `dns.servers[].name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 区分大小写的名称。可以使用中文和空格；不得含逗号或控制字符。名称唯一性及引用由运行时检查。 |
| `dns.servers[].outbound` | 字符串 | `DIRECT` | 最短 1；格式见 Schema | 只决定 DNS 查询的传输路径，不决定查询域名的业务出口。 |
| `dns.servers[].type（必填）` | 字符串 |  | 取值：`udp`、`tcp` | v1 仅支持 UDP/TCP DNS。 |

## `frs`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `frs` | 多选一 |  |  | 仅 rules 中出现 FRS-IP/FRS-DOMAIN 时解释；否则整个值由运行时忽略。 |

## `inbounds`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `inbounds` | 数组 | `[]` |  | v1 同时最多一个 TUN。空数组可表示配置片段，但 CLI run 还要求至少一个入口。 |
| `inbounds[]` | 多选一 |  |  |  |
| `inbounds[]（变体 1）` | 对象 |  |  |  |
| `inbounds[]（变体 1）.listen（必填）` | 字符串 |  | 格式见 Schema | IPv4:port 或 [IPv6]:port，端口 1–65535；IPv6 地址合法性由运行时校验。 |
| `inbounds[]（变体 1）.name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 区分大小写的名称。可以使用中文和空格；不得含逗号或控制字符。名称唯一性及引用由运行时检查。 |
| `inbounds[]（变体 1）.outbound` | 字符串 |  | 最短 1；格式见 Schema | 强制绑定出口；指定后跳过 rules，但仍执行身份、能力和防回环检查。 |
| `inbounds[]（变体 1）.tcp-idle` | 字符串 |  | 格式见 Schema | 覆盖 base.timeouts.tcp-idle；省略则继承。 |
| `inbounds[]（变体 1）.type（必填）` | 多选一 |  | 固定为 `"mixed"` |  |
| `inbounds[]（变体 1）.udp` | 布尔 | `true` |  | 允许 SOCKS5 UDP ASSOCIATE；Mixed 的 HTTP 分支不提供 UDP。 |
| `inbounds[]（变体 1）.users` | 对象 | `{}` |  | 用户名到密码的映射。空对象表示无需认证；非空时必须认证。密码不得输出到日志。 |
| `inbounds[]（变体 2）` | 对象 |  |  |  |
| `inbounds[]（变体 2）.listen（必填）` | 字符串 |  | 格式见 Schema | IPv4:port 或 [IPv6]:port，端口 1–65535；IPv6 地址合法性由运行时校验。 |
| `inbounds[]（变体 2）.name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 区分大小写的名称。可以使用中文和空格；不得含逗号或控制字符。名称唯一性及引用由运行时检查。 |
| `inbounds[]（变体 2）.outbound` | 字符串 |  | 最短 1；格式见 Schema | 强制绑定出口；指定后跳过 rules，但仍执行身份、能力和防回环检查。 |
| `inbounds[]（变体 2）.tcp-idle` | 字符串 |  | 格式见 Schema | 覆盖 base.timeouts.tcp-idle；省略则继承。 |
| `inbounds[]（变体 2）.type（必填）` | 多选一 |  | 固定为 `"socks5"` |  |
| `inbounds[]（变体 2）.udp` | 布尔 | `true` |  | 允许 SOCKS5 UDP ASSOCIATE；Mixed 的 HTTP 分支不提供 UDP。 |
| `inbounds[]（变体 2）.users` | 对象 | `{}` |  | 用户名到密码的映射。空对象表示无需认证；非空时必须认证。密码不得输出到日志。 |
| `inbounds[]（变体 3）` | 对象 |  |  | 三层设备，无 listen/users；不受 allow-lan 影响。 |
| `inbounds[]（变体 3）.dns-hijack` | 布尔 | `true` |  | dns.enable=true 时接管进入 TUN 的 TCP/UDP 53，采用策略入口。 |
| `inbounds[]（变体 3）.name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 区分大小写的名称。可以使用中文和空格；不得含逗号或控制字符。名称唯一性及引用由运行时检查。 |
| `inbounds[]（变体 3）.outbound` | 字符串 |  | 最短 1；格式见 Schema | 强制绑定出口；指定后跳过 rules，但仍执行身份、能力和防回环检查。 |
| `inbounds[]（变体 3）.stack` | 字符串 | `lwip` | 固定为 `"lwip"` |  |
| `inbounds[]（变体 3）.tcp` | 布尔 | `true` |  | 启用 TCP。 |
| `inbounds[]（变体 3）.tcp-idle` | 字符串 |  | 格式见 Schema | 覆盖 base.timeouts.tcp-idle；省略则继承。 |
| `inbounds[]（变体 3）.type（必填）` | 多选一 |  | 固定为 `"tun"` |  |
| `inbounds[]（变体 3）.udp` | 布尔 | `true` |  | 启用按目标隔离的 UDP flow；Full Cone 后续。 |

## `log`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `log` | 对象 |  |  |  |
| `log.file` | 字符串 | `~/.ftun/ftun.log` | 最短 1；格式见 Schema | 本地路径；~ 展开当前用户目录，相对路径以配置文件目录为基准。Schema 不检查文件存在性或权限。 |
| `log.level` | 字符串 | `warn` | 取值：`silent`、`error`、`warn`、`info`、`debug`、`trace` | silent 关闭日志格式化及输出。 |
| `log.max-files` | 整数 | `3` | 最小 1；最大 32 | 保留的日志文件总数（含当前文件）：ftun.log、ftun.log.1…；为 1 时超限直接截断重写。收到 SIGUSR1 会重新打开日志文件，配合外部 logrotate。 |
| `log.max-size` | 整数 | `10485760` | 最小 0；最大 4294967295 | 单个日志文件的大小上限（字节）；写入会超过时轮转。0 表示不轮转；非 0 时至少 65536。 |

## `outbounds`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `outbounds` | 数组 | `[]` |  |  |
| `outbounds[]` | 多选一 |  |  |  |
| `outbounds[]（变体 1）` | 对象 |  |  |  |
| `outbounds[]（变体 1）.dns-server` | 多选一 | `` |  | 需要本地解析且尚无真实候选时使用；已有真实候选不得重新解析。 |
| `outbounds[]（变体 1）.name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 自定义出站/组名称，不可重定义内置 DIRECT 或 REJECT。 |
| `outbounds[]（变体 1）.password` | 字符串 |  | 最短 1；最长 255 | SOCKS5 认证值；Schema 限制字符数，运行时还须验证 UTF-8 编码后为 1–255 字节。 |
| `outbounds[]（变体 1）.server（必填）` | 字符串 |  | 格式见 Schema | IPv4/ASCII 域名:port 或 [IPv6]:port；端口 1–65535。 |
| `outbounds[]（变体 1）.type（必填）` | 多选一 |  | 固定为 `"socks5"` |  |
| `outbounds[]（变体 1）.udp` | 布尔 | `true` |  | 允许 UDP ASSOCIATE，不支持 SOCKS5 分片。 |
| `outbounds[]（变体 1）.username` | 字符串 |  | 最短 1；最长 255 | SOCKS5 认证值；Schema 限制字符数，运行时还须验证 UTF-8 编码后为 1–255 字节。 |
| `outbounds[]（变体 2）` | 对象 |  |  | 更改 default 后 SIGHUP，或通过宿主 C 接口切换；仅影响新连接。 |
| `outbounds[]（变体 2）.default（必填）` | 字符串 |  | 最短 1；格式见 Schema | 必须是 outbounds 中的成员，防止成员顺序隐式改变默认出口。 |
| `outbounds[]（变体 2）.dns-server` | 多选一 | `` |  | 需要本地解析且尚无真实候选时使用；已有真实候选不得重新解析。 |
| `outbounds[]（变体 2）.name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 自定义出站/组名称，不可重定义内置 DIRECT 或 REJECT。 |
| `outbounds[]（变体 2）.outbounds（必填）` | 数组 |  | 至少项数 1 | 成员可为节点、其他组或 DIRECT/REJECT；引用、default 属于成员及无环检查由运行时完成。 |
| `outbounds[]（变体 2）.outbounds[]` | 字符串 |  | 最短 1；格式见 Schema | 区分大小写的名称。可以使用中文和空格；不得含逗号或控制字符。名称唯一性及引用由运行时检查。 |
| `outbounds[]（变体 2）.type（必填）` | 多选一 |  | 固定为 `"select"` |  |
| `outbounds[]（变体 3）` | 对象 |  |  | 无有效结果时用 default；新鲜结果全失败时尝试上次合法选择/default，标记 degraded；不自动直连。 |
| `outbounds[]（变体 3）.default（必填）` | 字符串 |  | 最短 1；格式见 Schema | 必须是 outbounds 中的成员，防止成员顺序隐式改变默认出口。 |
| `outbounds[]（变体 3）.dns-server` | 多选一 | `` |  | 需要本地解析且尚无真实候选时使用；已有真实候选不得重新解析。 |
| `outbounds[]（变体 3）.expected-status` | 整数 | `204` | 最小 100；最大 599 | 探测期望 HTTP 状态码。 |
| `outbounds[]（变体 3）.interval` | 字符串 | `5m` | 格式见 Schema | 正整数与 ms/s/m/h 单位，不接受 0、负数、小数或无单位；整数溢出及字段之间的大小关系由运行时检查。 |
| `outbounds[]（变体 3）.lazy` | 布尔 | `true` |  | 未使用时可暂停周期探测；业务请求不等待完整测速。 |
| `outbounds[]（变体 3）.name（必填）` | 字符串 |  | 最短 1；格式见 Schema | 自定义出站/组名称，不可重定义内置 DIRECT 或 REJECT。 |
| `outbounds[]（变体 3）.outbounds（必填）` | 数组 |  | 至少项数 1 | 成员可为节点、其他组或 DIRECT/REJECT；引用、default 属于成员及无环检查由运行时完成。 |
| `outbounds[]（变体 3）.outbounds[]` | 字符串 |  | 最短 1；格式见 Schema | 区分大小写的名称。可以使用中文和空格；不得含逗号或控制字符。名称唯一性及引用由运行时检查。 |
| `outbounds[]（变体 3）.timeout` | 字符串 | `5s` | 格式见 Schema | 单次探测超时，不大于 interval；跨字段比较由运行时执行。 |
| `outbounds[]（变体 3）.tolerance` | 整数 | `50` | 最小 0 | 切换延迟优势阈值，毫秒。 |
| `outbounds[]（变体 3）.type（必填）` | 多选一 |  | 固定为 `"url-test"` |  |
| `outbounds[]（变体 3）.url（必填）` | 字符串 |  | 格式见 Schema | HTTP/HTTPS URL，主机支持 IPv4、[IPv6] 或 ASCII 域名；HTTPS 必须验证证书和主机名。 |

## `rules`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `rules` | 数组 | `[]` |  | 按顺序匹配；空数组/无命中使用 DIRECT。 |
| `rules[]` | 多选一 |  |  | First Match Wins。保留配置顺序，解析失败终止；IP 命中后只拨命中子集。无正则、no-resolve 或 INBOUND matcher。 |

## `sniff`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `sniff` | 对象 |  |  |  |
| `sniff.enable` | 布尔 | `false` |  | 仅缺少域名时嗅探；失败/超时继续原元数据，不改变原始真实目的 IP。 |
| `sniff.http-host` | 布尔 | `true` |  | 解析 HTTP Host；预读字节按序交还。 |
| `sniff.tls-sni` | 布尔 | `true` |  | 解析 TLS ClientHello SNI，不解密 TLS。 |

## `tun`

| 字段 | 类型 | 默认值 | 取值范围 | 说明 |
|---|---|---|---|---|
| `tun` | 对象 |  |  | 物理 TUN 的规范配置；TUN 入站只描述 Proxy 消费者，不接受设备字段。 |
| `tun.auto-route` | 布尔 | `false` |  |  |
| `tun.interface（必填）` | 字符串 |  | 最短 1；最长 15 | 平台 TUN 设备名。 |
| `tun.ipv4（必填）` | 对象 |  |  |  |
| `tun.ipv4.address（必填）` | 字符串 |  | 格式见 Schema | 设备 IPv4 地址及前缀；保留主机地址语义，不能将此字段当路由网络地址清除主机位。 |
| `tun.ipv6` | 对象 |  |  |  |
| `tun.ipv6.address（必填）` | 字符串 |  | 格式见 Schema | 可选设备 IPv6 地址及前缀；配置后安装 IPv6 路由，MTU 至少 1280。 |
| `tun.mtu` | 整数 | `1500` | 最小 1 |  |
| `tun.route-table` | 整数 | `18004` | 最小 256；最大 4294967280 |  |
| `tun.rule-priority` | 整数 | `11000` | 最小 1；最大 32000 |  |
| `tun.strict-route` | 布尔 | `false` |  |  |

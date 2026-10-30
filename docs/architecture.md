# 源码与构建结构

产品源码按六层组织，CMake 为各层和可复用能力生成独立静态库：

| 层 | 目标 | 依赖方向 |
| --- | --- | --- |
| util | `ftun_util` | 无第一方依赖 |
| platform | `ftun_platform` | util |
| core | `ftun_core` | platform、util |
| libs | `ftun_lib_buffer`、`ftun_lib_transport`、`ftun_lib_resolver`、`ftun_lib_tls`、`ftun_lib_tun`、`ftun_lib_http` | core、platform、util 和其他 libs；无环 |
| 业务 | `ftun_dns`、`ftun_proxy` | libs 和下层；业务之间无链接依赖 |
| app | `ftun_app`、`ftun_app_config`、可执行文件 `ftun` | 业务和下层 |

每个静态目标通过构建目录中的头文件目录获得自身及显式依赖的头文件。除负责装配的 app 外，目标没有整个 `src` 的搜索路径。路径写法从 `src/` 起，例如 `libs/transport/path.h`。因此下层直接 include 业务头文件会在编译时失败。测试另外核验编译命令的源码归属、业务之间的引用及依赖环，并用非法输入验证检查器。

DNS 与 Proxy 的协作在 `app/composition` 接通。DNS、HTTP 和控制解析只保存不透明出口编号，经 `libs/transport/egress` 请求到最终目标的 Path；Proxy 独立拥有协议字段、组选择和握手。请求绑定配置代次与已选叶子，旧请求不因组切换或重载重新选路。Worker 使用独立的不可变出口快照，不读取 owner 的可变组状态。基础解析、DNS 报文、传输和通道控制由公共库提供；Proxy 接收 DNS hook 表，保留明确的失败状态。关闭业务的构建不产生该业务的实现符号；关闭 TUN 时也不链接 lwIP。

Linux 事件后端由 `platform/linux/poller_epoll.c` 等待 epoll 并处理 eventfd，`core/event` 管理源、定时器、跨线程投递和公平分派。同一 FD 的兴趣合并后在等待前更新，取消会撤销未交付的通知。所有内核 readiness 先入有界前端队列，业务回调仍在 owner loop 上运行。

`util/ip`、`util/hash` 和 `util/dnswire` 无 OS 头文件、无全局可变状态和 I/O。DNS 解析器先计算布局，再写入调用方提供的对齐存储；resolver 的拥有型包装负责预算、分配和释放。IPv6 文本转换使用有许可记录的 musl 算法；Socket 与 lwIP 数据面支持 IPv4/IPv6，DNS 在启用双栈解析时并发查询 A/AAAA。

`core/config` 只负责有界 JSON 文档、通用字段读取和配置引用及预算所有权，不包含业务模型。聚合模型在 `app/config` 私有定义；DNS、Proxy、TUN 通过声明在对应业务或共享库中的只读段访问配置，DDRA 只借用通用模块位计划。JSON AST 仅在配置构造期间存在，发布后的配置由 owner 串行管理和显式引用。

DNS、Proxy 和 TUN 的字段解析与最终字段清理由 `dns/config`、`proxy/config`、`libs/tun/config` 的独立静态目标提供。它们接收不透明分配 owner 和显式配置段，不读取 app 模型、不启动业务、不做 I/O。裁剪运行模块时保留这些控制阶段的字段读写，以维持已知字段的校验语义；这不会引入业务服务或网络实现。`ftun_app_config` 也只继承显式依赖的头文件目录。局部语义、默认值、规则与组图校验也归所属配置目标；路径、跨段引用/冲突/重叠和依赖闭包编译由 app 装配。完整组合计划只由 app 持有，业务读取各自需要的准备与保留字段。共享传输/解析配置仅按值投影实际消费的数据，字符串和列表借用不可变文档，不创建额外对象。独立宿主可以采用不同的聚合模型。

Schema 维护在 `schema/{core,dns,proxy,app}.schema.json`，构建时由 CMake 合并到构建目录，并安装到 `share/ftun/schema`。仓库中的 `schema/ftun.schema.json` 供编辑器与样例使用；修改分片后运行 `cmake -DFTUN_SCHEMA_DIR=$PWD/schema -DFTUN_SCHEMA_OUTPUT=$PWD/schema/ftun.schema.json -P tools/schema/merge.cmake` 更新，`config-schema-generated` 检查发行文件是否同步。合并保留本地 `$defs` 引用并拒绝重复定义；所有分片描述的都是当前已有能力。

Core 通过 `platform/thread`、`platform/atomic`、`platform/file`、`platform/clock` 和 `platform/process` 使用线程、同步、原子与系统 I/O。原生同步对象嵌入调用方存储；条件变量统一使用绝对单调毫秒截止时间，返回时仍持锁。原子操作使用经过编译和链接探测的编译器原语，必要时链接 libatomic，不依赖 Core 中的 C11 语法，也不声称所有目标均为无锁。分层检查禁止所有非 platform 层直接包含原生系统头、调用 pthread 或使用 stdatomic；这些层的静态库不直接引用原生线程、进程、文件、socket 或系统解析符号。

持久文件操作先在 Core 准入路径内存和 FD，再调用不分配堆对象的平台原语。平台按 fsync 临时文件、rename、fsync 目录执行替换，显式报告 rename 是否已发布；后续失败不会伪报旧文件仍然权威。日志队列、脱敏和轮转策略保留在 Core，平台文件写入返回已写前缀，部分失败不会重发已经写出的字节。

资源凭据内嵌于唯一拥有者，准入不再分配额外对象。根直系预算是独立同步域，后代共享本域锁；热路径只锁本域，通过根原子额度仲裁全局上限。保证份额、清理保留与向量回滚保持一致，只有结构修改和一致用量快照锁定全部域。

`libs/transport/channel` 统一拥有型流与报文通道的数据 I/O、停止与静默查询，内嵌于 Path 或协议连接，不额外分配。Stream 保留前缀接纳与 Operation 完成，Datagram 保留整包与原回调语义。Path 管理代次、网络视图、授权和驱动，Relay 可借用其流。DNS、控制执行器和 SOCKS 协议通过统一数据接口读写。

`libs/tls` 只接纳和交付有界内存密文，保留 CA、主机名验证和最低 TLS 版本。固定 CA 配置的 context 可以供多个会话共享；原生会话构造单独同步，各会话数据 I/O 由各自 owner 推进。双向密文环随包装对象先准入，原生库的证书与内部堆仍不构成精确的 RSS 硬限额。`libs/http` 显式推进密文和传输背压，跨重定向复用 context，始终保留请求的绝对期限；业务配置与组选择计划由 Proxy 生成。

CI 的 macOS 任务只使用真实 SDK 编译 POSIX 平台源，不生成可运行产品。Mesh、其他操作系统原生服务和新增代理协议尚未实现。

公开 C API 位于 `include/ftun`，实现位于 `app/capi`。ABI 1 的结构布局、函数签名和符号保留；`ftun.h` 汇总拆分后的头文件，`error.h` 继续支持已有宿主的 include 路径。宿主通过安装后的 `FTUN::Runtime` CMake 目标链接完整静态依赖，而不是单独链接内部 core 库。

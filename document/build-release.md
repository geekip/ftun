# v1.0 / v1.0.1 构建、交付与验证基线

FTUN 1.0 的正式目标是 Linux x86_64 IPv4。默认完整档静态内置 DNS、FakeIP、
TUN/lwIP 和 FRS，并装配可运行的 TUN、SOCKS5、Mixed、Router、Group、DNS、
FRS 与 Outbound 数据面。配置和构建过程不联网；第三方来源锁位于
[`third_party/LOCK.json`](../third_party/LOCK.json)，许可说明位于
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)。FTUN 项目许可证为
仓库根目录的 [GNU GPL v3](../LICENSE)。

## 构建档

| preset | 目的 | 优化/检查 |
|---|---|---|
| `debug` | 开发与完整正确性测试 | `-O0 -g` |
| `sanitize` | 内存与未定义行为检查 | ASan/UBSan、frame pointer |
| `release` | 标准 glibc 交付 | `-O2`、section GC |
| `release-size` | 体积比较 | `-Os`、section GC |
| `release-lto` | 独立验证 LTO | `-O3`、IPO/LTO |
| `linux-x86_64-musl` | Linux x86_64 全静态交付 | musl、`-Os`、section GC、`-static` |

```sh
cmake --preset release
cmake --build --preset release --parallel
ctest --preset release --output-on-failure

FTUN_MUSL_CC=/usr/bin/x86_64-linux-musl-gcc \
  cmake --preset linux-x86_64-musl
cmake --build --preset linux-x86_64-musl --parallel
ctest --preset linux-x86_64-musl --output-on-failure
```

`FTUN_MUSL_AR`、`FTUN_MUSL_RANLIB` 和 `FTUN_MUSL_SYSROOT` 可覆盖配套工具。
静态 ELF 门禁要求没有 `PT_INTERP` 和 `DT_NEEDED`；标准 Release 可以链接目标系统
动态库。musl 与 LTO 档分开验证，LTO 不是静态闭合的前提。

## 模块裁剪

`FTUN_MODULE_DNS`、`FTUN_MODULE_FAKEIP`、`FTUN_MODULE_TUN`、
`FTUN_MODULE_FRS` 只接受 `OFF` 或 `BUILTIN`。FakeIP 要求 DNS 同时内置。
每次构建生成 `ftun-build-modules.txt`；配置检查、启动和重载会拒绝缺少生效能力的
配置，不会跳过规则或改变默认值。

自动矩阵覆盖最小核心、无 TUN、无 DNS、无 FakeIP、无 FRS 和完整档。关闭 TUN
不会移除 SOCKS5 TCP/UDP；`dns.enable=false` 的必要本地解析保留 SystemResolver。
运行时关闭功能只裁剪本次 DDRA 资源，不等于编译期裁剪。

## 2026-10-12 v1.0.1 候选证据

环境与 v1.0 基线一致：Linux `6.12.107+deb13-amd64` x86_64、GCC 14.2.0、
CMake 3.31.6。下列矩阵在 `953e5f7` 基线之上的候选工作树完成；提交后的正式
候选必须从干净源码重新配置和构建，并以产物自身报告的 revision 固定来源。

| 验证档 | 结果 |
|---|---:|
| Debug | 82 / 82 |
| ASan/UBSan | 82 / 82 |
| glibc Release | 85 / 85 |
| glibc MinSizeRel | 85 / 85 |
| glibc LTO | 85 / 85 |
| musl x86_64 全静态 | 85 / 85 |

矩阵包含 OFF/BUILTIN 模块组合、真实 TUN 本机/LAN、SOCKS5/Mixed TCP/UDP、
DNS/FakeIP/FRS、重载回滚、损坏 FRS 拒绝、安装/卸载、静态 ELF 与无 capability
权限分界。普通用户的 socket-only 真实 TCP/UDP 转发成功；同一用户启动
TUN 配置会在准备阶段明确失败。

空闲 TCP 连接持续 60 秒时，进程 CPU 接近无连接基线，没有持续
`POLLOUT` 唤醒。真实容量点验收了 1、32、128、256 个 SOCKS5 TCP flow；256 flow
同时保持时为 RSS 6,704 KiB、PSS 4,766 KiB、534 fd，第 257 个连接被拒绝且
已有 256 个连接完成转发。

默认 Release 的空闲资源三次采样为 RSS 4,340/4,916/4,860 KiB、PSS
2,380/2,794/2,833 KiB、fd 6/6/6，CPU 均为 0%。未剥离二进制为
1,057,544 B，剥离后为 965,984 B，最小部署文件合计 1,009,179 B。
MinSizeRel 剥离后为 646,496 B，LTO 为 986,304 B，musl 全静态为
726,800 B。

同机预热后五轮解析基准的中位数如下：

| 编译策略 | HTTP Host ops/s | TLS SNI ops/s | 剥离大小 |
|---|---:|---:|---:|
| `-O2` + section GC（默认） | 3,515,760 | 10,716,833 | 965,984 B |
| `-O3` + section GC | 3,736,689 | 10,698,745 | 1,019,232 B |
| `-Os` + section GC | 1,747,536 | 10,364,999 | 646,496 B |
| `-Oz` + section GC | 1,660,373 | 9,716,296 | 634,208 B |
| `-O3` + LTO + section GC | 3,888,780 | 11,256,264 | 986,304 B |
| `-O2`，无 section GC | 3,552,406 | 11,035,727 | 1,236,448 B |

因此默认保持 `-O2` + section GC：`-O3` 的局部收益伴随体积增长，LTO
仍有下述 wolfSSL/GCC 14 诊断风险，取消 section GC 只显著增大文件。`-Oz`
相对 `-Os` 只减少 12,288 B，但 HTTP Host 吞吐更低，不新增发行档。

lwIP 真实 TUN 对照比较原 12 MSS、约 64 KiB（44 MSS）和窗口扩大。在
50 ms RTT 下，LAN 中位数从 1.52 MiB/s 提高到 1.91 MiB/s；在 1% 丢包下
从 2.93 MiB/s 提高到 3.79 MiB/s。窗口扩大在部分工况更快，但内存和兼容
风险更高；1.0.1 因此选择 44 MSS 且不启用扩大。最终默认配置三轮
8 MiB 实际 TUN 转发的中位数为本机 5.51 MiB/s、LAN 4.60 MiB/s；真实
SOCKS5 UDP 10,000 包为 19,841 包/秒。该 UDP 证据不支持在本版引入
`recvmmsg`/`sendmmsg` 两套状态路径。

v1.0.1 发布候选还必须在最终内容不变的构建上完成连续至少 24 小时
长稳；短 CI 和 60 秒空闲检查不代替该门槛。

## 2026-10-12 v1.0 冻结候选证据

环境：Linux `6.12.107+deb13-amd64` x86_64，GCC 14.2.0，CMake 3.31.6。
网络验收在隔离 user/network namespace 内使用 veth、独立 peer 和真实 TUN 设备完成。

| 验证档 | 结果 |
|---|---:|
| Debug | 81 / 81 |
| ASan/UBSan | 81 / 81；生产场景另连续 3 次通过 |
| glibc Release | 83 / 83 |
| glibc MinSizeRel | 82 / 82，按计划排除重复模块矩阵 |
| glibc LTO | 82 / 82，按计划排除重复模块矩阵 |
| musl 全静态 | 83 / 83 |

生产场景覆盖 SOCKS5/Mixed TCP 与 UDP、TUN 本机与 LAN TCP/UDP、DNS UDP/TCP 与
TUN 53 劫持、FakeIP 恢复、DIRECT/SOCKS5、URL-Test、FRS 启动下载/相对重定向/
ETag 304、事务重载回滚、持久化重启、损坏本地 FRS 拒绝和退出资源回收。URL-Test
使用 Bootstrap 解析，FRS 更新使用配置的命名 DNS server；测试还覆盖 DNS upstream
域名经 Bootstrap 解析后通过带认证 SOCKS5 发起查询、代理端点域名解析、SOCKS5
远端 DOMAIN、不存在本地 FRS 且启动下载失败时拒绝运行，以及 `dns.enable=false` 时
DIRECT 域名经 SystemResolver 建链。

Release 三轮 8 MiB 环回数据面负载分别为 380.95、131.15、615.38 MiB/s。
32 个并发 TCP 流采样为 RSS 19,748 KiB、PSS 17,873 KiB、86 个 fd；冻结门槛为
RSS/PSS 64 MiB 和 256 个 fd。随后 60 秒持续循环 TCP、UDP 与 DNS 操作通过。
这些数字用于相同环境的回归，不是公网、跨机或特定硬件吞吐承诺。

标准 Release 未剥离二进制为 1,030,040 B，剥离后 941,408 B，包含根许可证的
最小部署文件为 984,408 B。最终独立启动三次的空闲 RSS 为
19,120/17,124/17,380 KiB，PSS 为 17,100/15,160/15,201 KiB，fd 为 6/6/6，
采样 CPU 均为 0%。HTTP Host
热路径五轮中位数为 3,421,941 ops/s，TLS SNI 为 10,787,698 ops/s。

GCC 14 的 LTO 内联分析会在 wolfSSL 5.8.4 `Hmac_UpdateFinal_CT` 报
`-Wstringop-overflow` 警告；普通 Release、TLS/HTTPS 合约及 ASan/UBSan 没有复现
运行时越界。该上游工具链告警未被静默屏蔽，升级依赖时应复核。

## 依赖与许可

锁文件精确记录 libev 4.33、cJSON 1.7.19、heiher/lwIP 提交及补丁、wolfSSL
5.8.4 gitlink、摘要、许可文件和编译边界。自动测试核对 vendored 内容、补丁、
wolfSSL submodule revision/工作树、notice 和实际编译输入。

FTUN 采用 GNU GPL v3；wolfSSL 当前也按 GPLv3 开放源码许可组合分发。商业闭源
分发需要另行取得适当的 wolfSSL 商业许可，并重新审查整体分发许可；构建通过不
替代法律审查。

## 安装与卸载

```sh
cmake --install build/release --prefix /usr/local
cmake --build build/release --target uninstall
```

安装内容包括 `ftun`、静态开发库、公开头、FTUN 根许可证、README、控制/构建/发行文档、
依赖锁、notice 及实际依赖许可证。`uninstall` 只按该构建目录的 install manifest 删除已安装文件，
不递归删除前缀，也不删除用户配置、状态或日志。临时前缀验证中安装后二进制返回
`FTUN 1.0.1`，并报告构建时的固定源码 revision 与完整内置能力清单；卸载后无文件
残留。正式发行构建必须来自干净工作树，版本输出不得带 `-dirty`；具体 revision 以
产物自身输出为准，避免文档提交反过来改变其记录的提交标识。

# v1.0 构建、交付与验证基线

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
`FTUN 1.0.0`，并报告构建源码 `cdd6151b016d-dirty` 与完整内置能力清单；卸载后
无文件残留。`-dirty` 如实表示当前冻结候选尚未获准形成提交，正式提交后的发行构建
必须重新配置并输出不带该后缀的固定 revision。

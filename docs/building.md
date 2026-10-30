# 平台构建与分发

九个发行预设均生成独立 `ftun` 程序。构建使用 Zig **0.15.2** 的 C 编译器、目标头文件和运行库，以及 CMake 3.21+、Ninja。第三方产品源码来自仓库锁定的子模块；配置和编译不联网。先安装对应宿主的 [Zig 0.15.2](https://ziglang.org/download/0.15.2/)，将其加入 `PATH`，或令 `FTUN_ZIG_DIR` 指向包含 `zig` / `zig.exe` 的目录。

| 预设 | 目标和 ABI | 功能范围 |
|---|---|---|
| `darwin-amd64` | macOS 12+，x86_64，Mach-O | DNS、显式代理、FakeIP、FRS |
| `darwin-arm64` | macOS 12+，Apple Silicon，Mach-O | 同上 |
| `windows-amd64` | Windows 10 1709+，x86_64，PE32+ | 全模块，Wintun 使用手动路由 |
| `windows-arm64` | Windows 11 ARM64，PE32+ | 同上 |
| `linux-amd64-musl` | x86_64，musl，全静态 PIE | 全模块，含 TUN |
| `linux-arm64-musl` | AArch64，musl，全静态 PIE | 同上 |
| `linux-armv7-musl` | ARMv7-A / Cortex-A7，EABI hard-float，musl，全静态 PIE | 同上 |
| `linux-mips-musl` | MIPS32r2，大端，O32 soft-float，musl，全静态 PIE | 同上 |
| `linux-mipsel-musl` | MIPS32r2，小端，O32 soft-float，musl，全静态 PIE | 同上 |

Linux 发行档以 Linux 5.10+ 为运行基线；ARMv7 要求对应 CPU 指令能力。MIPS 是 32 位软浮点程序，不适用于 MIPS64 / N32 / hard-float ABI。产物无外部 libc 和动态加载器依赖。TUN 仍要求内核支持和相应网络权限，交叉编译通过不代表已验证具体路由器的内核或网络环境。

```sh
cmake --preset linux-arm64-musl
cmake --build --preset linux-arm64-musl --parallel 3
# 其余平台替换预设名称，产物为 build/<预设>/ftun，Windows 为 ftun.exe。
```

Linux 上交叉生成 Mach-O 时还需 `llvm-install-name-tool`（Debian/Ubuntu 的 LLVM 工具包）；macOS 上可使用系统的 `install_name_tool`。Zig 已提供这里需要的 Darwin libc 头文件及链接描述，无需下载 Apple SDK。Windows 程序不需额外安装 MinGW DLL；启用 TUN 时需要程序目录中的官方签名 `wintun.dll`。

发行预设采用 `MinSizeRel`、`-Os` 和节回收，保留栈保护及平台支持的链接加固。现有 Debug、Sanitizer、模块裁剪和旧 `linux-x86_64-musl` 预设继续可用。新预设使用独立构建目录，不覆盖旧产物。

## Darwin / Windows 的能力边界

提供 IPv4/IPv6 DNS UDP/TCP、SOCKS5/Mixed TCP/UDP、规则和代理出站、配置检查、事务重载与正常停止。Darwin 的 TUN 模块关闭；Windows 提供以下 Wintun 手动路由模式。出口 mark 和接口绑定尚未支持，显式请求这些保护会返回不支持。

- macOS 使用 kqueue 和 EVFILT_USER 唤醒；Windows 使用 wepoll 1.5.8 的水平触发就绪通知和 TCP 唤醒对。wepoll 通过 Git submodule 固定提交，内部使用 AFD/IOCP；单批最多交付 64 个事件，不再构造全量 WSAPoll 数组，也不再有后端的 8191 个 Socket 固定上限，实际容量受配置预算及系统资源限制。上游内部堆和 IOCP/AFD 句柄先准入再创建，延迟删除的 Socket 状态保持额度到实际释放；AFD 分组按上游实现保留到后端关闭。进程级 keyed event 采用每个后端一份保守句柄额度，预算不代表精确内核内存或 RSS。
- 两个平台保留 TCP keepalive 和应用层绝对期限；不支持 Linux 的 TCP_USER_TIMEOUT 和累计 ACK 进度检测，不能提供 Linux 上同等的发送确认停滞判定。可按部署需要配置 `tcp-idle`。未实现原生网络变化订阅，恢复依靠现有期限与退避调度。
- Windows 的 `ftun stop PID` / `ftun reload PID` 通过当前会话的进程事件工作，PID 为 Windows 原生 PID。普通退出可使用 Ctrl+C 或 `stop`。关闭控制台窗口时系统可能直接终止进程，需正常清理时使用 `stop`。
- Windows 的文件和目录使用 UTF-8 路径输入，新建私有状态及日志使用当前用户的受保护 DACL；文件锁、映射和同卷替换使用原生接口。文件先 FlushFileBuffers，再以 MoveFileEx WRITE_THROUGH 发布；不能将 Wine 文件测试等同于实际 NTFS 断电耐久验证。Windows BootTime 用于保守失效判断，系统时间调整可能使缓存提前失效。Wine 验证使用文件日志；Wine 从 Unix 继承的 stderr 管道不支持 Windows 等待模式，CLI 会明确启动失败，不能据此推定原生 Windows 管道行为。
- HTTPS 显式验证 CA 和目标身份。可设置 `SSL_CERT_FILE` 指向 PEM CA 文件；设置后加载失败会拒绝连接，不取消验证。Linux/macOS 还会查找常见系统 PEM 路径（macOS 含 `/etc/ssl/cert.pem`）；Windows 必须提供 PEM 文件，当前不导入 Windows 证书仓库。CA 环境变量应在启动前设置。
- macOS 的 CLI 看门狗使用进程级 ITIMER_REAL；同一进程只有一个此类定时器，嵌入宿主不得同时占用该定时器。系统服务通知仅在 Linux 提供；Windows 设置 `NOTIFY_SOCKET` 会返回不支持。

## Windows Wintun

源码通过 Git submodule 固定官方 Wintun 0.14.1，实际只引用公开 API 头文件。驱动使用官方签名 DLL；不从源码编译未签名驱动。构建前显式准备运行库：

```sh
git submodule update --init --recursive
python tools/fetch_wintun.py
cmake --preset windows-amd64 -DFTUN_PORTABLE_TESTS=ON
cmake --build --preset windows-amd64 --parallel 3
# ARM64 替换为 windows-arm64；离线准备可使用 --archive wintun-0.14.1.zip。
```

ZIP、两档 DLL 和运行库许可的 SHA256 均由依赖锁固定；准备脚本、CMake 和打包阶段检查对应内容。发布包包含匹配 CPU 的 `wintun.dll`，与 `ftun.exe` 放在同一目录。程序只从自身目录加载 Wintun，并限制其依赖从 DLL 目录和系统目录加载；不会搜索当前工作目录或 PATH。只运行 DNS/显式代理时不会加载 Wintun。

以管理员身份启动。程序创建独占网卡、设置 IPv4/IPv6 地址和对应 MTU，退出时撤销地址、结束 session 并关闭自建网卡；遇到同名已有网卡会拒绝启动。使用以下物理设备配置，并添加 `type: "tun"` 的入站：

```json
"tun": {
  "interface": "ftun0",
  "mtu": 1500,
  "ipv4": {"address": "172.31.255.1/30"},
  "ipv6": {"address": "fd00:ffff::1/126"},
  "auto-route": false,
  "strict-route": false
}
```

Windows 明确拒绝 `auto-route: true`；不安装默认路由、防火墙或出口防回环规则，也不修改系统 DNS。配置地址会产生 Windows 自身的直连路由。其他需要进入 FTUN 的目标前缀由用户手动添加，例如在管理员 PowerShell 中将实验网段导向网卡：

```powershell
New-NetRoute -DestinationPrefix '198.18.0.0/15' -InterfaceAlias 'ftun0' -NextHop '0.0.0.0' -PolicyStore ActiveStore
New-NetRoute -DestinationPrefix 'fd00:1234::/64' -InterfaceAlias 'ftun0' -NextHop '::' -PolicyStore ActiveStore
# 撤销上述路由：
Remove-NetRoute -DestinationPrefix '198.18.0.0/15' -InterfaceAlias 'ftun0' -Confirm:$false
Remove-NetRoute -DestinationPrefix 'fd00:1234::/64' -InterfaceAlias 'ftun0' -Confirm:$false
```

手动捕获前缀必须保留 FTUN 自己的出口路径；例如 `DIRECT` 访问同一个已捕获目标会再次进入 TUN。将需要代理的目标导向 TUN 时，代理服务器地址应继续通过原网络到达。更改网卡名、地址或 MTU 需要重启；普通规则/代理配置仍遵循原重载契约。

Wintun 使用 1 MiB 环容量；环区及控制元数据、设备/控制句柄在创建前准入，持有到 session/adapter 关闭后再归还。句柄等待通过 Windows 线程池通知 owner loop，不将 HANDLE 传给 wepoll。发送环满时保留原有有界队列，只保留一个 1 ms 定时器等待再写，队列满则返回资源不足。预算是逻辑准入额度，不表示驱动内核内存或进程 RSS 上限。

## 验证与打包

发行档默认不编译现有 Linux 专用测试。开启可移植契约测试后，在目标系统执行：

```sh
cmake --preset darwin-arm64 -DFTUN_PORTABLE_TESTS=ON
cmake --build --preset darwin-arm64 --parallel 3
python3 tests/portable/product.py build/darwin-arm64
```

该测试执行线程/条件变量、96 路事件公平性、跨线程唤醒、IPv4/IPv6 UDP、文件锁/替换/映射与进程控制契约；复用既有 TLS 内存握手测试验证 CA/身份拒绝与密文背压；Windows 另测原生满管道的非阻塞写入，以及 wepoll 的并发 owner、分配/句柄预算失败、延迟回收、反复注销和 8200 个 UDP Socket 注册。Windows Wintun 定向契约另测官方 DLL 导出、安全加载路径、环收发所有权、预算拒绝、双栈地址/MTU、部分失败撤销、发送背压及停止清理；这部分使用 API 替身，不代表真实驱动通过。再通过真实回环验证 SOCKS5/HTTP、DNS A/AAAA UDP/TCP、无效重载回滚、有效重载与停止。Linux 交叉产物可用 `--runner '["qemu-aarch64"]'`（其余分别为 `qemu-arm`、`qemu-mips`、`qemu-mipsel`）；Windows amd64 可在 Linux 上用 Wine 做补充验证。

原生 Windows 管理员终端可额外执行 `build/windows-amd64/ftun-wintun-driver-test.exe --driver`（ARM64 替换目录）。该测试创建 `ftun-probe`，使用 `198.18.254.1/30` 和 `fdfe:ff01::1/126`，验证 Windows 内核与 Wintun 两方向的 IPv4/IPv6 UDP 回环，随后删除网卡；不要在已使用这些地址的机器运行。Wine 明确跳过这个驱动测试。CI 的手动触发项 `wintun_driver` 可开启相同测试；默认不修改 runner 的网络。

CI 为九个档位构建程序：Darwin/Windows 使用对应架构原生 runner，Linux 非本机架构使用 QEMU。原生 CI 尚未实际执行时，只能报告交叉构建和本地模拟器的结果；Darwin、Windows ARM64 的运行资格必须以原生 runner 结果为准。

```sh
python3 tools/package.py linux-arm64-musl --output dist
```

包名为 `ftun-v<版本>-<平台>.tar.gz`，Windows 为 `.zip`，均附 SHA256。只包含程序、Windows TUN 所需的官方签名 DLL、模块清单、用户 README、依赖锁和许可，不包含库开发文件或本地工作资料。Git 标签发布先等待九档构建和协议冒烟全部通过，再汇总发布；任一档失败都不会进入发布任务。

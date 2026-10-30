# 第三方依赖

FTUN 使用的第三方库、运行库及借鉴实现，精确提交与校验信息见 LOCK.json。

## cJSON

开源协议：MIT

使用版本：1.7.19

仓库地址：https://github.com/DaveGamble/cJSON.git

集成能力：JSON 配置解析，仅编译 cJSON.c，嵌套深度限制为 32。

## heiher/lwIP

开源协议：BSD-3-Clause

使用版本：2.2.1.8-3-g150d2b1

仓库地址：https://github.com/heiher/lwip.git

集成能力：TUN 的 IPv4/IPv6 raw 协议栈、TCP 终结、UDP、分片及校验和。

## wolfSSL

开源协议：GPL-3.0-only；上游另提供商业许可。

使用版本：5.8.4

仓库地址：https://github.com/wolfSSL/wolfssl.git

集成能力：TLS 1.3 客户端、SNI、证书链与域名/IP 身份验证。

## wepoll

开源协议：BSD-2-Clause

使用版本：1.5.8

仓库地址：https://github.com/piscisaureus/wepoll.git

集成能力：Windows Socket 水平触发就绪通知，基于 AFD/IOCP，接入 FTUN 内存与句柄预算。

## Wintun API

开源协议：MIT (API header)；头文件也可选 GPL-2.0。

使用版本：0.14.1

仓库地址：https://git.zx2c4.com/wintun

集成能力：通过公开 API 使用适配器、session、收发环及读事件；不编译上游驱动源码。

## Wintun 签名运行库

开源协议：Wintun Prebuilt Binaries License（二进制许可）。

使用版本：0.14.1

仓库地址：https://git.zx2c4.com/wintun

集成能力：Windows TUN 驱动运行库，使用官方签名 DLL，支持 amd64 与 arm64。

## musl

开源协议：MIT

使用版本：参考提交 947b4574fa7998f027d3906e1f53acb9a7553c61

仓库地址：https://git.musl-libc.org/git/musl

集成能力：src/util/ip.c 借鉴 inet_pton/inet_ntop 实现 IPv6 文本解析与格式化，不引入整库或源码快照。

#ifndef FTUN_PLATFORM_LINUX_UAPI_H
#define FTUN_PLATFORM_LINUX_UAPI_H

/*
 * Minimal Linux userspace ABI declarations used by ftun. Some musl
 * toolchains ship libc headers without a Linux UAPI header bundle, so keep
 * the small stable wire ABI we need independent of glibc.
 */
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define FTUN_TUNSETIFF _IOW('T', 202, int)
#define FTUN_IFF_TUN 0x0001
#define FTUN_IFF_NO_PI 0x1000
#define FTUN_IFF_TUN_EXCL 0x8000

#define FTUN_NETLINK_ROUTE 0

struct ftun_sockaddr_nl {
  sa_family_t nl_family;
  unsigned short nl_pad;
  uint32_t nl_pid;
  uint32_t nl_groups;
};

struct ftun_nlmsghdr {
  uint32_t nlmsg_len;
  uint16_t nlmsg_type;
  uint16_t nlmsg_flags;
  uint32_t nlmsg_seq;
  uint32_t nlmsg_pid;
};

struct ftun_nlmsgerr {
  int error;
  struct ftun_nlmsghdr msg;
};

#define FTUN_NLM_F_REQUEST 0x01
#define FTUN_NLM_F_ACK 0x04
#define FTUN_NLM_F_DUMP_INTR 0x10
#define FTUN_NLM_F_ROOT 0x100
#define FTUN_NLM_F_MATCH 0x200
#define FTUN_NLM_F_DUMP (FTUN_NLM_F_ROOT | FTUN_NLM_F_MATCH)
#define FTUN_NLM_F_EXCL 0x200
#define FTUN_NLM_F_CREATE 0x400
#define FTUN_NLMSG_NOOP 0x1
#define FTUN_NLMSG_ERROR 0x2
#define FTUN_NLMSG_DONE 0x3
#define FTUN_NLMSG_OVERRUN 0x4
#define FTUN_NLMSG_ALIGNTO 4u
#define FTUN_NLMSG_ALIGN(length) \
  (((length) + FTUN_NLMSG_ALIGNTO - 1u) & ~(FTUN_NLMSG_ALIGNTO - 1u))
#define FTUN_NLMSG_HDRLEN \
  ((int)FTUN_NLMSG_ALIGN(sizeof(struct ftun_nlmsghdr)))
#define FTUN_NLMSG_LENGTH(length) ((length) + FTUN_NLMSG_HDRLEN)
#define FTUN_NLMSG_DATA(header) \
  ((void *)(((char *)(header)) + FTUN_NLMSG_HDRLEN))
#define FTUN_NLMSG_NEXT(header, length) \
  ((length) -= FTUN_NLMSG_ALIGN((header)->nlmsg_len), \
   (struct ftun_nlmsghdr *)(((char *)(header)) + \
                            FTUN_NLMSG_ALIGN((header)->nlmsg_len)))
#define FTUN_NLMSG_OK(header, length) \
  ((length) >= (int)sizeof(struct ftun_nlmsghdr) && \
   (header)->nlmsg_len >= sizeof(struct ftun_nlmsghdr) && \
   (header)->nlmsg_len <= (uint32_t)(length))

struct ftun_ifaddrmsg {
  uint8_t ifa_family;
  uint8_t ifa_prefixlen;
  uint8_t ifa_flags;
  uint8_t ifa_scope;
  uint32_t ifa_index;
};

#define FTUN_IFA_ADDRESS 1
#define FTUN_IFA_LOCAL 2

struct ftun_rtattr {
  uint16_t rta_len;
  uint16_t rta_type;
};

#define FTUN_RTA_ALIGNTO 4u
#define FTUN_RTA_ALIGN(length) \
  (((length) + FTUN_RTA_ALIGNTO - 1u) & ~(FTUN_RTA_ALIGNTO - 1u))
#define FTUN_RTA_LENGTH(length) \
  (FTUN_RTA_ALIGN(sizeof(struct ftun_rtattr)) + (length))
#define FTUN_RTA_DATA(attribute) \
  ((void *)(((char *)(attribute)) + FTUN_RTA_LENGTH(0u)))

struct ftun_rtmsg {
  uint8_t rtm_family;
  uint8_t rtm_dst_len;
  uint8_t rtm_src_len;
  uint8_t rtm_tos;
  uint8_t rtm_table;
  uint8_t rtm_protocol;
  uint8_t rtm_scope;
  uint8_t rtm_type;
  unsigned int rtm_flags;
};

#define FTUN_RTM_NEWADDR 20
#define FTUN_RTM_DELADDR 21
#define FTUN_RTM_GETADDR 22
#define FTUN_RTM_NEWROUTE 24
#define FTUN_RTM_DELROUTE 25
#define FTUN_RTM_GETROUTE 26
#define FTUN_RTM_NEWRULE 32
#define FTUN_RTM_DELRULE 33
#define FTUN_RTM_GETRULE 34
#define FTUN_RTN_UNICAST 1
#define FTUN_RTN_UNREACHABLE 7
#define FTUN_RT_SCOPE_UNIVERSE 0
#define FTUN_RT_SCOPE_LINK 253
#define FTUN_RT_TABLE_UNSPEC 0u
#define FTUN_RT_TABLE_DEFAULT 253u
#define FTUN_RT_TABLE_MAIN 254u
#define FTUN_RT_TABLE_LOCAL 255u
#define FTUN_RTA_DST 1
#define FTUN_RTA_OIF 4
#define FTUN_RTA_PRIORITY 6
#define FTUN_RTA_TABLE 15

struct ftun_fib_rule_hdr {
  uint8_t family;
  uint8_t dst_len;
  uint8_t src_len;
  uint8_t tos;
  uint8_t table;
  uint8_t res1;
  uint8_t res2;
  uint8_t action;
  uint32_t flags;
};

#define FTUN_FRA_DST 1
#define FTUN_FRA_IIFNAME 3
#define FTUN_FRA_PRIORITY 6
#define FTUN_FRA_FWMARK 10
#define FTUN_FRA_TABLE 15
#define FTUN_FRA_FWMASK 16
#define FTUN_FRA_PROTOCOL 21
#define FTUN_FR_ACT_TO_TBL 1
#define FTUN_FR_ACT_UNREACHABLE 7

typedef char ftun_uapi_sockaddr_nl_size[
  sizeof(struct ftun_sockaddr_nl) == 12u ? 1 : -1];
typedef char ftun_uapi_nlmsghdr_size[
  sizeof(struct ftun_nlmsghdr) == 16u ? 1 : -1];
typedef char ftun_uapi_nlmsgerr_size[
  sizeof(struct ftun_nlmsgerr) == 20u ? 1 : -1];
typedef char ftun_uapi_ifaddrmsg_size[
  sizeof(struct ftun_ifaddrmsg) == 8u ? 1 : -1];
typedef char ftun_uapi_rtattr_size[
  sizeof(struct ftun_rtattr) == 4u ? 1 : -1];
typedef char ftun_uapi_rtmsg_size[
  sizeof(struct ftun_rtmsg) == 12u ? 1 : -1];
typedef char ftun_uapi_fib_rule_hdr_size[
  sizeof(struct ftun_fib_rule_hdr) == 12u ? 1 : -1];

#endif

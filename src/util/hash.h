#ifndef FTUN_UTIL_HASH_H
#define FTUN_UTIL_HASH_H
#include "util/types.h"
#define FTUN_HASH_SEED_BYTES 16u
/* SipHash-2-4。key 和 seed 必须有效，seed 是 16 字节的进程内随机密钥；
 * 持久格式不得使用。 */
uint64_t ftun_hash_seeded(ftun_bytes_t key,
                          const uint8_t seed[FTUN_HASH_SEED_BYTES]);

/* 版本化的稳定磁盘哈希；不是索引随机化哈希，也不是密码学摘要。 */
ftun_status_t ftun_persistent_hash(uint32_t version, ftun_bytes_t key,
                                   uint64_t *out);

#endif

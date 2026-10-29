#ifndef FTUN_TESTS_FUZZ_COMMON_H
#define FTUN_TESTS_FUZZ_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* 每个目标导出 libFuzzer 入口：返回 0；违反不变量就 abort（libFuzzer 与回放驱动都把
 * 它当作崩溃）。内存错误由 ASan/UBSan 报告。可选导出：
 *   LLVMFuzzerInitialize    一次性初始化（建立长期存在的对象）；
 *   ftun_fuzz_seeds         向驱动提供内置种子（有效的样例输入）。 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

typedef void (*ftun_fuzz_seed_fn)(const uint8_t *data, size_t size);

#define FUZZ_REQUIRE(condition) do { \
  if (!(condition)) { \
    fprintf(stderr, "fuzz invariant violated at %s:%d: %s\n", \
            __FILE__, __LINE__, #condition); \
    abort(); \
  } \
} while (0)

/* 不可信输入不应触发的状态：内部状态损坏表示解析器把输入错误当成了内部不变量。 */
#define FUZZ_NOT_CORRUPT(status) FUZZ_REQUIRE((status) != FTUN_E_STATE_CORRUPT)

#endif

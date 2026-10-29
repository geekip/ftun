#ifndef FTUN_UTIL_TIME_MATH_H
#define FTUN_UTIL_TIME_MATH_H
#include <stdint.h>
/* 正整数加 ms/s/m/h；溢出或无效输入返回 0，不写输出。同步借用 value。 */
int ftun_duration_parse_ms(const char *value, uint64_t *out);
#endif

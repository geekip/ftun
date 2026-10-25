#ifndef FTUN_TEST_C_API_ABI_FIXTURE_H
#define FTUN_TEST_C_API_ABI_FIXTURE_H
#include <stddef.h>
#include <stdint.h>

/* 桥接层不包含当前公开头，历史调用方只看固定发行声明。 */
size_t ftun_test_current_layout(size_t *out, size_t capacity);
int ftun_test_service_create(const void *options, void **out);
void ftun_test_service_begin(int (*tick)(void *, void *), void *user,
                              int blocked);
void ftun_test_service_release(void);
uint64_t ftun_test_service_deadline(void);
int ftun_test_control_detach(void *core, int detach);
void ftun_test_fail_usage(void);
int ftun_test_budget_limits(void *core, size_t limits[3]);
#endif

#ifndef FTUN_TEST_FRS_FIXTURE_H
#define FTUN_TEST_FRS_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

int ftun_test_frs_fixture(uint8_t **out, size_t *length);
int ftun_test_write_file(const char *path, const uint8_t *data, size_t length);

#endif

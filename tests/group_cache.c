#define _POSIX_C_SOURCE 200809L
#include "config/model.h"
#include "config/parser.h"
#include "proxy/state/group_cache.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "group cache contract failed at line %d: %s\n", \
            __LINE__, #x); \
    return 1; \
  } \
} while (0)

static ftun_config_t *parse(const char *text)
{
  ftun_config_t *config = NULL;
  ftun_bytes_t bytes = {(const uint8_t *)text, strlen(text)};
  if (ftun_config_parse(bytes, &config) != FTUN_OK) return NULL;
  return config;
}

int main(void)
{
  char directory[] = "/tmp/ftun-group-cache-XXXXXX";
  char path[256];
  ftun_runtime_group_record_t records[2];
  ftun_group_cache_snapshot_t snapshot;
  ftun_group_cache_snapshot_t *loaded = NULL;
  ftun_config_t *first = NULL;
  ftun_config_t *second = NULL;
  uint64_t first_hash;
  uint64_t second_hash;
  int descriptor;
  uint8_t byte;
  CHECK(mkdtemp(directory) != NULL);
  CHECK(snprintf(path, sizeof(path), "%s/groups.cache", directory) > 0);
  memset(records, 0, sizeof(records));
  memset(&snapshot, 0, sizeof(snapshot));
  records[0].group = (ftun_string_t){"manual", 6u};
  records[0].member = (ftun_string_t){"node-b", 6u};
  records[0].kind = FTUN_RUNTIME_GROUP_SELECT;
  records[1].group = (ftun_string_t){"auto", 4u};
  records[1].member = (ftun_string_t){"node-a", 6u};
  records[1].kind = FTUN_RUNTIME_GROUP_URL_TEST;
  records[1].degraded = true;
  records[1].health_valid = true;
  records[1].health_success = false;
  records[1].latency_ms = 42u;
  records[1].observed_ms = 900u;
  snapshot.fingerprint = UINT64_C(0x1122334455667788);
  snapshot.saved_ms = 1000u;
  snapshot.records = records;
  snapshot.record_count = 2u;
  CHECK(ftun_group_cache_write(path, &snapshot) == FTUN_OK);
  CHECK(ftun_group_cache_load(path, &loaded) == FTUN_OK && loaded != NULL);
  CHECK(loaded->fingerprint == snapshot.fingerprint &&
        loaded->saved_ms == 1000u && loaded->health_clock_valid &&
        loaded->record_count == 2u);
  CHECK(loaded->records[1].kind == FTUN_RUNTIME_GROUP_URL_TEST &&
        loaded->records[1].degraded && loaded->records[1].health_valid &&
        !loaded->records[1].health_success &&
        loaded->records[1].latency_ms == 42u &&
        loaded->records[1].observed_ms == 900u);
  CHECK(memcmp(loaded->records[0].group.data, "manual", 6u) == 0);
  CHECK(ftun_group_cache_destroy(&loaded) == FTUN_OK && loaded == NULL);

  descriptor = open(path, O_RDWR);
  CHECK(descriptor >= 0 && lseek(descriptor, 45, SEEK_SET) == 45);
  CHECK(read(descriptor, &byte, 1u) == 1);
  byte ^= 0x80u;
  CHECK(lseek(descriptor, 45, SEEK_SET) == 45);
  CHECK(write(descriptor, &byte, 1u) == 1 && close(descriptor) == 0);
  CHECK(ftun_group_cache_load(path, &loaded) == FTUN_E_STATE_CORRUPT &&
        loaded == NULL);
  CHECK(ftun_group_cache_load("/tmp/ftun-group-cache-no-such-file", &loaded) ==
        FTUN_E_EOF);

  first = parse("{\"dns\":{\"enable\":false},\"outbounds\":["
    "{\"name\":\"node-a\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1\"},"
    "{\"name\":\"manual\",\"type\":\"select\",\"outbounds\":[\"node-a\"],"
    "\"default\":\"node-a\"}]}");
  second = parse("{\"dns\":{\"enable\":false},\"outbounds\":["
    "{\"name\":\"node-a\",\"type\":\"socks5\",\"server\":\"127.0.0.1:2\"},"
    "{\"name\":\"manual\",\"type\":\"select\",\"outbounds\":[\"node-a\"],"
    "\"default\":\"node-a\"}]}");
  CHECK(first != NULL && second != NULL);
  CHECK(ftun_group_cache_fingerprint(first, &first_hash) == FTUN_OK);
  CHECK(ftun_group_cache_fingerprint(first, &second_hash) == FTUN_OK &&
        first_hash == second_hash);
  CHECK(ftun_group_cache_fingerprint(second, &second_hash) == FTUN_OK &&
        first_hash != second_hash);
  CHECK(ftun_config_destroy(&first) == FTUN_OK);
  CHECK(ftun_config_destroy(&second) == FTUN_OK);
  CHECK(unlink(path) == 0 && rmdir(directory) == 0);
  return 0;
}

#include "config/parser.h"
#include "config/validate.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "config validation failed: %s\n", #x); \
    return 1; \
  } \
} while (0)

static ftun_status_t parse_text(const char *text, ftun_config_t **out)
{
  ftun_bytes_t bytes;
  bytes.data = (const uint8_t *)text;
  bytes.length = strlen(text);
  return ftun_config_parse(bytes, out);
}

static int expect_validation(const char *text, ftun_status_t expected,
                             const char *path)
{
  ftun_config_t *config = NULL;
  ftun_diagnostic_t diagnostic;
  ftun_status_t status;
  if (parse_text(text, &config) != FTUN_OK || config == NULL) {
    fprintf(stderr, "validation fixture did not parse\n");
    return 0;
  }
  memset(&diagnostic, 0xa5, sizeof(diagnostic));
  status = ftun_config_validate(config, &diagnostic);
  if (status != expected || diagnostic.error.status != expected) {
    fprintf(stderr, "unexpected validation status: got %s expected %s\n",
            ftun_status_name(status), ftun_status_name(expected));
    (void)ftun_config_destroy(&config);
    return 0;
  }
  if (expected == FTUN_OK) {
    if (diagnostic.message.data != NULL || diagnostic.message.length != 0u ||
        diagnostic.path.data != NULL || diagnostic.path.length != 0u) {
      fprintf(stderr, "success diagnostic was not cleared\n");
      (void)ftun_config_destroy(&config);
      return 0;
    }
  } else if (diagnostic.message.data == NULL || diagnostic.message.length == 0u ||
             diagnostic.path.data == NULL ||
             diagnostic.path.length != strlen(path) ||
             memcmp(diagnostic.path.data, path, diagnostic.path.length) != 0) {
    fprintf(stderr, "failure diagnostic is incomplete\n");
    (void)ftun_config_destroy(&config);
    return 0;
  }
  return ftun_config_destroy(&config) == FTUN_OK && config == NULL;
}

static char *read_file(const char *path, size_t *length)
{
  FILE *file;
  long size;
  char *data;
  *length = 0u;
  file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0L, SEEK_END) != 0) {
    if (file != NULL) (void)fclose(file);
    return NULL;
  }
  size = ftell(file);
  if (size < 0L || (unsigned long)size > FTUN_CONFIG_MAX_JSON_BYTES ||
      fseek(file, 0L, SEEK_SET) != 0) {
    (void)fclose(file);
    return NULL;
  }
  data = (char *)malloc((size_t)size + 1u);
  if (data == NULL) {
    (void)fclose(file);
    return NULL;
  }
  if (fread(data, 1u, (size_t)size, file) != (size_t)size || fclose(file) != 0) {
    free(data);
    return NULL;
  }
  data[size] = '\0';
  *length = (size_t)size;
  return data;
}

static char *make_deep_group_config(size_t groups)
{
  size_t capacity = groups * 160u + 256u;
  size_t used = 0u;
  size_t index;
  char *text = (char *)malloc(capacity);
  int written;
  if (text == NULL) return NULL;
  written = snprintf(text, capacity,
    "{\"dns\":{\"enable\":false},\"outbounds\":["
    "{\"name\":\"leaf\",\"type\":\"socks5\",\"server\":\"127.0.0.1:1\"}");
  if (written < 0 || (size_t)written >= capacity) {
    free(text);
    return NULL;
  }
  used = (size_t)written;
  for (index = 0u; index < groups; index++) {
    const char *member = index + 1u == groups ? "leaf" : NULL;
    if (member != NULL) {
      written = snprintf(text + used, capacity - used,
        ",{\"name\":\"g%03lu\",\"type\":\"select\","
        "\"outbounds\":[\"leaf\"],\"default\":\"leaf\"}",
        (unsigned long)index);
    } else {
      written = snprintf(text + used, capacity - used,
        ",{\"name\":\"g%03lu\",\"type\":\"select\","
        "\"outbounds\":[\"g%03lu\"],\"default\":\"g%03lu\"}",
        (unsigned long)index, (unsigned long)(index + 1u),
        (unsigned long)(index + 1u));
    }
    if (written < 0 || (size_t)written >= capacity - used) {
      free(text);
      return NULL;
    }
    used += (size_t)written;
  }
  if (used + 3u > capacity) {
    free(text);
    return NULL;
  }
  memcpy(text + used, "]}", 3u);
  return text;
}

/* TASK-CONFIG-003 / TEST-CONFIG-003：纯内存语义、引用与图校验。 */
int main(int argc, char **argv)
{
  static const char valid_rules[] =
    "{\"dns\":{\"enable\":false},\"frs\":{\"path\":\"rules.frs\"},"
    "\"outbounds\":[{\"name\":\"p\","
    "\"type\":\"socks5\",\"server\":\"proxy.example.:1080\"}],\"rules\":["
    "\"SRC-IP-CIDR,192.168.0.0/16,DIRECT\",\"IP-CIDR,10.0.0.0/8,p\","
    "\"DOMAIN,a.example,p\",\"DOMAIN-SUFFIX,example.com.,p\","
    "\"DOMAIN-KEYWORD,example,p\",\"FRS-IP,private,DIRECT\","
    "\"frs-domain,proxy,p\",\"DST-PORT,443,p\",\"NETWORK,udp,p\","
    "\"MATCH,DIRECT\"]}";
  static const char disabled_dns_refs[] =
    "{\"dns\":{\"enable\":false,\"default-server\":\"missing\","
    "\"listeners\":[{\"listen\":\"127.0.0.1:53\",\"server\":\"missing\"}],"
    "\"servers\":[{\"name\":\"s\",\"type\":\"udp\",\"address\":[\"1.1.1.1\"],"
    "\"outbound\":\"missing\"}]},\"frs\":{\"dns-server\":\"missing\"},"
    "\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
    "\"server\":\"127.0.0.1:1\",\"dns-server\":\"missing\"}]}";
  ftun_config_t *config = NULL;
  ftun_diagnostic_t diagnostic;
  ftun_bytes_t bytes;
  char *file_data;
  char *deep_groups;
  size_t file_length;

  CHECK(argc == 2);
  file_data = read_file(argv[1], &file_length);
  CHECK(file_data != NULL);
  bytes.data = (const uint8_t *)file_data;
  bytes.length = file_length;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_OK && config != NULL);
  memset(&diagnostic, 0xa5, sizeof(diagnostic));
  CHECK(ftun_config_validate(config, &diagnostic) == FTUN_OK);
  CHECK(diagnostic.error.status == FTUN_OK && diagnostic.message.data == NULL &&
        diagnostic.path.data == NULL);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  free(file_data);

  CHECK(ftun_config_validate(NULL, &diagnostic) == FTUN_E_INVALID);
  CHECK(diagnostic.path.length == 0u && diagnostic.message.length > 0u);
  CHECK(expect_validation(valid_rules, FTUN_OK, ""));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"outbounds\":[{"
                          "\"name\":\"　Proxy　\",\"type\":\"socks5\","
                          "\"server\":\"127.0.0.1:1\"}],\"rules\":["
                          "\"fRs-DoMaIn, CN , Proxy \" ]}", FTUN_OK, ""));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"outbounds\":[{"
                          "\"name\":\"Proxy\",\"type\":\"socks5\","
                          "\"server\":\"127.0.0.1:1\"}],\"rules\":["
                          "\"FRS-DOMAIN,CN,proxy\"]}", FTUN_E_INVALID,
                          "/rules"));
  CHECK(expect_validation(disabled_dns_refs, FTUN_OK, ""));
  CHECK(expect_validation("{\"base\":{\"ipv6\":true}}", FTUN_E_UNSUPPORTED,
                          "/base/ipv6"));
  CHECK(expect_validation("{\"log\":{\"level\":\"verbose\"}}", FTUN_E_INVALID,
                          "/log/level"));
  CHECK(expect_validation("{\"dns\":{\"fake-ip\":{\"range\":\"198.18.0.0/33\"}}}",
                          FTUN_E_INVALID, "/dns/fake-ip/range"));
  CHECK(expect_validation("{\"dns\":{\"bootstrap\":[\"01.1.1.1\"]}}",
                          FTUN_E_INVALID, "/dns/bootstrap"));
  CHECK(expect_validation("{\"dns\":{\"default-server\":\"missing\"}}",
                          FTUN_E_INVALID, "/dns/default-server"));
  CHECK(expect_validation("{\"dns\":{\"servers\":[{\"name\":\"s\",\"type\":\"udp\","
                          "\"address\":[\"dns.example:53\"],\"outbound\":\"missing\"}]}}",
                          FTUN_E_INVALID, "/dns/servers"));
  CHECK(expect_validation("{\"dns\":{\"listeners\":[{\"listen\":\"0.0.0.0:53\"},"
                          "{\"listen\":\"127.0.0.1:53\"}]}}",
                          FTUN_E_INVALID, "/dns/listeners"));
  CHECK(expect_validation("{\"inbounds\":[{\"name\":\"a\",\"type\":\"mixed\","
                          "\"listen\":\"0.0.0.0:1080\"},{\"name\":\"b\","
                          "\"type\":\"socks5\",\"listen\":\"127.0.0.1:1080\"}]}",
                          FTUN_E_INVALID, "/inbounds"));
  CHECK(expect_validation("{\"inbounds\":[{\"name\":\"bad,name\",\"type\":\"mixed\","
                          "\"listen\":\"127.0.0.1:1\"}]}",
                          FTUN_E_INVALID, "/inbounds"));
  CHECK(expect_validation("{\"inbounds\":[{\"name\":\"a\",\"type\":\"mixed\","
                          "\"listen\":\"127.0.0.1:1\"},{\"name\":\"a\","
                          "\"type\":\"socks5\",\"listen\":\"127.0.0.1:2\"}]}",
                          FTUN_E_INVALID, "/inbounds"));
  CHECK(expect_validation("{\"inbounds\":[{\"name\":\"a\",\"type\":\"mixed\","
                          "\"listen\":\"127.0.0.1:1\",\"outbound\":\"missing\"}]}",
                          FTUN_E_INVALID, "/inbounds"));
  CHECK(expect_validation("{\"inbounds\":[{\"name\":\"t\",\"type\":\"tun\","
                          "\"interface\":{\"name\":\"t0\"},\"ipv4\":{"
                          "\"address\":\"198.18.0.1/30\"}}]}",
                          FTUN_E_INVALID, "/dns/fake-ip/range"));
  CHECK(expect_validation("{\"outbounds\":[{\"name\":\"DIRECT\",\"type\":\"socks5\","
                          "\"server\":\"127.0.0.1:1\"}]}",
                          FTUN_E_INVALID, "/outbounds"));
  CHECK(expect_validation("{\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
                          "\"server\":\"bad_domain:1\"}]}",
                          FTUN_E_INVALID, "/outbounds"));
  CHECK(expect_validation("{\"outbounds\":[{\"name\":\"g\",\"type\":\"select\","
                          "\"outbounds\":[\"DIRECT\"],\"default\":\"REJECT\"}]}",
                          FTUN_E_INVALID, "/outbounds"));
  CHECK(expect_validation("{\"outbounds\":[{\"name\":\"a\",\"type\":\"select\","
                          "\"outbounds\":[\"b\"],\"default\":\"b\"},{\"name\":\"b\","
                          "\"type\":\"select\",\"outbounds\":[\"a\"],\"default\":\"a\"}]}",
                          FTUN_E_INVALID, "/outbounds"));
  CHECK(expect_validation("{\"outbounds\":[{\"name\":\"g\",\"type\":\"url-test\","
                          "\"outbounds\":[\"DIRECT\"],\"default\":\"DIRECT\","
                          "\"url\":\"ftp://example.com/x\",\"interval\":\"5s\","
                          "\"timeout\":\"6s\"}]}", FTUN_E_INVALID, "/outbounds"));
  CHECK(expect_validation("{\"outbounds\":[{\"name\":\"g\",\"type\":\"url-test\","
                          "\"outbounds\":[\"DIRECT\"],\"default\":\"DIRECT\","
                          "\"url\":\"https://example.com/x\",\"interval\":\"5s\","
                          "\"timeout\":\"6s\"}]}", FTUN_E_INVALID, "/outbounds"));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"rules\":["
                          "\"IP-CIDR,10.0.0.1/8,DIRECT\"]}", FTUN_OK, ""));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"rules\":["
                          "\"IP-CIDR,10.0.0.1/33,DIRECT\"]}",
                          FTUN_E_INVALID, "/rules"));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"rules\":["
                          "\"DOMAIN,é.example,DIRECT\"]}",
                          FTUN_E_INVALID, "/rules"));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"rules\":["
                          "\"MATCH,missing\"]}", FTUN_E_INVALID, "/rules"));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"rules\":["
                          "\"FRS-IP,private,DIRECT\"]}", FTUN_OK, ""));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"frs\":42}",
                          FTUN_OK, ""));
  CHECK(expect_validation("{\"dns\":{\"enable\":false},\"frs\":{"
                          "\"auto-update\":true},\"rules\":["
                          "\"FRS-IP,private,DIRECT\"]}", FTUN_OK, ""));

  deep_groups = make_deep_group_config(65u);
  CHECK(deep_groups != NULL);
  CHECK(expect_validation(deep_groups, FTUN_E_LIMIT, "/outbounds"));
  free(deep_groups);
  return 0;
}

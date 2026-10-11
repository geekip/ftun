#include "config/model.h"
#include "config/parser.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "config parser failed: %s\n", #x); \
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

static int expect_status(const char *text, ftun_status_t expected)
{
  ftun_config_t *config = (ftun_config_t *)(uintptr_t)1;
  ftun_status_t status = parse_text(text, &config);
  if (status != expected || config != NULL) {
    fprintf(stderr, "unexpected parse status: got %s expected %s\n",
            ftun_status_name(status), ftun_status_name(expected));
    if (config != NULL && config != (ftun_config_t *)(uintptr_t)1) {
      (void)ftun_config_destroy(&config);
    }
    return 0;
  }
  return 1;
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

static char *make_nested(size_t depth)
{
  size_t index;
  char *text = (char *)malloc(depth * 2u + 2u);
  if (text == NULL) return NULL;
  for (index = 0u; index < depth; index++) text[index] = '[';
  text[depth] = '0';
  for (index = 0u; index < depth; index++) text[depth + 1u + index] = ']';
  text[depth * 2u + 1u] = '\0';
  return text;
}

static char *make_long_string(size_t length)
{
  char *text = (char *)malloc(length + 15u);
  if (text == NULL) return NULL;
  memcpy(text, "{\"rules\":[\"", 11u);
  memset(text + 11u, 'a', length);
  memcpy(text + 11u + length, "\"]}", 4u);
  return text;
}

static char *make_large_array(size_t count)
{
  size_t index;
  size_t offset = 10u;
  char *text = (char *)malloc(count * 4u + 12u);
  if (text == NULL) return NULL;
  memcpy(text, "{\"rules\":[", offset);
  for (index = 0u; index < count; index++) {
    if (index != 0u) text[offset++] = ',';
    text[offset++] = '"';
    text[offset++] = 'x';
    text[offset++] = '"';
  }
  text[offset++] = ']';
  text[offset++] = '}';
  text[offset] = '\0';
  return text;
}

/* TASK-CONFIG-002 / TEST-CONFIG-002：有界解析、类型模型和失败清理。 */
int main(int argc, char **argv)
{
  static const char disabled_dns[] =
    "{\"dns\":{\"enable\":false,\"default-server\":\"missing\"},"
    "\"frs\":42,\"inbounds\":[{\"name\":\"本地\","
    "\"type\":\"mixed\",\"listen\":\"127.0.0.1:1\",\"users\":{\"u\":\"p\"}}],"
    "\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
    "\"server\":\"127.0.0.1:2\",\"username\":\"u\",\"password\":\"p\"}]}";
  ftun_config_t *config = NULL;
  ftun_bytes_t bytes;
  char *file_data;
  char *generated;
  size_t file_length;
  uint8_t invalid_utf8[] = {'{', '"', 'r', 'u', 'l', 'e', 's', '"', ':', '[',
                            '"', 0xc2u, '"', ']', '}'};

  CHECK(argc == 2);
  file_data = read_file(argv[1], &file_length);
  CHECK(file_data != NULL);
  bytes.data = (const uint8_t *)file_data;
  bytes.length = file_length;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_OK && config != NULL);
  memset(file_data, 'x', file_length);
  free(file_data);
  CHECK(strcmp(config->base.cache_file, "./state/ftun.cache") == 0);
  CHECK(config->dns.enable && config->dns.listener_count == 2u &&
        config->dns.server_count == 2u);
  CHECK(config->inbound_count == 3u &&
        config->inbounds[2].kind == FTUN_CONFIG_INBOUND_TUN &&
        config->inbounds[2].mtu == 1500u && config->inbounds[2].strict_route);
  CHECK(config->outbound_count == 4u &&
        config->outbounds[2].kind == FTUN_CONFIG_OUTBOUND_URL_TEST &&
        config->outbounds[2].expected_status == 204u &&
        config->outbounds[3].members.count == 3u);
  CHECK(config->rules.count == 6u && strcmp(config->rules.items[3],
        "DOMAIN,a.com,proxy") == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK && config == NULL);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(parse_text("{}", &config) == FTUN_OK);
  CHECK(!config->base.ipv6 && !config->base.allow_lan && config->base.state_cache &&
        strcmp(config->log.level, "warn") == 0 && config->dns.enable &&
        strcmp(config->dns.fake_ip.range, "198.18.0.0/15") == 0 &&
        config->sniff.tls_sni && config->sniff.http_host);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(parse_text(disabled_dns, &config) == FTUN_OK);
  CHECK(!config->dns.enable && strcmp(config->dns.default_server, "missing") == 0 &&
        !config->frs.active && !config->frs.present &&
        config->inbounds[0].user_count == 1u &&
        strcmp(config->inbounds[0].users[0].name, "u") == 0 &&
        strcmp(config->outbounds[0].password, "p") == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(parse_text("{\"dns\":{\"enable\":false},\"frs\":{"
                   "\"path\":\"rules.frs\",\"url\":\"https://example.com/rules.frs\","
                   "\"auto-update\":true},\"rules\":[\"frs-domain,CN,DIRECT\"]}",
                   &config) == FTUN_OK);
  CHECK(config->frs.active && config->frs.present && config->frs.auto_update &&
        strcmp(config->frs.path, "rules.frs") == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(parse_text("{\"dns\":{\"enable\":false},\"outbounds\":[{"
                   "\"name\":\"　Proxy🚀　\",\"type\":\"socks5\","
                   "\"server\":\"127.0.0.1:1\"}],\"rules\":["
                   "\"FrS-DoMaIn, CN ,　Proxy🚀　\"]}", &config) == FTUN_OK);
  CHECK(strcmp(config->outbounds[0].name, "Proxy🚀") == 0 &&
        strcmp(config->rules.items[0], "FrS-DoMaIn,CN,Proxy🚀") == 0);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);

  CHECK(expect_status("", FTUN_E_INVALID));
  CHECK(expect_status("[]", FTUN_E_INVALID));
  CHECK(expect_status("{} trailing", FTUN_E_INVALID));
  CHECK(expect_status("{\"base\":{},\"base\":{}}", FTUN_E_INVALID));
  CHECK(expect_status("{\"base\":{},\"\\u0062ase\":{}}", FTUN_E_INVALID));
  CHECK(expect_status("{\"unknown\":1}", FTUN_E_INVALID));
  CHECK(expect_status("{\"base\":{\"unknown\":1}}", FTUN_E_INVALID));
  CHECK(expect_status("{\"base\":{\"ipv6\":0}}", FTUN_E_INVALID));
  CHECK(expect_status("{\"api\":{}}", FTUN_E_UNSUPPORTED));
  CHECK(expect_status("{\"plugins\":[]}", FTUN_E_UNSUPPORTED));
  CHECK(expect_status("{\"inbounds\":[{\"name\":\"x\",\"type\":\"http\","
                      "\"listen\":\"127.0.0.1:1\"}]}", FTUN_E_UNSUPPORTED));
  CHECK(expect_status("{\"inbounds\":[{\"type\":\"mixed\","
                      "\"listen\":\"127.0.0.1:1\"}]}", FTUN_E_INVALID));
  CHECK(expect_status("{\"outbounds\":[{\"name\":\"p\",\"type\":\"socks5\","
                      "\"server\":\"127.0.0.1:1\",\"username\":\"u\"}]}",
                      FTUN_E_INVALID));
  CHECK(expect_status("{\"inbounds\":[{\"name\":\"t\",\"type\":\"tun\","
                      "\"interface\":{\"name\":\"t0\",\"mtu\":1.5},"
                      "\"ipv4\":{\"address\":\"10.0.0.1/24\"}}]}", FTUN_E_INVALID));
  CHECK(expect_status("{\"outbounds\":[{\"name\":\"g\",\"type\":\"url-test\","
                      "\"outbounds\":[\"DIRECT\"],\"default\":\"DIRECT\","
                      "\"url\":\"http://x\",\"tolerance\":4294967296}]}",
                      FTUN_E_INVALID));
  CHECK(expect_status("{\"$schema\":\"\\u0000x\"}", FTUN_E_INVALID));

  bytes.data = invalid_utf8;
  bytes.length = sizeof(invalid_utf8);
  config = (ftun_config_t *)(uintptr_t)1;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_E_INVALID && config == NULL);
  bytes.data = (const uint8_t *)"\xef\xbb\xbf{}";
  bytes.length = 5u;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_OK && config != NULL);
  CHECK(ftun_config_destroy(&config) == FTUN_OK);
  bytes.data = (const uint8_t *)"\xef\xbb\xbf\xef\xbb\xbf{}";
  bytes.length = 8u;
  config = (ftun_config_t *)(uintptr_t)1;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_E_INVALID && config == NULL);
  bytes.data = (const uint8_t *)"{}\0x";
  bytes.length = 4u;
  config = (ftun_config_t *)(uintptr_t)1;
  CHECK(ftun_config_parse(bytes, &config) == FTUN_E_INVALID && config == NULL);

  generated = make_nested(FTUN_CONFIG_MAX_DEPTH + 1u);
  CHECK(generated != NULL && expect_status(generated, FTUN_E_LIMIT));
  free(generated);
  generated = make_long_string(FTUN_CONFIG_MAX_STRING_BYTES + 1u);
  CHECK(generated != NULL && expect_status(generated, FTUN_E_LIMIT));
  free(generated);
  generated = make_large_array(FTUN_CONFIG_MAX_ARRAY_ITEMS + 1u);
  CHECK(generated != NULL && expect_status(generated, FTUN_E_LIMIT));
  free(generated);
  generated = (char *)malloc(FTUN_CONFIG_MAX_JSON_BYTES + 2u);
  CHECK(generated != NULL);
  memset(generated, ' ', FTUN_CONFIG_MAX_JSON_BYTES + 1u);
  generated[FTUN_CONFIG_MAX_JSON_BYTES + 1u] = '\0';
  CHECK(expect_status(generated, FTUN_E_LIMIT));
  free(generated);

  bytes.data = (const uint8_t *)"{}";
  bytes.length = 2u;
  CHECK(ftun_config_parse(bytes, NULL) == FTUN_E_INVALID);
  CHECK(ftun_config_destroy(NULL) == FTUN_E_INVALID);
  return 0;
}

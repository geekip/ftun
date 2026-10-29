#ifndef FTUN_CORE_CONFIG_SYNTAX_H
#define FTUN_CORE_CONFIG_SYNTAX_H
#include "core/config/document.h"
/* 无I/O、无分配的字段词法校验；诊断字符串为静态借用。 */
typedef struct {
  uint32_t address;
  uint32_t mask;
} ftun_config_cidr_t;

typedef struct {
  uint32_t address;
  uint16_t port;
} ftun_config_listener_t;

ftun_status_t ftun_config_diagnostic(ftun_diagnostic_t *out,
                                            ftun_status_t status,
                                            const char *path,
                                            const char *message);
int ftun_span_equal(const char *data, size_t length, const char *value);
int ftun_span_equal_ascii_fold(const char *data, size_t length,
                                      const char *value);
int ftun_name_span_valid(const char *value, size_t length);
int ftun_name_valid(const char *value);
int ftun_path_valid(const char *value);
int ftun_ipv4_span(const char *value, size_t length, uint32_t *out);
int ftun_domain_span(const char *value, size_t length);
int ftun_host_span(const char *value, size_t length, uint32_t *ipv4,
                          int *is_ipv4);
int ftun_listen_address(const char *value, ftun_config_listener_t *out);
int ftun_server_address(const char *value, int port_required,
                               uint32_t *ipv4, int *is_ipv4);
int ftun_bootstrap_address(const char *value, uint32_t *out);
int ftun_cidr(const char *value, int require_network,
                     ftun_config_cidr_t *out);
int ftun_http_url(const char *value, uint32_t *ipv4, int *is_ipv4);
int ftun_list_contains(const ftun_config_string_list_t *list,
                              const char *value);
int ftun_ascii_token(const char *value, size_t length);
int ftun_config_cidr_has(const ftun_config_cidr_t *cidr, uint32_t address);
int ftun_cidr_overlap(const ftun_config_cidr_t *left,
                             const ftun_config_cidr_t *right);
int ftun_listener_conflict(const ftun_config_listener_t *left,
                                  const ftun_config_listener_t *right);
#endif

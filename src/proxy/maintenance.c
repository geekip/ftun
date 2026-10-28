#define _GNU_SOURCE 1

#include "proxy/engine_internal.h"
#include "network/address.h"

int ftun_proxy_runtime_duration_ms(const char *value, uint64_t *out)
{
  size_t length;
  size_t digits;
  size_t index;
  uint64_t result = 0u;
  uint64_t multiplier;
  if (value == NULL) return 0;
  length = strlen(value);
  if (length < 2u || value[0] < '1' || value[0] > '9') return 0;
  if (length >= 3u && value[length - 2u] == 'm' &&
      value[length - 1u] == 's') {
    digits = length - 2u;
    multiplier = 1u;
  } else {
    digits = length - 1u;
    if (value[length - 1u] == 's') multiplier = UINT64_C(1000);
    else if (value[length - 1u] == 'm') multiplier = UINT64_C(60000);
    else if (value[length - 1u] == 'h') multiplier = UINT64_C(3600000);
    else return 0;
  }
  for (index = 0u; index < digits; index++) {
    uint64_t digit;
    if (value[index] < '0' || value[index] > '9') return 0;
    digit = (uint64_t)(value[index] - '0');
    if (result > (UINT64_MAX - digit) / 10u) return 0;
    result = result * 10u + digit;
  }
  if (result == 0u || result > UINT64_MAX / multiplier) return 0;
  *out = result * multiplier;
  return 1;
}

ftun_status_t ftun_proxy_runtime_http_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size)
{
  const ftun_proxy_runtime_http_work_t *header;
  const char *url;
  const char *username;
  const char *password;
  const char *etag;
  ftun_http_fetch_spec_t spec;
  ftun_http_fetch_result_t fetched;
  ftun_proxy_runtime_http_result_t output;
  ftun_budget_t *budget = NULL;
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_runtime_t *prepared = NULL;
  ftun_frs_view_t *view = NULL;
#endif
  size_t expected;
  size_t maximum;
  size_t total;
  size_t copied_body;
  ftun_status_t status;
  if (out_result_size != NULL) *out_result_size = 0u;
  if (input.data == NULL || input.length < sizeof(*header) || result == NULL ||
      out_result_size == NULL || result_capacity < sizeof(output)) return FTUN_E_INVALID;
  header = (const ftun_proxy_runtime_http_work_t *)input.data;
  if (header->magic != FTUN_PROXY_RUNTIME_HTTP_WORK_MAGIC ||
      header->budget == 0u || header->maximum_bytes == 0u || header->maximum_bytes > SIZE_MAX ||
      header->url_length == 0u) return FTUN_E_INVALID;
  maximum = (size_t)header->maximum_bytes;
  expected = sizeof(*header);
  if (header->url_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->url_length;
  if (header->username_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->username_length;
  if (header->password_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->password_length;
  if (header->etag_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += header->etag_length;
  if (expected != input.length || header->etag_length >
      FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES ||
      (header->use_proxy != 0u && header->proxy_port == 0u) ||
      (header->validate_frs != 0u && header->runtime_snapshot == 0u)) {
    return FTUN_E_INVALID;
  }
  /* 宿主在所有Worker及结果清理结束后才销毁预算，任务只借用。 */
  budget = (ftun_budget_t *)header->budget;
  url = (const char *)input.data + sizeof(*header);
  username = url + header->url_length;
  password = username + header->username_length;
  etag = password + header->password_length;
  memset(&spec, 0, sizeof(spec));
  spec.budget = budget;
  spec.url.data = url;
  spec.url.length = header->url_length;
  spec.maximum_bytes = maximum;
  spec.deadline_ms = header->deadline_ms;
  spec.socket_mark = header->mark;
  spec.generation = header->generation;
  spec.purpose = header->purpose;
  spec.resolver = header->resolver;
  spec.path = header->path;
  spec.allow_system_resolver = header->allow_system_resolver;
  spec.use_proxy = header->use_proxy != 0u;
  if (spec.use_proxy) {
    spec.proxy.kind = header->proxy_domain[0] == '\0'
      ? FTUN_ADDRESS_IPV4 : FTUN_ADDRESS_DOMAIN;
    spec.proxy.port = header->proxy_port;
    memcpy(spec.proxy.address, header->proxy_address, 4u);
    memcpy(spec.proxy_domain, header->proxy_domain,
           sizeof(spec.proxy_domain));
    if (spec.proxy.kind == FTUN_ADDRESS_DOMAIN) {
      spec.proxy.domain.data = spec.proxy_domain;
      spec.proxy.domain.length = strlen(spec.proxy_domain);
    }
  }
  spec.proxy_username.data = username;
  spec.proxy_username.length = header->username_length;
  spec.proxy_password.data = password;
  spec.proxy_password.length = header->password_length;
  spec.if_none_match.data = etag;
  spec.if_none_match.length = header->etag_length;
  memset(&fetched, 0, sizeof(fetched));
  status = ftun_http_fetch(&spec, &fetched);
#if defined(FTUN_HAVE_MODULE_FRS)
  if (status == FTUN_OK && header->validate_frs != 0u &&
      fetched.status == 200u) {
    const ftun_config_t *config = NULL;
    status = ftun_frs_open_bytes_budget(budget,
      (ftun_bytes_t){fetched.data, fetched.length}, &view);
    if (status == FTUN_OK) {
      status = ftun_runtime_config(
        (ftun_runtime_t *)header->runtime_snapshot, &config);
    }
    if (status == FTUN_OK) {
      status = ftun_runtime_prepare_detached_frs(config, view, &prepared);
      if (status == FTUN_OK) view = NULL;
    }
  }
#else
  if (status == FTUN_OK && header->validate_frs != 0u) {
    status = FTUN_E_UNSUPPORTED;
  }
#endif
  if (status == FTUN_OK) {
    size_t etag_length = fetched.etag == NULL ? 0u : strlen(fetched.etag);
    copied_body = header->validate_frs != 0u ? 0u : fetched.length;
    if (etag_length > FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES ||
        fetched.length > maximum ||
        etag_length > SIZE_MAX - sizeof(output) ||
        copied_body > SIZE_MAX - sizeof(output) - etag_length) {
      status = FTUN_E_LIMIT;
    } else {
      total = sizeof(output) + etag_length + copied_body;
      if (total > result_capacity) status = FTUN_E_LIMIT;
      else {
        memset(&output, 0, sizeof(output));
        output.status = fetched.status;
        output.etag_length = (uint32_t)etag_length;
        output.body_length = fetched.length;
#if defined(FTUN_HAVE_MODULE_FRS)
        output.prepared_runtime = (uintptr_t)prepared;
#endif
        output.tls_verified = fetched.tls_verified ? 1u : 0u;
        memcpy(result, &output, sizeof(output));
        if (etag_length != 0u) {
          memcpy(result + sizeof(output), fetched.etag, etag_length);
        }
        if (copied_body != 0u) {
          memcpy(result + sizeof(output) + etag_length,
                 fetched.data, copied_body);
        }
        *out_result_size = total;
#if defined(FTUN_HAVE_MODULE_FRS)
        prepared = NULL;
#endif
      }
    }
  }
  /* 失败结果也保留清理拥有者，由 Worker 在 owner 上收尾。 */
  if (*out_result_size == 0u) {
    memset(&output, 0, sizeof(output));
    memcpy(result, &output, sizeof(output));
    *out_result_size = sizeof(output);
  }
  memcpy(&output, result, sizeof(output));
#if defined(FTUN_HAVE_MODULE_FRS)
  {
    ftun_status_t cleanup = ftun_runtime_prepared_release(&prepared);
    if (status == FTUN_OK) status = cleanup;
    if (prepared != NULL) output.prepared_runtime = (uintptr_t)prepared;
    cleanup = ftun_frs_view_release(&view);
    if (status == FTUN_OK) status = cleanup;
    output.cleanup_view = (uintptr_t)view;
  }
#endif
  ftun_http_fetch_release(&fetched);
  memcpy(result, &output, sizeof(output));
  return status;
}

ftun_status_t ftun_proxy_runtime_http_input_cleanup(ftun_bytes_t input)
{
  ftun_proxy_runtime_http_work_t header;
  ftun_runtime_t *runtime;
  ftun_status_t status;
  if (input.data == NULL || input.length < sizeof(header)) return FTUN_E_INVALID;
  memcpy(&header, input.data, sizeof(header));
  if (header.magic != FTUN_PROXY_RUNTIME_HTTP_WORK_MAGIC) return FTUN_E_INVALID;
  if (header.runtime_snapshot == 0u) return FTUN_OK;
  runtime = (ftun_runtime_t *)header.runtime_snapshot;
  status = ftun_runtime_release(&runtime);
  header.runtime_snapshot = (uintptr_t)runtime;
  memcpy((void *)(uintptr_t)input.data, &header, sizeof(header));
  /* 已消费引用的失败对象由 manager 接管，不再属于 Worker。 */
  return runtime == NULL ? FTUN_OK : status;
}

ftun_status_t ftun_proxy_runtime_http_result_cleanup(ftun_bytes_t result)
{
  ftun_proxy_runtime_http_result_t output;
#if defined(FTUN_HAVE_MODULE_FRS)
  ftun_status_t status;
  ftun_runtime_t *prepared;
  ftun_frs_view_t *view;
#endif
  if (result.data == NULL || result.length < sizeof(output)) return FTUN_E_INVALID;
  memcpy(&output, result.data, sizeof(output));
#if defined(FTUN_HAVE_MODULE_FRS)
  prepared = (ftun_runtime_t *)output.prepared_runtime;
  status = ftun_runtime_prepared_release(&prepared);
  output.prepared_runtime = (uintptr_t)prepared;
  memcpy((void *)(uintptr_t)result.data, &output, sizeof(output));
  if (status != FTUN_OK) return status;
  view = (ftun_frs_view_t *)output.cleanup_view;
  status = ftun_frs_view_release(&view);
  output.cleanup_view = (uintptr_t)view;
  memcpy((void *)(uintptr_t)result.data, &output, sizeof(output));
  if (status != FTUN_OK) return status;
#endif
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_http_submit(
  ftun_proxy_runtime_t *engine, const ftun_http_fetch_spec_t *spec,
  bool validate_frs, ftun_runtime_t *runtime_snapshot,
  ftun_worker_completion_fn completion, void *user,
  ftun_operation_t **out)
{
  ftun_proxy_runtime_http_work_t *header;
  ftun_worker_job_t job;
  uint8_t *input;
  size_t input_length;
  size_t result_capacity;
  size_t username_length;
  size_t password_length;
  size_t etag_length;
  ftun_reservation_t *input_reservation = NULL;
  ftun_status_t release_status;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || engine->budget == NULL || spec == NULL || completion == NULL || out == NULL ||
      spec->url.data == NULL || spec->url.length == 0u ||
      spec->url.length > UINT32_MAX || spec->maximum_bytes == 0u) {
    return FTUN_E_INVALID;
  }
  if (validate_frs != (runtime_snapshot != NULL)) return FTUN_E_INVALID;
  username_length = spec->proxy_username.length;
  password_length = spec->proxy_password.length;
  etag_length = spec->if_none_match.length;
  if (username_length > UINT32_MAX || password_length > UINT32_MAX ||
      etag_length > FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES ||
      spec->maximum_bytes > SIZE_MAX - sizeof(ftun_proxy_runtime_http_result_t) -
                            FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES) return FTUN_E_LIMIT;
  input_length = sizeof(*header);
  if (spec->url.length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += spec->url.length;
  if (username_length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += username_length;
  if (password_length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += password_length;
  if (etag_length > SIZE_MAX - input_length) return FTUN_E_LIMIT;
  input_length += etag_length;
  result_capacity = sizeof(ftun_proxy_runtime_http_result_t) +
                    FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES +
                    (validate_frs ? 0u : spec->maximum_bytes);
  status = ftun_budget_reserve(engine->budget, input_length,
                               &input_reservation);
  if (status != FTUN_OK) return status;
  input = (uint8_t *)calloc(1u, input_length);
  if (input == NULL) {
    (void)ftun_reservation_release(&input_reservation);
    return FTUN_E_LIMIT;
  }
  header = (ftun_proxy_runtime_http_work_t *)input;
  header->magic = FTUN_PROXY_RUNTIME_HTTP_WORK_MAGIC;
  header->budget = (uintptr_t)engine->budget;
  header->mark = spec->socket_mark;
  header->generation = spec->generation;
  header->purpose = spec->purpose;
  header->resolver = spec->resolver;
  header->path = engine->control_path;
  header->allow_system_resolver = true;
#if defined(FTUN_HAVE_MODULE_TUN)
  header->allow_system_resolver = !engine->tun_auto_route;
#endif
  header->maximum_bytes = spec->maximum_bytes;
  header->deadline_ms = spec->deadline_ms;
  header->use_proxy = spec->use_proxy ? 1u : 0u;
  header->validate_frs = validate_frs ? 1u : 0u;
  header->runtime_snapshot = (uintptr_t)runtime_snapshot;
  header->proxy_port = spec->proxy.port;
  memcpy(header->proxy_address, spec->proxy.address, 4u);
  memcpy(header->proxy_domain, spec->proxy_domain,
         sizeof(header->proxy_domain));
  header->url_length = (uint32_t)spec->url.length;
  header->username_length = (uint32_t)username_length;
  header->password_length = (uint32_t)password_length;
  header->etag_length = (uint32_t)etag_length;
  memcpy(input + sizeof(*header), spec->url.data, spec->url.length);
  if (username_length != 0u) {
    memcpy(input + sizeof(*header) + spec->url.length,
           spec->proxy_username.data, username_length);
  }
  if (password_length != 0u) {
    memcpy(input + sizeof(*header) + spec->url.length + username_length,
           spec->proxy_password.data, password_length);
  }
  if (etag_length != 0u) {
    memcpy(input + sizeof(*header) + spec->url.length + username_length +
           password_length, spec->if_none_match.data, etag_length);
  }
  memset(&job, 0, sizeof(job));
  job.execute = ftun_proxy_runtime_http_execute;
  job.input.data = input;
  job.input.length = input_length;
  job.result_capacity = result_capacity;
  job.input_cleanup = ftun_proxy_runtime_http_input_cleanup;
  job.result_cleanup = ftun_proxy_runtime_http_result_cleanup;
  job.deadline_ms = spec->deadline_ms;
  if (runtime_snapshot != NULL) {
    status = ftun_runtime_retain(runtime_snapshot);
    if (status != FTUN_OK) {
      free(input);
      (void)ftun_reservation_release(&input_reservation);
      return status;
    }
  }
  status = ftun_worker_submit(engine->maintenance_worker, &job, completion,
                              user, out);
  if (status != FTUN_OK && runtime_snapshot != NULL) {
    (void)ftun_runtime_release(&runtime_snapshot);
  }
  free(input);
  release_status = ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK && release_status != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

int ftun_proxy_runtime_nonblocking(int descriptor)
{
  int flags = fcntl(descriptor, F_GETFL, 0);
  return flags >= 0 &&
         fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

ftun_status_t ftun_proxy_runtime_parse_ipv4_endpoint(
  const char *text, ftun_endpoint_t *out)
{
  ftun_host_port_t value;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (text == NULL || out == NULL ||
      !ftun_host_port_split(text, strlen(text), &value) ||
      !value.has_port || value.bracketed ||
      !ftun_ipv4_parse(value.host, value.host_length, out->address)) {
    return FTUN_E_INVALID;
  }
  out->kind = FTUN_ADDRESS_IPV4;
  out->port = value.port;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_parse_server_endpoint(
  const char *text, ftun_endpoint_t *out)
{
  ftun_host_port_t value;
  ftun_status_t status = ftun_proxy_runtime_parse_ipv4_endpoint(text, out);
  if (status == FTUN_OK) return FTUN_OK;
  if (!ftun_host_port_split(text, strlen(text), &value) || !value.has_port ||
      value.bracketed || value.host_length > 253u) return FTUN_E_INVALID;
  memset(out, 0, sizeof(*out));
  out->kind = FTUN_ADDRESS_DOMAIN;
  out->domain.data = text;
  out->domain.length = value.host_length;
  out->port = value.port;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_parse_bootstrap_endpoint(
  const char *text, ftun_endpoint_t *out)
{
  ftun_host_port_t value;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (text == NULL || out == NULL ||
      !ftun_host_port_split(text, strlen(text), &value) || value.bracketed ||
      !ftun_ipv4_parse(value.host, value.host_length, out->address)) {
    return FTUN_E_INVALID;
  }
  out->kind = FTUN_ADDRESS_IPV4;
  out->port = value.has_port ? value.port : 53u;
  return FTUN_OK;
}

#if defined(FTUN_HAVE_MODULE_FAKEIP)
ftun_status_t ftun_proxy_runtime_fakeip_range(const char *text,
                                               uint32_t *first,
                                               uint32_t *end)
{
  ftun_cidr_t cidr;
  if (first != NULL) *first = 0u;
  if (end != NULL) *end = 0u;
  if (text == NULL || first == NULL || end == NULL ||
      !ftun_cidr_parse(text, strlen(text), true, &cidr) ||
      !ftun_cidr_ipv4_hosts(&cidr, first, end)) return FTUN_E_INVALID;
  return FTUN_OK;
}

void ftun_proxy_runtime_fakeip_store_completed(
  ftun_operation_t *operation, ftun_error_t error,
  ftun_fakeip_store_operation_t kind, uint64_t sequence,
  uint32_t reserved_end, void *user)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  (void)operation;
  (void)sequence;
  (void)reserved_end;
  if (engine == NULL) return;
  if (kind == FTUN_FAKEIP_STORE_RESERVATION &&
      engine->fakeip_reserve_operation == operation) {
    engine->fakeip_reserve_operation = NULL;
  }
  engine->fakeip_store_status = error.status;
  if (engine->fakeip_store_completions != SIZE_MAX) {
    engine->fakeip_store_completions++;
  }
  if (kind == FTUN_FAKEIP_STORE_RESERVATION && error.status != FTUN_OK) {
    engine->fakeip_reserve_warning = true;
    ftun_proxy_runtime_background_log(engine, error.status,
      FTUN_DIAGNOSTIC_FAKEIP_RESERVE, "persistent FakeIP reservation failed; existing mappings remain readable");
  } else if (kind == FTUN_FAKEIP_STORE_RESERVATION) {
    engine->fakeip_reserve_warning = false;
  }
}

ftun_status_t ftun_proxy_runtime_wait_worker_until(ftun_proxy_runtime_t *engine,
                                                    ftun_worker_t *worker,
                                                    size_t expected,
                                                    uint64_t deadline_ms)
{
  ftun_status_t status;
  if (worker == NULL) return FTUN_E_INVALID;
  while (engine->fakeip_store_completions < expected) {
    uint64_t now;
    size_t callbacks = 0u;
    status = ftun_worker_poll(worker, 64u, &callbacks);
    if (status != FTUN_OK) return status;
    status = ftun_monotonic_now(&now);
    if (status != FTUN_OK) return status;
    if (now >= deadline_ms) return FTUN_E_TIMEOUT;
    if (callbacks == 0u) sched_yield();
  }
  return engine->fakeip_store_status;
}

ftun_status_t ftun_proxy_runtime_wait_worker(ftun_proxy_runtime_t *engine,
                                              ftun_worker_t *worker,
                                              size_t expected)
{
  uint64_t now;
  ftun_status_t status = ftun_monotonic_now(&now);
  if (status != FTUN_OK) return status;
  if (now > UINT64_MAX - FTUN_PROXY_RUNTIME_WORKER_WAIT_MS) {
    return FTUN_E_LIMIT;
  }
  return ftun_proxy_runtime_wait_worker_until(engine, worker, expected,
                                        now + FTUN_PROXY_RUNTIME_WORKER_WAIT_MS);
}

ftun_status_t ftun_proxy_runtime_fakeip_prepare(ftun_proxy_runtime_t *engine,
                                                 const ftun_config_t *config)
{
  ftun_fakeip_service_options_t service_options;
  ftun_fakeip_store_options_t store_options;
  ftun_fakeip_snapshot_t *snapshot = NULL;
  ftun_fakeip_store_info_t store_info;
  ftun_operation_t *operation = NULL;
  uint32_t first;
  uint32_t end;
  uint32_t reserve_end;
  size_t maximum;
  size_t path_length;
  size_t expected;
  ftun_status_t status;
  if ((config->plan->prepare & FTUN_PLAN_FAKE_IP) == 0u) return FTUN_OK;
  status = ftun_proxy_runtime_fakeip_range(config->dns.fake_ip.range, &first, &end);
  if (status != FTUN_OK) return status;
  maximum = (size_t)((uint64_t)end - (uint64_t)first);
  if (maximum == 0u) return FTUN_E_INVALID;
  memset(&service_options, 0, sizeof(service_options));
  service_options.budget = engine->budget;
  service_options.max_entries = maximum;
  if (config->dns.fake_ip.persist) {
    if (config->base.cache_file == NULL) return FTUN_E_INVALID;
    path_length = strlen(config->base.cache_file);
    if (path_length > SIZE_MAX - sizeof(".fakeip")) return FTUN_E_LIMIT;
    status = ftun_budget_reserve(engine->budget, path_length + sizeof(".fakeip"),
      &engine->fakeip_directory_reservation);
    if (status != FTUN_OK) return status;
    engine->fakeip_directory = (char *)malloc(path_length + sizeof(".fakeip"));
    if (engine->fakeip_directory == NULL) {
      (void)ftun_reservation_release(&engine->fakeip_directory_reservation);
      return FTUN_E_LIMIT;
    }
    memcpy(engine->fakeip_directory, config->base.cache_file, path_length);
    memcpy(engine->fakeip_directory + path_length, ".fakeip",
           sizeof(".fakeip"));
    memset(&store_options, 0, sizeof(store_options));
    store_options.directory = engine->fakeip_directory;
    store_options.budget = engine->budget;
    store_options.worker = engine->fakeip_worker;
    store_options.completion = ftun_proxy_runtime_fakeip_store_completed;
    store_options.user = engine;
    status = ftun_fakeip_store_open(&store_options, &engine->fakeip_store);
    if (status == FTUN_OK) {
      status = ftun_fakeip_snapshot_load(engine->fakeip_store, maximum,
                                         &snapshot);
    }
    if (status == FTUN_OK) {
      status = ftun_fakeip_store_get_info(engine->fakeip_store, &store_info);
    }
    if (status == FTUN_OK &&
        (store_info.identity.first_address != first ||
         store_info.identity.end_address_exclusive != end)) {
      status = FTUN_E_STATE_CORRUPT;
    }
    service_options.store = engine->fakeip_store;
    service_options.snapshot = snapshot;
  } else {
    service_options.first_address = first;
    service_options.end_address_exclusive = end;
  }
  if (status == FTUN_OK) {
    status = ftun_fakeip_service_create(&service_options, &engine->fakeip);
  }
  (void)ftun_fakeip_snapshot_destroy(&snapshot);
  if (status != FTUN_OK) return status;
  if (engine->fakeip_store == NULL || store_info.reserved_end >= end) {
    return FTUN_OK;
  }
  reserve_end = store_info.reserved_end;
  if (reserve_end < first) return FTUN_E_STATE_CORRUPT;
  if ((uint64_t)reserve_end + FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_BATCH <
      (uint64_t)end) {
    reserve_end += FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_BATCH;
  }
  else reserve_end = end;
  expected = engine->fakeip_store_completions + 1u;
  engine->fakeip_store_status = FTUN_E_AGAIN;
  status = ftun_fakeip_store_reserve(engine->fakeip_store, reserve_end,
                                     &operation);
  if (status == FTUN_OK) engine->fakeip_reserve_operation = operation;
  if (status == FTUN_OK) status = ftun_proxy_runtime_wait_worker(
    engine, engine->fakeip_worker, expected);
  return status;
}

ftun_status_t ftun_proxy_runtime_fakeip_reserve_runtime(
  ftun_proxy_runtime_t *engine)
{
  ftun_fakeip_service_info_t service;
  ftun_fakeip_store_info_t store;
  ftun_operation_t *operation = NULL;
  uint32_t reserve_end;
  ftun_status_t status;
  if (engine == NULL || engine->fakeip_store == NULL ||
      engine->fakeip == NULL || engine->fakeip_reserve_operation != NULL) {
    return FTUN_OK;
  }
  status = ftun_fakeip_store_get_info(engine->fakeip_store, &store);
  if (status != FTUN_OK) return status;
  if (store.pending || store.halted) return FTUN_OK;
  status = ftun_fakeip_service_get_info(engine->fakeip, &service);
  if (status != FTUN_OK) return status;
  if (service.next_address > store.reserved_end ||
      store.reserved_end > service.end_address_exclusive) {
    return FTUN_E_STATE_CORRUPT;
  }
  if (store.reserved_end >= service.end_address_exclusive ||
      store.reserved_end - service.next_address >
        FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_LOW_WATER) {
    return FTUN_OK;
  }
  reserve_end = store.reserved_end;
  if ((uint64_t)reserve_end + FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_BATCH <
      (uint64_t)service.end_address_exclusive) {
    reserve_end += FTUN_PROXY_RUNTIME_FAKEIP_RESERVE_BATCH;
  } else {
    reserve_end = service.end_address_exclusive;
  }
  engine->fakeip_store_status = FTUN_E_AGAIN;
  status = ftun_fakeip_store_reserve(engine->fakeip_store, reserve_end,
                                     &operation);
  if (status == FTUN_OK) {
    engine->fakeip_reserve_operation = operation;
    engine->fakeip_reserve_warning = false;
    return FTUN_OK;
  }
  if (status != FTUN_E_AGAIN && !engine->fakeip_reserve_warning) {
    engine->fakeip_reserve_warning = true;
    ftun_proxy_runtime_background_log(engine, status,
      FTUN_DIAGNOSTIC_FAKEIP_SCHEDULE, "persistent FakeIP reservation could not be scheduled; "
      "existing mappings remain readable");
  }
  return FTUN_OK;
}
#endif

/* 记下监听地址与名字；不创建 socket。 */
ftun_status_t ftun_proxy_runtime_config_outbound_id(
  const ftun_config_t *config, const char *name, uint32_t *out)
{
  size_t index;
  if (config == NULL || name == NULL || out == NULL) return FTUN_E_INVALID;
  if (strcmp(name, "DIRECT") == 0) {
    *out = FTUN_OUTBOUND_ID_DIRECT;
    return FTUN_OK;
  }
  if (strcmp(name, "REJECT") == 0) {
    *out = FTUN_OUTBOUND_ID_REJECT;
    return FTUN_OK;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    if (strcmp(name, config->outbounds[index].name) == 0) {
      if (index > UINT32_MAX - FTUN_OUTBOUND_ID_NAMED_BASE) {
        return FTUN_E_LIMIT;
      }
      *out = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
      return FTUN_OK;
    }
  }
  return FTUN_E_REJECTED;
}

int ftun_proxy_runtime_string_equal(const char *left, const char *right)
{
  if (left == NULL || right == NULL) return left == right;
  return strcmp(left, right) == 0;
}

int ftun_proxy_runtime_string_list_equal(
  const ftun_config_string_list_t *left,
  const ftun_config_string_list_t *right)
{
  size_t index;
  if (left->count != right->count) return 0;
  for (index = 0u; index < left->count; index++) {
    if (!ftun_proxy_runtime_string_equal(left->items[index], right->items[index])) {
      return 0;
    }
  }
  return 1;
}

int ftun_proxy_runtime_health_config_equal(const ftun_config_t *left,
                                           const ftun_config_t *right)
{
  size_t index;
  if (left == NULL || right == NULL || left->outbound_count !=
      right->outbound_count || left->plan == NULL || right->plan == NULL) {
    return 0;
  }
  for (index = 0u; index < left->outbound_count; index++) {
    const ftun_config_outbound_t *a = &left->outbounds[index];
    const ftun_config_outbound_t *b = &right->outbounds[index];
    if (a->kind != b->kind || a->udp != b->udp ||
        a->tolerance_ms != b->tolerance_ms || a->lazy != b->lazy ||
        a->expected_status != b->expected_status ||
        !ftun_proxy_runtime_string_equal(a->name, b->name) ||
        !ftun_proxy_runtime_string_equal(a->dns_server, b->dns_server) ||
        !ftun_proxy_runtime_string_equal(a->server, b->server) ||
        !ftun_proxy_runtime_string_equal(a->username, b->username) ||
        !ftun_proxy_runtime_string_equal(a->password, b->password) ||
        !ftun_proxy_runtime_string_list_equal(&a->members, &b->members) ||
        !ftun_proxy_runtime_string_equal(a->default_member, b->default_member) ||
        !ftun_proxy_runtime_string_equal(a->url, b->url) ||
        !ftun_proxy_runtime_string_equal(a->interval, b->interval) ||
        !ftun_proxy_runtime_string_equal(a->timeout, b->timeout) ||
        ((left->plan->outbound_states[index] & FTUN_PLAN_ITEM_REACHABLE) !=
         (right->plan->outbound_states[index] & FTUN_PLAN_ITEM_REACHABLE))) {
      return 0;
    }
  }
  return 1;
}

ftun_status_t ftun_proxy_runtime_prepare_inbound_ids(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config)
{
  size_t listener;
  if (engine == NULL || config == NULL) return FTUN_E_INVALID;
  memset(engine->pending_listener_ids, 0,
         sizeof(engine->pending_listener_ids));
#if defined(FTUN_HAVE_MODULE_TUN)
  engine->pending_tun_inbound_id = 0u;
#endif
  for (listener = 0u; listener < engine->listener_count; listener++) {
    size_t index;
    for (index = 0u; index < config->inbound_count; index++) {
      if (strcmp(engine->listeners[listener].name,
                 config->inbounds[index].name) == 0) break;
    }
    if (index == config->inbound_count || index >= UINT32_MAX) {
      return FTUN_E_RESTART_REQUIRED;
    }
    engine->pending_listener_ids[listener] = (uint32_t)index + 1u;
  }
#if defined(FTUN_HAVE_MODULE_TUN)
  if (engine->has_tun) {
    size_t index;
    for (index = 0u; index < config->inbound_count; index++) {
      if (strcmp(engine->tun_listener.name, config->inbounds[index].name) == 0) {
        break;
      }
    }
    if (index == config->inbound_count || index >= UINT32_MAX) {
      return FTUN_E_RESTART_REQUIRED;
    }
    engine->pending_tun_inbound_id = (uint32_t)index + 1u;
  }
#endif
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_health_prepare(
  ftun_proxy_runtime_t *engine, const ftun_config_t *config, uint64_t generation,
  ftun_proxy_runtime_health_group_t **out_groups, size_t *out_group_count,
  ftun_proxy_runtime_health_slot_t **out_slots, size_t *out_slot_count,
  ftun_reservation_t **out_reservation)
{
  ftun_proxy_runtime_health_group_t *groups = NULL;
  ftun_proxy_runtime_health_slot_t *slots = NULL;
  ftun_reservation_t *reservation = NULL;
  size_t group_count = 0u;
  size_t slot_count = 0u;
  size_t group_cursor = 0u;
  size_t slot_cursor = 0u;
  size_t bytes;
  size_t index;
  uint64_t now_ms;
  ftun_status_t status;
  if (out_groups != NULL) *out_groups = NULL;
  if (out_group_count != NULL) *out_group_count = 0u;
  if (out_slots != NULL) *out_slots = NULL;
  if (out_slot_count != NULL) *out_slot_count = 0u;
  if (out_reservation != NULL) *out_reservation = NULL;
  if (engine == NULL || config == NULL || generation == 0u ||
      out_groups == NULL || out_group_count == NULL || out_slots == NULL ||
      out_slot_count == NULL || out_reservation == NULL) {
    return FTUN_E_INVALID;
  }
  for (index = 0u; index < config->outbound_count; index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    if (item->kind != FTUN_CONFIG_OUTBOUND_URL_TEST ||
        (config->plan->outbound_states[index] &
         FTUN_PLAN_ITEM_REACHABLE) == 0u) continue;
    if (group_count == SIZE_MAX || item->members.count > SIZE_MAX - slot_count) {
      return FTUN_E_LIMIT;
    }
    group_count++;
    slot_count += item->members.count;
  }
  if (group_count == 0u) return FTUN_OK;
  if (group_count > SIZE_MAX / sizeof(*groups) ||
      slot_count > SIZE_MAX / sizeof(*slots) ||
      group_count * sizeof(*groups) >
        SIZE_MAX - slot_count * sizeof(*slots)) return FTUN_E_LIMIT;
  bytes = group_count * sizeof(*groups) + slot_count * sizeof(*slots);
  status = ftun_budget_reserve(engine->budget, bytes, &reservation);
  if (status != FTUN_OK) return status;
  groups = (ftun_proxy_runtime_health_group_t *)calloc(group_count, sizeof(*groups));
  slots = (ftun_proxy_runtime_health_slot_t *)calloc(slot_count, sizeof(*slots));
  if (groups == NULL || slots == NULL) {
    free(groups);
    free(slots);
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_monotonic_now(&now_ms);
  for (index = 0u; status == FTUN_OK && index < config->outbound_count;
       index++) {
    const ftun_config_outbound_t *item = &config->outbounds[index];
    ftun_proxy_runtime_health_group_t *group;
    size_t member;
    if (item->kind != FTUN_CONFIG_OUTBOUND_URL_TEST ||
        (config->plan->outbound_states[index] &
         FTUN_PLAN_ITEM_REACHABLE) == 0u) continue;
    group = &groups[group_cursor];
    group->outbound_index = index;
    group->slot_start = slot_cursor;
    group->slot_count = item->members.count;
    group->group_id = (uint32_t)index + FTUN_OUTBOUND_ID_NAMED_BASE;
    group->lazy = item->lazy;
    group->consumed = !item->lazy;
    group->selected_since_ms = now_ms;
    if (!ftun_proxy_runtime_duration_ms(item->interval, &group->interval_ms) ||
        !ftun_proxy_runtime_duration_ms(item->timeout, &group->timeout_ms)) {
      status = FTUN_E_INVALID;
      break;
    }
    for (member = 0u; member < item->members.count; member++, slot_cursor++) {
      ftun_proxy_runtime_health_slot_t *slot = &slots[slot_cursor];
      slot->engine = engine;
      slot->group_index = group_cursor;
      slot->generation = generation;
      slot->schedule.consumers = group->consumed ? 1u : 0u;
      slot->schedule.next_due_ms = group->consumed ? now_ms : 0u;
      status = ftun_proxy_runtime_config_outbound_id(config,
        item->members.items[member], &slot->member_id);
      if (status != FTUN_OK) break;
      slot->sample.member_id = slot->member_id;
      slot->sample.tcp_only = true;
    }
    group_cursor++;
  }
  if (status != FTUN_OK) {
    free(groups);
    free(slots);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  *out_groups = groups;
  *out_group_count = group_count;
  *out_slots = slots;
  *out_slot_count = slot_count;
  *out_reservation = reservation;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_health_release(
  ftun_proxy_runtime_health_group_t **groups,
  ftun_proxy_runtime_health_slot_t **slots,
  size_t slot_count, ftun_reservation_t **reservation)
{
  size_t index;
  if (groups == NULL || slots == NULL || reservation == NULL) {
    return FTUN_E_INVALID;
  }
  if (*slots != NULL) {
    for (index = 0u; index < slot_count; index++) {
      if ((*slots)[index].operation != NULL) return FTUN_E_AGAIN;
    }
  }
  free(*groups);
  free(*slots);
  *groups = NULL;
  *slots = NULL;
  return ftun_reservation_release(reservation);
}

void ftun_proxy_runtime_health_consume(ftun_proxy_runtime_t *engine,
                                       uint32_t group_id)
{
  size_t index;
  uint64_t now_ms;
  if (engine == NULL || ftun_monotonic_now(&now_ms) != FTUN_OK) return;
  for (index = 0u; index < engine->health_group_count; index++) {
    ftun_proxy_runtime_health_group_t *group = &engine->health_groups[index];
    size_t member;
    if (group->group_id != group_id || group->consumed) continue;
    engine->health_deadline_valid = false;
    group->consumed = true;
    for (member = 0u; member < group->slot_count; member++) {
      ftun_proxy_runtime_health_slot_t *slot =
        &engine->health_slots[group->slot_start + member];
      slot->schedule.consumers = 1u;
      slot->schedule.next_due_ms = now_ms;
    }
    return;
  }
}

ftun_status_t ftun_proxy_runtime_health_publish(
  ftun_proxy_runtime_health_slot_t *completed, uint64_t now_ms)
{
  ftun_proxy_runtime_t *engine = completed->engine;
  ftun_proxy_runtime_health_group_t *group;
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  const ftun_config_outbound_t *item;
  ftun_health_sample_t *samples = NULL;
  uint32_t *members = NULL;
  ftun_reservation_t *scratch_reservation = NULL;
  ftun_health_snapshot_t snapshot;
  ftun_group_spec_t spec;
  ftun_group_choice_t choice;
  ftun_health_sample_t selected_sample;
  ftun_string_t dns_server;
  uint32_t previous = 0u;
  bool is_group = false;
  bool degraded = false;
  size_t index;
  ftun_status_t status;
  if (completed->group_index >= engine->health_group_count) {
    return FTUN_E_STATE_CORRUPT;
  }
  group = &engine->health_groups[completed->group_index];
  status = ftun_runtime_active_acquire(engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  if (status == FTUN_OK && (completed->generation != engine->generation ||
      group->outbound_index >= config->outbound_count)) status = FTUN_E_STALE;
  if (status != FTUN_OK) goto done;
  item = &config->outbounds[group->outbound_index];
  if (group->slot_count > SIZE_MAX / (sizeof(*members) + sizeof(*samples))) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  status = ftun_budget_reserve(engine->budget,
    group->slot_count * (sizeof(*members) + sizeof(*samples)), &scratch_reservation);
  if (status != FTUN_OK) goto done;
  members = (uint32_t *)calloc(group->slot_count, sizeof(*members));
  samples = (ftun_health_sample_t *)calloc(group->slot_count,
                                            sizeof(*samples));
  if (members == NULL || samples == NULL) {
    status = FTUN_E_LIMIT;
    goto done;
  }
  for (index = 0u; index < group->slot_count; index++) {
    ftun_proxy_runtime_health_slot_t *slot =
      &engine->health_slots[group->slot_start + index];
    members[index] = slot->member_id;
    samples[index] = slot->sample;
  }
  status = ftun_runtime_group_selected(runtime, group->group_id, &previous,
                                        &is_group, &degraded, &dns_server);
  (void)degraded;
  (void)dns_server;
  if (status == FTUN_OK && !is_group) status = FTUN_E_STATE_CORRUPT;
  memset(&snapshot, 0, sizeof(snapshot));
  snapshot.generation = engine->generation;
  snapshot.samples = samples;
  snapshot.sample_count = group->slot_count;
  memset(&spec, 0, sizeof(spec));
  spec.generation = engine->generation;
  spec.group_id = group->group_id;
  spec.members = members;
  spec.member_count = group->slot_count;
  spec.previous_member_id = previous;
  spec.previous_since_ms = group->selected_since_ms;
  spec.now_ms = now_ms;
  spec.sample_max_age_ms = group->interval_ms > UINT64_MAX / 2u
    ? UINT64_MAX : group->interval_ms * 2u;
  spec.minimum_hold_ms = group->interval_ms;
  spec.tolerance_ms = item->tolerance_ms;
  status = ftun_proxy_runtime_config_outbound_id(config, item->default_member,
                                           &spec.default_member_id);
  if (status == FTUN_OK) status = ftun_url_test_choose(&spec, &snapshot,
                                                       &choice);
  memset(&selected_sample, 0, sizeof(selected_sample));
  if (status == FTUN_OK) {
    selected_sample.member_id = choice.leaf_id;
    selected_sample.tcp_only = true;
    for (index = 0u; index < group->slot_count; index++) {
      if (samples[index].member_id == choice.leaf_id) {
        selected_sample = samples[index];
        break;
      }
    }
    status = ftun_runtime_group_publish_health(engine->core,
      group->group_id, &choice, &selected_sample);
    if (status == FTUN_OK && choice.leaf_id != previous) {
      group->selected_since_ms = now_ms;
    }
  }
done:
  free(samples);
  free(members);
  (void)ftun_reservation_release(&scratch_reservation);
  (void)ftun_runtime_release(&runtime);
  return status;
}

void ftun_proxy_runtime_health_completed(ftun_operation_t *operation,
                                         ftun_error_t error,
                                         ftun_bytes_t result, void *user)
{
  ftun_proxy_runtime_health_slot_t *slot =
    (ftun_proxy_runtime_health_slot_t *)user;
  ftun_proxy_runtime_t *engine;
  ftun_proxy_runtime_health_group_t *group;
  const ftun_proxy_runtime_http_result_t *response = NULL;
  const ftun_config_t *config = NULL;
  ftun_runtime_t *runtime = NULL;
  uint64_t now_ms = 0u;
  uint64_t maximum_backoff;
  bool success = false;
  ftun_status_t status = error.status;
  if (slot == NULL || slot->operation != operation || slot->engine == NULL) {
    return;
  }
  engine = slot->engine;
  slot->operation = NULL;
  engine->health_deadline_valid = false;
  if (slot->group_index >= engine->health_group_count || engine->stopped ||
      slot->generation != engine->generation) return;
  group = &engine->health_groups[slot->group_index];
  (void)ftun_monotonic_now(&now_ms);
  if (status == FTUN_OK && result.data != NULL &&
      result.length >= sizeof(*response)) {
    response = (const ftun_proxy_runtime_http_result_t *)result.data;
    if (response->etag_length <= FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES &&
        response->body_length <= SIZE_MAX &&
        response->etag_length <= result.length - sizeof(*response) &&
        (size_t)response->body_length == result.length - sizeof(*response) -
                                         response->etag_length) {
      status = ftun_runtime_active_acquire(engine->core, &runtime);
      if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
      if (status == FTUN_OK && group->outbound_index < config->outbound_count) {
        const ftun_config_outbound_t *item =
          &config->outbounds[group->outbound_index];
        success = response->status == item->expected_status &&
          (item->url == NULL || strncmp(item->url, "https://", 8u) != 0 ||
           response->tls_verified != 0u);
      }
    } else {
      status = FTUN_E_PROTOCOL;
    }
  }
  (void)ftun_runtime_release(&runtime);
  memset(&slot->sample, 0, sizeof(slot->sample));
  slot->sample.member_id = slot->member_id;
  slot->sample.tcp_only = true;
  slot->sample.success = status == FTUN_OK && success;
  slot->sample.observed_ms = now_ms;
  if (now_ms >= slot->started_ms) {
    uint64_t latency = now_ms - slot->started_ms;
    slot->sample.latency_ms = latency > UINT32_MAX
      ? UINT32_MAX : (uint32_t)latency;
  }
  maximum_backoff = group->interval_ms > UINT64_MAX / 16u
    ? UINT64_MAX : group->interval_ms * 16u;
  (void)ftun_health_schedule(&slot->schedule, now_ms, group->interval_ms,
                              maximum_backoff,
                              slot->member_id ^ (uint32_t)now_ms,
                              slot->sample.success);
  status = ftun_proxy_runtime_health_publish(slot, now_ms);
  if (status != FTUN_OK && status != FTUN_E_STALE) {
#if defined(FTUN_HAVE_MODULE_FRS)
    ftun_proxy_runtime_background_log(engine, status,
                               FTUN_DIAGNOSTIC_HEALTH_PUBLISH, "URL-Test result publish failed");
#endif
  }
}

/* 仅在调度元数据变化时重算；休眠组和在途探测不制造期限。 */
void ftun_proxy_runtime_health_deadline_refresh(ftun_proxy_runtime_t *engine)
{
  size_t index;
  if (engine->health_deadline_valid &&
      engine->health_deadline_generation == engine->generation) return;
  engine->health_deadline_present = false;
  engine->health_deadline_ms = 0u;
  for (index = 0u; index < engine->health_slot_count; index++) {
    const ftun_proxy_runtime_health_slot_t *slot = &engine->health_slots[index];
    const ftun_proxy_runtime_health_group_t *group =
      &engine->health_groups[slot->group_index];
    if (engine->health_scan_work != SIZE_MAX) engine->health_scan_work++;
    if (group->consumed && slot->operation == NULL &&
        (!engine->health_deadline_present ||
         slot->schedule.next_due_ms < engine->health_deadline_ms)) {
      engine->health_deadline_ms = slot->schedule.next_due_ms;
      engine->health_deadline_present = true;
    }
  }
  engine->health_deadline_generation = engine->generation;
  engine->health_deadline_valid = true;
}

ftun_status_t ftun_proxy_runtime_health_run(ftun_proxy_runtime_t *engine,
                                             size_t quota,
                                             size_t *out_work)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  size_t inspected = 0u;
  size_t work = 0u;
  ftun_status_t status;
  if (out_work != NULL) *out_work = 0u;
  if (engine == NULL || quota == 0u || out_work == NULL) {
    return FTUN_E_INVALID;
  }
  /* 非复用 Health 的 prepare 已确认没有在途操作；持久化窗口内冻结新探测，
   * 保证 commit 只交换已准备对象，不会在释放旧数组时返回 AGAIN。 */
  if (engine->reload_prepared && !engine->pending_health_reuse) return FTUN_OK;
  if (engine->health_slot_count == 0u) return FTUN_OK;
  ftun_proxy_runtime_health_deadline_refresh(engine);
  if (!engine->health_deadline_present ||
      engine->now_ms < engine->health_deadline_ms) return FTUN_OK;
  status = ftun_runtime_active_acquire(engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  while (status == FTUN_OK && inspected < engine->health_slot_count &&
         work < quota) {
    size_t index = engine->health_cursor;
    ftun_proxy_runtime_health_slot_t *slot = &engine->health_slots[index];
    ftun_proxy_runtime_health_group_t *group =
      &engine->health_groups[slot->group_index];
    const ftun_config_outbound_t *item;
    ftun_http_fetch_spec_t spec;
    engine->health_cursor = (index + 1u) % engine->health_slot_count;
    inspected++;
    if (engine->health_scan_work != SIZE_MAX) engine->health_scan_work++;
    if (!group->consumed || slot->operation != NULL ||
        engine->now_ms < slot->schedule.next_due_ms) continue;
    work++;
    engine->health_deadline_valid = false;
    if (group->outbound_index >= config->outbound_count ||
        index - group->slot_start >= group->slot_count) {
      status = FTUN_E_STATE_CORRUPT;
      break;
    }
    item = &config->outbounds[group->outbound_index];
    memset(&spec, 0, sizeof(spec));
    spec.budget = engine->budget;
    spec.url.data = item->url;
    spec.url.length = strlen(item->url);
    spec.maximum_bytes = 64u * 1024u;
    spec.purpose = FTUN_DIAL_PURPOSE_PROBE;
    spec.socket_mark = engine->socket_mark;
    if (group->timeout_ms > UINT64_MAX - engine->now_ms) {
      status = FTUN_E_LIMIT;
      break;
    }
    spec.deadline_ms = engine->now_ms + group->timeout_ms;
    status = ftun_http_fetch_resolver(config, runtime,
      (ftun_string_t){NULL, 0u}, &spec);
    if (status == FTUN_OK) {
      status = ftun_http_fetch_route(config, runtime,
        item->members.items[index - group->slot_start], &spec);
    }
    if (status == FTUN_OK) {
      slot->started_ms = engine->now_ms;
      slot->generation = engine->generation;
      status = ftun_proxy_runtime_http_submit(engine, &spec, false, NULL,
        ftun_proxy_runtime_health_completed, slot, &slot->operation);
    }
    if (status != FTUN_OK) {
      uint64_t maximum_backoff = group->interval_ms > UINT64_MAX / 16u
        ? UINT64_MAX : group->interval_ms * 16u;
      (void)ftun_health_schedule(&slot->schedule, engine->now_ms,
        group->interval_ms, maximum_backoff,
        slot->member_id ^ (uint32_t)engine->now_ms, false);
      status = FTUN_OK;
    }
  }
  (void)ftun_runtime_release(&runtime);
  *out_work = work;
  return status;
}

void ftun_proxy_runtime_background_log(ftun_proxy_runtime_t *engine,
                                       ftun_status_t status,
                                       ftun_diagnostic_kind_t kind, const char *message)
{
  ftun_error_t error = {0};
  uint64_t generation = 0u;
  if (engine == NULL || message == NULL) return;
  /* 后台完成已派发至 owner，不在 Worker 上读当前代次。 */
  (void)ftun_core_context_generation(engine->core, &generation);
  error.status = status;
  error.stage = FTUN_STAGE_CONTROL;
  (void)ftun_diagnostic_report(engine->core, kind, generation, error, message);
}

/* 规则引用了尚未就绪的 FRS 集合而拒绝新连接：每个 NOT_READY 期间只记一次，
 * 之后的拒绝不再重复，避免下载失败期间刷屏。 */
void ftun_proxy_runtime_note_denied(ftun_proxy_runtime_t *engine,
                                           const ftun_route_result_t *route)
{
  if (!route->frs_not_ready || engine->frs_not_ready_logged) return;
  engine->frs_not_ready_logged = true;
  ftun_proxy_runtime_background_log(engine, FTUN_E_REJECTED,
    FTUN_DIAGNOSTIC_FRS_UPDATE,
    "connection rejected: frs-not-ready (rule file not downloaded yet)");
}

#if defined(FTUN_HAVE_MODULE_FRS)
ftun_status_t ftun_proxy_runtime_copy_etag(ftun_budget_t *budget,
  const uint8_t *value, size_t length, char **out,
  ftun_reservation_t **out_reservation)
{
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (out_reservation != NULL) *out_reservation = NULL;
  if (budget == NULL || out == NULL || out_reservation == NULL ||
      (length != 0u && value == NULL)) return FTUN_E_INVALID;
  if (length > FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES) return FTUN_E_LIMIT;
  if (length == 0u) return FTUN_OK;
  status = ftun_budget_reserve(budget, length + 1u, out_reservation);
  if (status != FTUN_OK) return status;
  *out = (char *)malloc(length + 1u);
  if (*out == NULL) {
    (void)ftun_reservation_release(out_reservation);
    return FTUN_E_LIMIT;
  }
  memcpy(*out, value, length);
  (*out)[length] = '\0';
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_replace_etag(ftun_proxy_runtime_t *engine,
                                               const uint8_t *value,
                                               size_t length)
{
  char *copy = NULL;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (engine == NULL || (length != 0u && value == NULL)) {
    return FTUN_E_INVALID;
  }
  status = ftun_proxy_runtime_copy_etag(engine->budget, value, length, &copy,
    &reservation);
  if (status != FTUN_OK) return status;
  free(engine->frs_etag);
  (void)ftun_reservation_release(&engine->frs_etag_reservation);
  engine->frs_etag = copy;
  engine->frs_etag_reservation = reservation;
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_frs_publish_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size)
{
  const ftun_proxy_runtime_frs_publish_work_t *work;
  ftun_proxy_runtime_frs_publish_result_t output;
  ftun_proxy_runtime_file_publish_t publish;
  const char *path;
  const uint8_t *body;
  size_t expected;
  ftun_status_t status;
  if (out_result_size != NULL) *out_result_size = 0u;
  if (input.data == NULL || input.length < sizeof(*work) || result == NULL ||
      result_capacity < sizeof(output) || out_result_size == NULL) {
    return FTUN_E_INVALID;
  }
  work = (const ftun_proxy_runtime_frs_publish_work_t *)input.data;
  if (work->magic != FTUN_PROXY_RUNTIME_FRS_PUBLISH_MAGIC || work->budget == 0u ||
      work->path_length == 0u || work->body_length > SIZE_MAX) {
    return FTUN_E_INVALID;
  }
  expected = sizeof(*work);
  if ((size_t)work->path_length > SIZE_MAX - expected - 1u) {
    return FTUN_E_LIMIT;
  }
  expected += (size_t)work->path_length + 1u;
  if ((size_t)work->body_length > SIZE_MAX - expected) return FTUN_E_LIMIT;
  expected += (size_t)work->body_length;
  if (expected != input.length) return FTUN_E_INVALID;
  path = (const char *)input.data + sizeof(*work);
  if (path[work->path_length] != '\0' ||
      memchr(path, '\0', work->path_length) != NULL) {
    return FTUN_E_INVALID;
  }
  body = input.data + sizeof(*work) + work->path_length + 1u;
  memset(&publish, 0, sizeof(publish));
  status = ftun_file_write_atomic_budget((ftun_budget_t *)work->budget, path,
    (ftun_bytes_t){body, (size_t)work->body_length}, 0644u,
    ftun_proxy_runtime_file_stage, &publish);
  output.status = (int32_t)status;
  output.reached = (uint32_t)publish.reached;
  memcpy(result, &output, sizeof(output));
  *out_result_size = sizeof(output);
  /* 发布失败作为数据返回 owner。这里返回成功以保留已到达阶段，使
   * “替换成功、同步失败”表现为耐久性警告，而不是误判为没有替换。 */
  return FTUN_OK;
}

ftun_status_t ftun_proxy_runtime_frs_publish_submit(
  ftun_proxy_runtime_t *engine, const char *path, ftun_bytes_t body,
  ftun_worker_completion_fn completion, ftun_operation_t **out)
{
  ftun_proxy_runtime_frs_publish_work_t *work;
  ftun_worker_job_t job;
  uint8_t *input;
  size_t path_length;
  size_t input_length;
  ftun_reservation_t *input_reservation = NULL;
  ftun_status_t release_status;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (engine == NULL || path == NULL || path[0] == '\0' ||
      (body.length != 0u && body.data == NULL) || completion == NULL ||
      out == NULL) return FTUN_E_INVALID;
  path_length = strlen(path);
  if (path_length > UINT32_MAX || body.length > UINT64_MAX ||
      path_length > SIZE_MAX - sizeof(*work) - 1u ||
      body.length > SIZE_MAX - sizeof(*work) - path_length - 1u) {
    return FTUN_E_LIMIT;
  }
  input_length = sizeof(*work) + path_length + 1u + body.length;
  status = ftun_budget_reserve(engine->budget, input_length,
                               &input_reservation);
  if (status != FTUN_OK) return status;
  input = (uint8_t *)malloc(input_length);
  if (input == NULL) {
    (void)ftun_reservation_release(&input_reservation);
    return FTUN_E_LIMIT;
  }
  work = (ftun_proxy_runtime_frs_publish_work_t *)input;
  memset(work, 0, sizeof(*work));
  work->magic = FTUN_PROXY_RUNTIME_FRS_PUBLISH_MAGIC;
  work->budget = (uintptr_t)engine->budget;
  work->path_length = (uint32_t)path_length;
  work->body_length = body.length;
  memcpy(input + sizeof(*work), path, path_length + 1u);
  if (body.length != 0u) {
    memcpy(input + sizeof(*work) + path_length + 1u, body.data, body.length);
  }
  memset(&job, 0, sizeof(job));
  job.execute = ftun_proxy_runtime_frs_publish_execute;
  job.input.data = input;
  job.input.length = input_length;
  job.result_capacity = sizeof(ftun_proxy_runtime_frs_publish_result_t);
  status = ftun_worker_submit(engine->maintenance_worker, &job, completion,
                              engine, out);
  free(input);
  release_status = ftun_reservation_release(&input_reservation);
  if (status != FTUN_OK && release_status != FTUN_OK) {
    status = FTUN_E_STATE_CORRUPT;
  }
  return status;
}

void ftun_proxy_runtime_frs_schedule_next(ftun_proxy_runtime_t *engine,
                                           uint64_t now_ms)
{
  if (engine->frs_not_ready && now_ms != 0u) {
    engine->frs_retry_ms = engine->frs_retry_ms == 0u
      ? FTUN_PROXY_RUNTIME_FRS_RETRY_INITIAL_MS
      : (engine->frs_retry_ms >= FTUN_PROXY_RUNTIME_FRS_RETRY_MAXIMUM_MS / 2u
           ? FTUN_PROXY_RUNTIME_FRS_RETRY_MAXIMUM_MS : engine->frs_retry_ms * 2u);
    engine->frs_due_ms = now_ms + engine->frs_retry_ms;
    return;
  }
  if (now_ms != 0u && engine->frs_interval_ms <= UINT64_MAX - now_ms) {
    engine->frs_due_ms = now_ms + engine->frs_interval_ms;
  } else {
    engine->frs_due_ms = UINT64_MAX;
  }
}

/* 放弃尚未被 Runtime 提交消费的代次预留；已发布或从未预留时无操作。 */
void ftun_proxy_runtime_frs_release_generation(ftun_proxy_runtime_t *engine)
{
  if (engine->frs_reserved_generation == 0u) return;
  (void)ftun_core_context_generation_release(engine->core, engine,
                                             engine->frs_reserved_generation);
  engine->frs_reserved_generation = 0u;
}

void ftun_proxy_runtime_frs_publish_completed(ftun_operation_t *operation,
                                               ftun_error_t error,
                                               ftun_bytes_t result,
                                               void *user)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  const ftun_proxy_runtime_frs_publish_result_t *published = NULL;
  ftun_runtime_t *active = NULL;
  ftun_runtime_info_t info;
  uint64_t now_ms = 0u;
  ftun_status_t status = error.status;
  ftun_status_t durability_status = FTUN_OK;
  if (engine == NULL || engine->frs_operation != operation) return;
  engine->frs_operation = NULL;
  (void)ftun_monotonic_now(&now_ms);
  if (!engine->frs_enabled || engine->stopped ||
      engine->frs_candidate == NULL) {
    status = FTUN_E_CANCELLED;
  }
  if (status == FTUN_OK) {
    if (result.data == NULL || result.length != sizeof(*published)) {
      status = FTUN_E_PROTOCOL;
    } else {
      published = (const ftun_proxy_runtime_frs_publish_result_t *)result.data;
      status = (ftun_status_t)published->status;
      if (status != FTUN_OK &&
          published->reached >= (uint32_t)FTUN_FILE_STAGE_RENAMED) {
        durability_status = status;
        status = FTUN_OK;
      }
    }
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_active_acquire(engine->core, &active);
  }
  if (status == FTUN_OK) status = ftun_runtime_get_info(active, &info);
  if (status == FTUN_OK && (info.generation != engine->generation ||
      info.generation != engine->frs_operation_generation)) {
    status = FTUN_E_STALE;
  }
  (void)ftun_runtime_release(&active);
  if (status == FTUN_OK && engine->frs_group_record_capacity != 0u) {
    size_t count = 0u;
    size_t index;
    status = ftun_runtime_group_records(engine->core,
      engine->frs_group_records, engine->frs_group_record_capacity, &count);
    for (index = 0u; status == FTUN_OK && index < count; index++) {
      status = ftun_runtime_candidate_group_restore(engine->core,
        &engine->frs_group_records[index], true);
      if (status == FTUN_E_REJECTED || status == FTUN_E_STALE) {
        status = FTUN_OK;
      }
    }
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_stage_commit(engine->core, engine->frs_candidate,
      engine->frs_reserved_generation);
  }
  if (status == FTUN_OK) {
    status = ftun_proxy_runtime_reload_commit_owned(
      engine, engine->frs_reserved_generation, FTUN_PROXY_RELOAD_OWNER_FRS);
  }
  if (status == FTUN_OK) {
    free(engine->frs_etag);
    (void)ftun_reservation_release(&engine->frs_etag_reservation);
    engine->frs_etag = engine->frs_candidate_etag;
    engine->frs_etag_reservation = engine->frs_candidate_etag_reservation;
    engine->frs_candidate_etag = NULL;
    engine->frs_candidate_etag_reservation = NULL;
    /* 提交消费并发布本次预留的代次；失败时下方释放预留。 */
    status = ftun_runtime_commit_reserved(engine->core, &engine->frs_candidate,
                                          engine);
    if (status == FTUN_OK) {
      engine->frs_not_ready = false;
      engine->frs_not_ready_logged = false;
      engine->frs_retry_ms = 0u;
      ftun_lifecycle_event_t event = {0};
      event.kind = FTUN_LIFECYCLE_CONFIG_PUBLISHED;
      event.module = FTUN_BUILD_MODULE_FRS;
      event.generation = engine->frs_reserved_generation;
      event.status = FTUN_OK;
      event.reason = FTUN_LIFECYCLE_REASON_FRS_UPDATE;
      (void)ftun_lifecycle_emit(engine->core, &event);
      engine->frs_reserved_generation = 0u;
    }
  }
  if (engine->frs_candidate != NULL) {
    (void)ftun_runtime_abort(engine->core, &engine->frs_candidate);
  }
  ftun_proxy_runtime_frs_release_generation(engine);
  if (engine->reload_prepared &&
      engine->reload_owner == FTUN_PROXY_RELOAD_OWNER_FRS) {
    (void)ftun_proxy_runtime_reload_abort_owned(engine, FTUN_PROXY_RELOAD_OWNER_FRS);
  }
  free(engine->frs_candidate_etag);
  engine->frs_candidate_etag = NULL;
  (void)ftun_reservation_release(&engine->frs_candidate_etag_reservation);
  free(engine->frs_group_records);
  engine->frs_group_records = NULL;
  (void)ftun_reservation_release(&engine->frs_group_records_reservation);
  engine->frs_group_record_capacity = 0u;
  ftun_proxy_runtime_frs_schedule_next(engine, now_ms);
  if (status != FTUN_OK && status != FTUN_E_STALE &&
      status != FTUN_E_CANCELLED) {
    ftun_proxy_runtime_background_log(engine, status, FTUN_DIAGNOSTIC_FRS_UPDATE, "FRS update failed");
  } else if (status == FTUN_OK && durability_status != FTUN_OK) {
    ftun_proxy_runtime_background_log(engine, durability_status,
      FTUN_DIAGNOSTIC_FRS_PUBLISH, "FRS update applied but directory durability is uncertain");
  }
}

void ftun_proxy_runtime_frs_completed(ftun_operation_t *operation,
                                      ftun_error_t error,
                                      ftun_bytes_t result, void *user)
{
  ftun_proxy_runtime_t *engine = (ftun_proxy_runtime_t *)user;
  ftun_proxy_runtime_http_result_t *response = NULL;
  const uint8_t *etag = NULL;
  const uint8_t *body = NULL;
  ftun_runtime_t *baseline = NULL;
  ftun_runtime_t *candidate = NULL;
  ftun_runtime_t *prepared = NULL;
  const ftun_config_t *config = NULL;
  ftun_runtime_info_t info;
  ftun_runtime_group_record_t *records = NULL;
  char *candidate_etag = NULL;
  ftun_reservation_t *records_reservation = NULL;
  ftun_reservation_t *etag_reservation = NULL;
  size_t record_count = 0u;
  size_t index;
  uint64_t now_ms = 0u;
  ftun_status_t status = error.status;
  bool unchanged = false;
  bool publish_scheduled = false;
  if (engine == NULL || engine->frs_operation != operation) return;
  engine->frs_operation = NULL;
  (void)ftun_monotonic_now(&now_ms);
  if (!engine->frs_enabled || engine->stopped ||
      engine->frs_operation_generation != engine->generation) {
    return;
  }
  if (status == FTUN_OK) {
    if (result.data == NULL || result.length < sizeof(*response)) {
      status = FTUN_E_PROTOCOL;
    } else {
      response = (ftun_proxy_runtime_http_result_t *)(uintptr_t)result.data;
      if (response->etag_length > FTUN_PROXY_RUNTIME_HTTP_ETAG_BYTES ||
          response->body_length > SIZE_MAX ||
          response->etag_length > result.length - sizeof(*response) ||
          result.length != sizeof(*response) + response->etag_length ||
          (response->status == 200u && response->prepared_runtime == 0u) ||
          (response->status != 200u && response->prepared_runtime != 0u)) {
        status = FTUN_E_PROTOCOL;
      } else {
        ftun_bytes_t prepared_bytes;
        etag = result.data + sizeof(*response);
        if (response->prepared_runtime != 0u) {
          prepared = (ftun_runtime_t *)response->prepared_runtime;
          status = ftun_runtime_prepared_frs_bytes(prepared,
                                                    &prepared_bytes);
          if (status == FTUN_OK &&
              prepared_bytes.length != (size_t)response->body_length) {
            status = FTUN_E_PROTOCOL;
          }
          if (status == FTUN_OK) {
            body = prepared_bytes.data;
            response->prepared_runtime = 0u;
          } else {
            prepared = NULL;
          }
        } else if (response->body_length != 0u) {
          status = FTUN_E_PROTOCOL;
        }
      }
    }
  }
  if (status == FTUN_OK) {
    status = ftun_runtime_active_acquire(engine->core, &baseline);
  }
  if (status == FTUN_OK) status = ftun_runtime_get_info(baseline, &info);
  if (status == FTUN_OK && (info.generation != engine->generation ||
      info.generation != engine->frs_operation_generation)) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(baseline, &config);
  if (status == FTUN_OK && response->status == 304u) {
    if (engine->frs_etag == NULL) status = FTUN_E_PROTOCOL;
    else unchanged = true;
  } else if (status == FTUN_OK && response->status != 200u) {
    status = FTUN_E_PROTOCOL;
  }
  if (status == FTUN_OK && !unchanged) {
    ftun_frs_view_t *old_view = NULL;
    ftun_bytes_t old_bytes;
    if (ftun_runtime_frs_view(baseline, &old_view) == FTUN_OK &&
        ftun_frs_view_bytes(old_view, &old_bytes) == FTUN_OK &&
        old_bytes.length == (size_t)response->body_length &&
        memcmp(old_bytes.data, body, old_bytes.length) == 0) {
      unchanged = true;
    }
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_runtime_attach_prepared(engine->core, &prepared,
                                          &candidate);
  }
  if (status == FTUN_OK && !unchanged) {
    ftun_status_t records_status = ftun_runtime_group_records(
      engine->core, NULL, 0u, &record_count);
    if (records_status != FTUN_OK && records_status != FTUN_E_LIMIT) {
      status = records_status;
    }
    if (status == FTUN_OK && record_count != 0u) {
      if (record_count > SIZE_MAX / sizeof(*records)) status = FTUN_E_LIMIT;
      else status = ftun_budget_reserve(engine->budget,
        record_count * sizeof(*records), &records_reservation);
      if (status == FTUN_OK) {
        records = (ftun_runtime_group_record_t *)calloc(
          record_count, sizeof(*records));
        if (records == NULL) status = FTUN_E_LIMIT;
        else status = ftun_runtime_group_records(engine->core, records,
          record_count, &record_count);
      }
    }
    for (index = 0u; status == FTUN_OK && index < record_count; index++) {
      status = ftun_runtime_candidate_group_restore(engine->core,
                                                     &records[index], true);
    }
  }
  if (status == FTUN_OK && !unchanged) {
    /* FRS 更新也产生新运行配置代次，必须经 Core 上下文唯一预留。 */
    status = ftun_core_context_generation_reserve(engine->core, engine,
      &engine->frs_reserved_generation);
    if (status == FTUN_OK &&
        engine->frs_reserved_generation != info.generation + 1u) {
      status = FTUN_E_STALE;
    }
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_proxy_runtime_reload_prepare_owned(engine, config,
      engine->frs_reserved_generation, NULL, FTUN_PROXY_RELOAD_OWNER_FRS);
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_runtime_stage_commit(engine->core, candidate,
                                       engine->frs_reserved_generation);
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_proxy_runtime_copy_etag(engine->budget, etag,
      response->etag_length, &candidate_etag, &etag_reservation);
  }
  if (status == FTUN_OK && !unchanged) {
    status = ftun_proxy_runtime_frs_publish_submit(engine, config->frs.path,
      (ftun_bytes_t){body, (size_t)response->body_length},
      ftun_proxy_runtime_frs_publish_completed, &engine->frs_operation);
    if (status == FTUN_OK) {
      engine->frs_candidate = candidate;
      candidate = NULL;
      engine->frs_candidate_etag = candidate_etag;
      candidate_etag = NULL;
      engine->frs_candidate_etag_reservation = etag_reservation;
      etag_reservation = NULL;
      engine->frs_group_records = records;
      engine->frs_group_records_reservation = records_reservation;
      records_reservation = NULL;
      engine->frs_group_record_capacity = record_count;
      records = NULL;
      publish_scheduled = true;
    }
  }
  if (status == FTUN_OK && unchanged) {
    status = ftun_proxy_runtime_replace_etag(engine, etag,
                                      response->etag_length);
  }
  if (candidate != NULL) (void)ftun_runtime_abort(engine->core, &candidate);
  if (!publish_scheduled && engine->reload_prepared &&
      engine->reload_owner == FTUN_PROXY_RELOAD_OWNER_FRS) {
    (void)ftun_proxy_runtime_reload_abort_owned(engine, FTUN_PROXY_RELOAD_OWNER_FRS);
  }
  if (!publish_scheduled) ftun_proxy_runtime_frs_release_generation(engine);
  free(candidate_etag);
  free(records);
  (void)ftun_reservation_release(&etag_reservation);
  (void)ftun_reservation_release(&records_reservation);
  {
    ftun_status_t cleanup = ftun_runtime_prepared_release(&prepared);
    if (status == FTUN_OK) status = cleanup;
    /* Worker 仍拥有结果存储；未清理对象回填后由其有界重试。 */
    if (prepared != NULL) response->prepared_runtime = (uintptr_t)prepared;
  }
  (void)ftun_runtime_release(&baseline);
  if (publish_scheduled) return;
  ftun_proxy_runtime_frs_schedule_next(engine, now_ms);
  if (status == FTUN_E_AGAIN && now_ms != 0u &&
      now_ms <= UINT64_MAX - FTUN_PROXY_RUNTIME_FRS_GENERATION_RETRY_MS) {
    /* 另一来源正在发布代次：保持候选内容不变，短暂延后后重新拉取。 */
    engine->frs_due_ms = now_ms + FTUN_PROXY_RUNTIME_FRS_GENERATION_RETRY_MS;
    return;
  }
  if (status != FTUN_OK && status != FTUN_E_STALE &&
      status != FTUN_E_CANCELLED) {
    ftun_proxy_runtime_background_log(engine, status, FTUN_DIAGNOSTIC_FRS_UPDATE, "FRS update failed");
  }
}

ftun_status_t ftun_proxy_runtime_frs_schedule(ftun_proxy_runtime_t *engine)
{
  ftun_runtime_t *runtime = NULL;
  const ftun_config_t *config = NULL;
  ftun_runtime_info_t info;
  ftun_budget_usage_t usage;
  ftun_http_fetch_spec_t spec;
  ftun_status_t status;
  if (engine == NULL || !engine->frs_enabled ||
      engine->frs_operation != NULL) return FTUN_OK;
  status = ftun_runtime_active_acquire(engine->core, &runtime);
  if (status == FTUN_OK) status = ftun_runtime_get_info(runtime, &info);
  if (status == FTUN_OK && info.generation != engine->generation) {
    status = FTUN_E_STALE;
  }
  if (status == FTUN_OK) status = ftun_runtime_config(runtime, &config);
  if (status == FTUN_OK) status = ftun_budget_get_usage(engine->budget, &usage);
  if (status == FTUN_OK && usage.normal_available / 2u < FTUN_FRS_HEADER_BYTES) {
    status = FTUN_E_LIMIT;
  }
  memset(&spec, 0, sizeof(spec));
  if (status == FTUN_OK) {
    spec.budget = engine->budget;
    spec.url.data = config->frs.url;
    spec.url.length = strlen(config->frs.url);
    /* 这里只限制业务输入；下载、校验和新旧候选按各自拥有期实际准入，
     * 不把此上限作为任务额外总预留，也不承诺上限大小的响应必能接纳。 */
    spec.maximum_bytes = usage.normal_available / 2u;
    spec.socket_mark = engine->socket_mark;
    if (engine->now_ms > UINT64_MAX - UINT64_C(30000)) status = FTUN_E_LIMIT;
    else spec.deadline_ms = engine->now_ms + UINT64_C(30000);
    if (engine->frs_etag != NULL) {
      spec.if_none_match.data = engine->frs_etag;
      spec.if_none_match.length = strlen(engine->frs_etag);
    }
  }
  if (status == FTUN_OK) {
    ftun_string_t resolver = {NULL, 0u};
    if (config->frs.dns_server != NULL &&
        config->frs.dns_server[0] != '\0') {
      resolver.data = config->frs.dns_server;
      resolver.length = strlen(config->frs.dns_server);
    }
    status = ftun_http_fetch_resolver(config, runtime, resolver, &spec);
  }
  if (status == FTUN_OK) {
    status = ftun_http_fetch_route(config, runtime,
      config->frs.update_outbound, &spec);
  }
  if (status == FTUN_OK) {
    engine->frs_operation_generation = engine->generation;
    status = ftun_proxy_runtime_http_submit(engine, &spec, true, runtime,
      ftun_proxy_runtime_frs_completed, engine, &engine->frs_operation);
  }
  (void)ftun_runtime_release(&runtime);
  return status;
}
#endif


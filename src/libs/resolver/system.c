#define _POSIX_C_SOURCE 200112L

#include "libs/resolver/system.h"
#include "platform/sysresolve.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
  ftun_reservation_t reservation;
  ftun_system_resolve_completion_fn completion;
  void *completion_user;
  ftun_string_t domain;
  char domain_storage[1];
} ftun_system_resolve_context_t;

static ftun_error_t ftun_system_resolver_error(ftun_status_t status,
                                                uint32_t stage)
{
  ftun_error_t error;
  memset(&error, 0, sizeof(error));
  error.status = status;
  error.stage = stage;
  return error;
}

static int ftun_system_resolver_domain_valid(ftun_string_t domain)
{
  size_t effective;
  size_t start = 0u;
  size_t index;
  size_t dots = 0u;
  int only_digits_and_dots = 1;
  if (domain.data == NULL || domain.length == 0u ||
      domain.length > FTUN_SYSTEM_RESOLVER_MAX_DOMAIN_BYTES ||
      memchr(domain.data, '\0', domain.length) != NULL) return 0;
  effective = domain.length;
  if (domain.data[effective - 1u] == '.') effective--;
  if (effective == 0u || effective > 253u) return 0;
  for (index = 0u; index < effective; index++) {
    unsigned char byte = (unsigned char)domain.data[index];
    if (byte == '.') dots++;
    else if (byte < (unsigned char)'0' || byte > (unsigned char)'9') {
      only_digits_and_dots = 0;
    }
  }
  if (only_digits_and_dots && dots == 3u) return 0;
  for (index = 0u; index <= effective; index++) {
    if (index == effective || domain.data[index] == '.') {
      size_t label_length = index - start;
      size_t label_index;
      if (label_length == 0u || label_length > 63u ||
          domain.data[start] == '-' || domain.data[index - 1u] == '-') return 0;
      for (label_index = start; label_index < index; label_index++) {
        unsigned char byte = (unsigned char)domain.data[label_index];
        if (!((byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'-')) return 0;
      }
      start = index + 1u;
    }
  }
  return 1;
}

static int ftun_system_resolver_device_valid(ftun_string_t device)
{
  size_t index;
  if (device.length == 0u) return 1;
  if (device.data == NULL ||
      device.length >= FTUN_SOCKET_INTERFACE_BYTES) return 0;
  for (index = 0u; index < device.length; index++) {
    unsigned char byte = (unsigned char)device.data[index];
    if (byte <= (unsigned char)' ' || byte == (unsigned char)'/' ||
        byte == (unsigned char)':') return 0;
  }
  return 1;
}

static int ftun_system_resolver_request_valid(
  const ftun_system_resolve_request_t *request)
{
  return request != NULL && request->worker != NULL &&
         request->budget != NULL &&
         ftun_system_resolver_domain_valid(request->domain) &&
         ftun_system_resolver_device_valid(
           request->protection.interface_name) &&
         (request->protection.mark != 0u ||
          request->protection.interface_name.length == 0u) &&
         request->check_path != NULL && request->completion != NULL;
}

static ftun_status_t ftun_system_resolver_execute(
  ftun_bytes_t input, uint8_t *result, size_t result_capacity,
  size_t *out_result_size)
{
  size_t count = 0u;
  ftun_status_t status;
  *out_result_size = 0u;
  if (input.data == NULL || input.length < 2u ||
      input.data[input.length - 1u] != '\0' ||
      memchr(input.data, '\0', input.length - 1u) != NULL ||
      result == NULL ||
      result_capacity < FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS * 4u) {
    return FTUN_E_INVALID;
  }
  status = ftun_sysresolve_ipv4((const char *)input.data, result,
    FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS, &count);
  if (status == FTUN_OK) *out_result_size = count * 4u;
  return status;
}

static int ftun_system_resolver_result_valid(ftun_bytes_t bytes)
{
  size_t count;
  size_t index;
  size_t previous;
  if (bytes.data == NULL || bytes.length == 0u || bytes.length % 4u != 0u) {
    return 0;
  }
  count = bytes.length / 4u;
  if (count > FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS) return 0;
  for (index = 0u; index < count; index++) {
    for (previous = 0u; previous < index; previous++) {
      if (memcmp(bytes.data + previous * 4u,
                 bytes.data + index * 4u, 4u) == 0) return 0;
    }
  }
  return 1;
}

static void ftun_system_resolver_completed(ftun_operation_t *operation,
                                           ftun_error_t error,
                                           ftun_bytes_t bytes, void *user)
{
  ftun_system_resolve_context_t *context =
    (ftun_system_resolve_context_t *)user;
  ftun_system_resolve_result_t result;
  ftun_endpoint_t addresses[FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS];
  ftun_reservation_t reservation;
  size_t index;
  memset(&result, 0, sizeof(result));
  result.domain = context->domain;
  if (error.status == FTUN_OK && !ftun_system_resolver_result_valid(bytes)) {
    error = ftun_system_resolver_error(FTUN_E_STATE_CORRUPT,
                                       FTUN_SYSTEM_RESOLVER_STAGE_RESULT);
  }
  if (error.status == FTUN_OK) {
    result.address_count = bytes.length / 4u;
    result.addresses = addresses;
    memset(addresses, 0, sizeof(addresses));
    for (index = 0u; index < result.address_count; index++) {
      addresses[index].kind = FTUN_ADDRESS_IPV4;
      memcpy(addresses[index].address, bytes.data + index * 4u, 4u);
    }
  } else if (error.stage == 0u) {
    error.stage = error.status == FTUN_E_TIMEOUT ?
      FTUN_SYSTEM_RESOLVER_STAGE_DEADLINE :
      FTUN_SYSTEM_RESOLVER_STAGE_QUERY;
  }
  context->completion(operation, error, &result, context->completion_user);
  reservation = context->reservation;
  context->reservation = (ftun_reservation_t){0};
  memset(context, 0, sizeof(*context));
  free(context);
  ftun_reservation_release(&reservation);
}

static void ftun_system_resolver_context_release(
  ftun_system_resolve_context_t *context)
{
  ftun_reservation_t reservation;
  if (context == NULL) return;
  reservation = context->reservation;
  context->reservation = (ftun_reservation_t){0};
  free(context);
  ftun_reservation_release(&reservation);
}

/* 有界系统解析适配。 */
ftun_status_t ftun_system_resolve_with_execute(
  ftun_core_t *core, const ftun_system_resolve_request_t *request,
  ftun_worker_execute_fn execute, ftun_operation_t **out)
{
  ftun_system_resolve_context_t *context;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  ftun_worker_job_t job;
  ftun_status_t status;
  size_t allocation_size;
  (void)core;
  if (out != NULL) *out = NULL;
  if (out == NULL || execute == NULL ||
      !ftun_system_resolver_request_valid(request)) return FTUN_E_INVALID;
  status = request->check_path(request->path_user, &request->protection);
  if (status != FTUN_OK) return status;
  if (request->domain.length > SIZE_MAX - sizeof(*context)) {
    return FTUN_E_LIMIT;
  }
  allocation_size = sizeof(*context) + request->domain.length;
  status = ftun_budget_reserve(request->budget, allocation_size, &reservation);
  if (status != FTUN_OK) return status;
  context = (ftun_system_resolve_context_t *)calloc(1u, allocation_size);
  if (context == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  context->reservation = reservation;
  context->completion = request->completion;
  context->completion_user = request->user;
  memcpy(context->domain_storage, request->domain.data,
         request->domain.length);
  context->domain_storage[request->domain.length] = '\0';
  context->domain.data = context->domain_storage;
  context->domain.length = request->domain.length;

  memset(&job, 0, sizeof(job));
  job.execute = execute;
  job.input.data = (const uint8_t *)context->domain_storage;
  job.input.length = request->domain.length + 1u;
  job.result_capacity = FTUN_SYSTEM_RESOLVER_MAX_IPV4_RESULTS * 4u;
  job.deadline_ms = request->deadline_ms;
  status = ftun_worker_submit(request->worker, &job,
                              ftun_system_resolver_completed, context, out);
  if (status != FTUN_OK) ftun_system_resolver_context_release(context);
  return status;
}

ftun_status_t ftun_system_resolve(
  ftun_core_t *core, const ftun_system_resolve_request_t *request,
  ftun_operation_t **out)
{
  return ftun_system_resolve_with_execute(
    core, request, ftun_system_resolver_execute, out);
}

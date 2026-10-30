#include "libs/resolver/dnswire.h"
#include "core/limits.h"
#include <stdlib.h>
typedef struct {
  ftun_reservation_t reservation;
  ftun_dns_message_t message;
} ftun_owned_dns_message_t;
ftun_status_t ftun_dns_message_parse_with_budget(ftun_budget_t *budget, ftun_bytes_t wire,
  ftun_dns_message_t **out)
{
  ftun_owned_dns_message_t *owned;
  ftun_reservation_t reservation = (ftun_reservation_t){0};
  size_t size, allocation;
  ftun_status_t status;
  if (out == NULL) return FTUN_E_INVALID;
  *out = NULL;
  status = ftun_dnswire_measure(wire, &size);
  if (status != FTUN_OK) return status;
  if (size > SIZE_MAX - offsetof(ftun_owned_dns_message_t, message)) return FTUN_E_LIMIT;
  allocation = size + offsetof(ftun_owned_dns_message_t, message);
  if (budget != NULL) {
    status = ftun_budget_reserve(budget, allocation, &reservation);
    if (status != FTUN_OK) return status;
  }
  owned = calloc(1u, allocation);
  if (owned == NULL) {
    ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  status = ftun_dnswire_decode(wire, &owned->message, size);
  if (status != FTUN_OK) {
    free(owned);
    ftun_reservation_release(&reservation);
    return status;
  }
  owned->reservation = reservation;
  *out = &owned->message;
  return FTUN_OK;
}

ftun_status_t ftun_dns_message_parse(ftun_bytes_t wire, ftun_dns_message_t **out)
{
  return ftun_dns_message_parse_with_budget(NULL, wire, out);
}

void ftun_dns_message_release(ftun_dns_message_t **message)
{
  ftun_reservation_t reservation;
  ftun_owned_dns_message_t *owned;
  if (*message == NULL) return;
  owned = (ftun_owned_dns_message_t *)((uint8_t *)*message - offsetof(ftun_owned_dns_message_t, message));
  reservation = owned->reservation;
  free(owned);
  *message = NULL;
  ftun_reservation_release(&reservation);
}


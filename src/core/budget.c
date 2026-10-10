#include "budget.h"
#include <stdlib.h>
#include <string.h>

/* TASK-CORE-004 / TEST-CORE-004，目标 0.2.0：owner-loop 串行的双层预算准入。 */
struct ftun_budget {
  ftun_budget_t *parent;
  size_t limit;
  size_t cleanup_reserve;
  size_t used;
  size_t child_count;
};

struct ftun_reservation {
  ftun_budget_t *budget;
  size_t bytes;
};

static int ftun_budget_fits(const ftun_budget_t *budget, size_t bytes, int cleanup)
{
  size_t available;
  size_t ceiling;
  if (budget == NULL || budget->used > budget->limit) return 0;
  ceiling = cleanup ? budget->limit : budget->limit - budget->cleanup_reserve;
  if (budget->used > ceiling) return 0;
  available = ceiling - budget->used;
  return bytes <= available;
}

static ftun_status_t ftun_budget_reserve_kind(ftun_budget_t *budget, size_t bytes,
                                               int cleanup, ftun_reservation_t **out)
{
  ftun_reservation_t *reservation;
  if (out != NULL) *out = NULL;
  if (budget == NULL || out == NULL || bytes == 0u) return FTUN_E_INVALID;
  if (!ftun_budget_fits(budget, bytes, cleanup) ||
      (budget->parent != NULL && !ftun_budget_fits(budget->parent, bytes, cleanup))) {
    return FTUN_E_LIMIT;
  }
  reservation = (ftun_reservation_t *)malloc(sizeof(*reservation));
  if (reservation == NULL) return FTUN_E_LIMIT;
  reservation->budget = budget;
  reservation->bytes = bytes;
  budget->used += bytes;
  if (budget->parent != NULL) budget->parent->used += bytes;
  *out = reservation;
  return FTUN_OK;
}

ftun_status_t ftun_budget_create(ftun_budget_t *parent, size_t limit,
                                 size_t cleanup_reserve, ftun_budget_t **out)
{
  ftun_budget_t *budget;
  if (out != NULL) *out = NULL;
  if (out == NULL || cleanup_reserve > limit) return FTUN_E_INVALID;
  if (parent != NULL && parent->parent != NULL) return FTUN_E_INVALID;
  if (parent != NULL && parent->child_count == SIZE_MAX) return FTUN_E_LIMIT;
  budget = (ftun_budget_t *)calloc(1u, sizeof(*budget));
  if (budget == NULL) return FTUN_E_LIMIT;
  budget->parent = parent;
  budget->limit = limit;
  budget->cleanup_reserve = cleanup_reserve;
  if (parent != NULL) parent->child_count++;
  *out = budget;
  return FTUN_OK;
}

ftun_status_t ftun_budget_reserve(ftun_budget_t *budget, size_t bytes,
                                  ftun_reservation_t **out)
{
  return ftun_budget_reserve_kind(budget, bytes, 0, out);
}

ftun_status_t ftun_budget_reserve_cleanup(ftun_budget_t *budget, size_t bytes,
                                          ftun_reservation_t **out)
{
  return ftun_budget_reserve_kind(budget, bytes, 1, out);
}

ftun_status_t ftun_budget_get_usage(const ftun_budget_t *budget, ftun_budget_usage_t *out)
{
  size_t normal_ceiling;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (budget == NULL || out == NULL || budget->used > budget->limit) {
    return FTUN_E_INVALID;
  }
  normal_ceiling = budget->limit - budget->cleanup_reserve;
  out->limit = budget->limit;
  out->cleanup_reserve = budget->cleanup_reserve;
  out->used = budget->used;
  out->normal_available = budget->used < normal_ceiling
    ? normal_ceiling - budget->used : 0u;
  out->total_available = budget->limit - budget->used;
  out->child_count = budget->child_count;
  return FTUN_OK;
}

ftun_status_t ftun_reservation_release(ftun_reservation_t **reservation)
{
  ftun_reservation_t *owned;
  ftun_budget_t *budget;
  if (reservation == NULL) return FTUN_E_INVALID;
  owned = *reservation;
  if (owned == NULL) return FTUN_OK;
  budget = owned->budget;
  if (budget == NULL || owned->bytes == 0u || budget->used < owned->bytes ||
      (budget->parent != NULL && budget->parent->used < owned->bytes)) {
    return FTUN_E_STATE_CORRUPT;
  }
  budget->used -= owned->bytes;
  if (budget->parent != NULL) budget->parent->used -= owned->bytes;
  owned->budget = NULL;
  owned->bytes = 0u;
  free(owned);
  *reservation = NULL;
  return FTUN_OK;
}

ftun_status_t ftun_budget_destroy(ftun_budget_t **budget)
{
  ftun_budget_t *owned;
  if (budget == NULL) return FTUN_E_INVALID;
  owned = *budget;
  if (owned == NULL) return FTUN_OK;
  if (owned->used != 0u || owned->child_count != 0u) return FTUN_E_AGAIN;
  if (owned->parent != NULL) {
    if (owned->parent->child_count == 0u) return FTUN_E_STATE_CORRUPT;
    owned->parent->child_count--;
  }
  free(owned);
  *budget = NULL;
  return FTUN_OK;
}

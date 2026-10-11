#include "inbound.h"

#if defined(FTUN_HAVE_MODULE_TUN)
#include "inbound/tun.h"
#include "tun/lwip_adapter.h"
#endif

#include <stdlib.h>
#include <string.h>

#define FTUN_INBOUND_INVALID_SOCKET ((ftun_native_socket_t)UINTPTR_MAX)

struct ftun_inbound {
  ftun_core_t *core;
  ftun_reservation_t *reservation;
  ftun_inbound_backend_t backend;
  ftun_inbound_info_t info;
  ftun_native_socket_t listener;
  ftun_packet_port_t *port;
};

static uint32_t ftun_inbound_kind_mask(ftun_inbound_kind_t kind)
{
  switch (kind) {
    case FTUN_INBOUND_MIXED: return FTUN_INBOUND_KIND_MASK_MIXED;
    case FTUN_INBOUND_SOCKS5: return FTUN_INBOUND_KIND_MASK_SOCKS5;
    case FTUN_INBOUND_TUN: return FTUN_INBOUND_KIND_MASK_TUN;
    default: return 0u;
  }
}

static int ftun_inbound_backend_valid(const ftun_inbound_backend_t *backend)
{
  const uint32_t known = FTUN_INBOUND_KIND_MASK_MIXED |
                         FTUN_INBOUND_KIND_MASK_SOCKS5 |
                         FTUN_INBOUND_KIND_MASK_TUN;
  return backend != NULL && (backend->kind_mask & ~known) == 0u &&
         backend->listener_open != NULL && backend->listener_close != NULL &&
         backend->packet_open != NULL && backend->packet_close != NULL &&
         backend->stream_ingress != NULL && backend->packet_ingress != NULL;
}

static int ftun_inbound_name_valid(ftun_string_t name, size_t capacity)
{
  size_t index;
  if (name.data == NULL || name.length == 0u || name.length >= capacity ||
      memchr(name.data, '\0', name.length) != NULL) return 0;
  for (index = 0u; index < name.length; index++) {
    unsigned char byte = (unsigned char)name.data[index];
    if (byte == (unsigned char)',' || byte <= 0x1fu || byte == 0x7fu) {
      return 0;
    }
  }
  return 1;
}

static ftun_status_t ftun_inbound_validate(const ftun_inbound_spec_t *spec,
                                           uint32_t kind_mask)
{
  uint32_t required;
  size_t user_index;
  if (spec == NULL || spec->budget == NULL || spec->generation == 0u ||
      spec->id == 0u ||
      !ftun_inbound_name_valid(spec->name, FTUN_INBOUND_NAME_BYTES)) {
    return FTUN_E_INVALID;
  }
  required = ftun_inbound_kind_mask(spec->kind);
  if (required == 0u) return FTUN_E_INVALID;
  if ((kind_mask & required) == 0u) return FTUN_E_UNSUPPORTED;
  if (spec->kind == FTUN_INBOUND_TUN) {
#if !defined(FTUN_HAVE_MODULE_TUN)
    return FTUN_E_UNSUPPORTED;
#else
    if (spec->listen.kind != FTUN_ADDRESS_NONE || spec->listen.port != 0u ||
        spec->listen.domain.length != 0u || (!spec->tcp && !spec->udp) ||
        spec->user_count != 0u || spec->users != NULL ||
        !ftun_inbound_name_valid(spec->tun.name,
                                 FTUN_PACKET_PORT_NAME_BYTES) ||
        spec->tun.mtu < FTUN_LWIP_MIN_MTU ||
        spec->tun.mtu > FTUN_LWIP_MAX_MTU) return FTUN_E_INVALID;
    return FTUN_OK;
#endif
  }
  if (!spec->tcp || spec->listen.kind != FTUN_ADDRESS_IPV4 ||
      spec->listen.port == 0u || spec->listen.domain.length != 0u ||
      spec->tun.name.length != 0u || spec->tun.mtu != 0u) {
    return FTUN_E_INVALID;
  }
  if ((spec->user_count == 0u) != (spec->users == NULL) ||
      spec->user_count > 64u) return FTUN_E_INVALID;
  for (user_index = 0u; user_index < spec->user_count; user_index++) {
    const ftun_inbound_user_t *user = &spec->users[user_index];
    if (user->username.data == NULL || user->password.data == NULL ||
        user->username.length == 0u || user->username.length > 255u ||
        user->password.length == 0u || user->password.length > 255u) {
      return FTUN_E_INVALID;
    }
  }
  return FTUN_OK;
}

static ftun_status_t ftun_inbound_listener_unavailable(
  void *context, const ftun_inbound_spec_t *spec, ftun_native_socket_t *out)
{
  (void)context;
  (void)spec;
  if (out != NULL) *out = FTUN_INBOUND_INVALID_SOCKET;
  return FTUN_E_UNSUPPORTED;
}

static ftun_status_t ftun_inbound_listener_close(
  void *context, ftun_native_socket_t *listener)
{
  (void)context;
  if (listener == NULL) return FTUN_E_INVALID;
  *listener = FTUN_INBOUND_INVALID_SOCKET;
  return FTUN_OK;
}

static ftun_status_t ftun_inbound_packet_open(
  void *context, ftun_core_t *core, const ftun_tun_spec_t *spec,
  ftun_packet_port_t **out)
{
  (void)context;
#if defined(FTUN_HAVE_MODULE_TUN)
  return ftun_packet_port_open(core, spec, out);
#else
  (void)core;
  (void)spec;
  if (out != NULL) *out = NULL;
  return FTUN_E_UNSUPPORTED;
#endif
}

static ftun_status_t ftun_inbound_packet_close(void *context,
                                                ftun_packet_port_t **port)
{
  (void)context;
#if defined(FTUN_HAVE_MODULE_TUN)
  return ftun_packet_port_close(port);
#else
  if (port == NULL) return FTUN_E_INVALID;
  *port = NULL;
  return FTUN_OK;
#endif
}

static ftun_status_t ftun_inbound_stream_unavailable(
  void *context, ftun_core_t *core, ftun_inbound_kind_t kind,
  ftun_stream_t *stream)
{
  (void)context;
  (void)core;
  (void)kind;
  (void)stream;
  return FTUN_E_UNSUPPORTED;
}

static ftun_status_t ftun_inbound_packet_ingress_default(
  void *context, ftun_core_t *core, ftun_packet_port_t *port,
  ftun_packet_t *packet)
{
  (void)context;
#if defined(FTUN_HAVE_MODULE_TUN)
  return ftun_tun_ingress(core, port, packet);
#else
  (void)core;
  (void)port;
  (void)packet;
  return FTUN_E_UNSUPPORTED;
#endif
}

static const ftun_inbound_backend_t ftun_inbound_default_backend = {
#if defined(FTUN_HAVE_MODULE_TUN)
  FTUN_INBOUND_KIND_MASK_TUN,
#else
  0u,
#endif
  ftun_inbound_listener_unavailable,
  ftun_inbound_listener_close,
  ftun_inbound_packet_open,
  ftun_inbound_packet_close,
  ftun_inbound_stream_unavailable,
  ftun_inbound_packet_ingress_default,
  NULL
};

/* TASK-INBOUND-001 / TEST-INBOUND-001，目标 0.2.0：统一资源工厂。 */
ftun_status_t ftun_inbound_prepare_with_backend(
  ftun_core_t *core, const ftun_inbound_spec_t *spec,
  const ftun_inbound_backend_t *backend, ftun_inbound_t **out)
{
  ftun_inbound_t *inbound;
  ftun_reservation_t *reservation = NULL;
  ftun_status_t status;
  if (out != NULL) *out = NULL;
  if (core == NULL || out == NULL || !ftun_inbound_backend_valid(backend)) {
    return FTUN_E_INVALID;
  }
  status = ftun_inbound_validate(spec, backend->kind_mask);
  if (status != FTUN_OK) return status;
  status = ftun_budget_reserve(spec->budget, sizeof(*inbound), &reservation);
  if (status != FTUN_OK) return status;
  inbound = (ftun_inbound_t *)calloc(1u, sizeof(*inbound));
  if (inbound == NULL) {
    (void)ftun_reservation_release(&reservation);
    return FTUN_E_LIMIT;
  }
  inbound->core = core;
  inbound->reservation = reservation;
  inbound->backend = *backend;
  inbound->listener = FTUN_INBOUND_INVALID_SOCKET;
  inbound->info.kind = spec->kind;
  inbound->info.resource_kind = spec->kind == FTUN_INBOUND_TUN
    ? FTUN_INBOUND_RESOURCE_PACKET_PORT : FTUN_INBOUND_RESOURCE_LISTENER;
  inbound->info.generation = spec->generation;
  inbound->info.id = spec->id;
  memcpy(inbound->info.name, spec->name.data, spec->name.length);
  inbound->info.fixed_outbound_id = spec->fixed_outbound_id;
  inbound->info.tcp = spec->tcp;
  inbound->info.udp = spec->udp;
  if (spec->kind == FTUN_INBOUND_TUN) {
    ftun_tun_spec_t tun = spec->tun;
    char name[FTUN_PACKET_PORT_NAME_BYTES];
    memset(name, 0, sizeof(name));
    memcpy(name, spec->tun.name.data, spec->tun.name.length);
    tun.name.data = name;
    status = backend->packet_open(backend->context, core, &tun,
                                  &inbound->port);
    if (status == FTUN_OK && inbound->port == NULL) {
      status = FTUN_E_STATE_CORRUPT;
    }
  } else {
    ftun_inbound_spec_t copied = *spec;
    copied.name.data = inbound->info.name;
    status = backend->listener_open(backend->context, &copied,
                                    &inbound->listener);
    if (status == FTUN_OK &&
        inbound->listener == FTUN_INBOUND_INVALID_SOCKET) {
      status = FTUN_E_STATE_CORRUPT;
    }
  }
  if (status != FTUN_OK) {
    if (inbound->port != NULL) {
      (void)backend->packet_close(backend->context, &inbound->port);
    }
    if (inbound->listener != FTUN_INBOUND_INVALID_SOCKET) {
      (void)backend->listener_close(backend->context, &inbound->listener);
    }
    free(inbound);
    (void)ftun_reservation_release(&reservation);
    return status;
  }
  inbound->info.accepting = true;
  *out = inbound;
  return FTUN_OK;
}

ftun_status_t ftun_inbound_prepare(ftun_core_t *core,
                                   const ftun_inbound_spec_t *spec,
                                   ftun_inbound_t **out)
{
  return ftun_inbound_prepare_with_backend(core, spec,
                                            &ftun_inbound_default_backend,
                                            out);
}

ftun_status_t ftun_inbound_get_info(const ftun_inbound_t *inbound,
                                    ftun_inbound_info_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (inbound == NULL || out == NULL) return FTUN_E_INVALID;
  *out = inbound->info;
  return FTUN_OK;
}

ftun_status_t ftun_inbound_get_policy(const ftun_inbound_t *inbound,
                                      ftun_inbound_policy_t *out)
{
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (inbound == NULL || out == NULL) return FTUN_E_INVALID;
  out->generation = inbound->info.generation;
  out->inbound_id = inbound->info.id;
  out->fixed_outbound_id = inbound->info.fixed_outbound_id;
  out->forced = inbound->info.fixed_outbound_id != 0u;
  return FTUN_OK;
}

ftun_status_t ftun_inbound_bind_metadata(const ftun_inbound_t *inbound,
                                         const ftun_metadata_t *adapter,
                                         ftun_metadata_t *out)
{
  const uint32_t known = FTUN_META_SOURCE | FTUN_META_PORT |
                         FTUN_META_NETWORK | FTUN_META_DOMAIN;
  if (out != NULL) memset(out, 0, sizeof(*out));
  if (inbound == NULL || adapter == NULL || out == NULL ||
      !inbound->info.accepting || adapter->generation != 0u ||
      adapter->inbound_id != 0u || (adapter->known_fields & ~known) != 0u) {
    return FTUN_E_INVALID;
  }
  if ((adapter->known_fields & FTUN_META_NETWORK) == 0u ||
      (adapter->network != 1u && adapter->network != 2u)) {
    return FTUN_E_INVALID;
  }
  if ((adapter->network == 1u && !inbound->info.tcp) ||
      (adapter->network == 2u && !inbound->info.udp)) {
    return FTUN_E_UNSUPPORTED;
  }
  *out = *adapter;
  out->generation = inbound->info.generation;
  out->inbound_id = inbound->info.id;
  return FTUN_OK;
}

ftun_status_t ftun_inbound_stream_ingress(ftun_inbound_t *inbound,
                                          ftun_stream_t *stream)
{
  if (inbound == NULL || stream == NULL) return FTUN_E_INVALID;
  if (!inbound->info.accepting) return FTUN_E_CANCELLED;
  if (inbound->info.resource_kind != FTUN_INBOUND_RESOURCE_LISTENER) {
    return FTUN_E_UNSUPPORTED;
  }
  return inbound->backend.stream_ingress(inbound->backend.context,
                                          inbound->core,
                                          inbound->info.kind, stream);
}

ftun_status_t ftun_inbound_packet_ingress(ftun_inbound_t *inbound,
                                          ftun_packet_t *packet)
{
  if (inbound == NULL || packet == NULL) return FTUN_E_INVALID;
  if (!inbound->info.accepting) return FTUN_E_CANCELLED;
  if (inbound->info.resource_kind != FTUN_INBOUND_RESOURCE_PACKET_PORT ||
      inbound->port == NULL) return FTUN_E_UNSUPPORTED;
  return inbound->backend.packet_ingress(inbound->backend.context,
                                          inbound->core, inbound->port,
                                          packet);
}

ftun_status_t ftun_inbound_close(ftun_inbound_t **inbound)
{
  ftun_inbound_t *owned;
  ftun_reservation_t *reservation;
  ftun_status_t status = FTUN_OK;
  ftun_status_t release_status;
  if (inbound == NULL) return FTUN_E_INVALID;
  owned = *inbound;
  if (owned == NULL) return FTUN_OK;
  owned->info.accepting = false;
  if (owned->info.resource_kind == FTUN_INBOUND_RESOURCE_PACKET_PORT) {
    status = owned->backend.packet_close(owned->backend.context, &owned->port);
    owned->port = NULL;
  } else {
    status = owned->backend.listener_close(owned->backend.context,
                                           &owned->listener);
    owned->listener = FTUN_INBOUND_INVALID_SOCKET;
  }
  reservation = owned->reservation;
  owned->reservation = NULL;
  release_status = ftun_reservation_release(&reservation);
  memset(owned, 0, sizeof(*owned));
  free(owned);
  *inbound = NULL;
  return status != FTUN_OK ? status : release_status;
}

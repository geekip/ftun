#include "platform/linux/netmon.h"
#include "platform/linux/uapi.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { \
  if (!(x)) { \
    fprintf(stderr, "netmon contract failed at line %d: %s\n", __LINE__, #x); \
    return 1; \
  } \
} while (0)

typedef struct {
  uint8_t data[1024];
  size_t length;
} blob_t;

static void append(blob_t *blob, uint16_t type, const void *payload, size_t payload_length,
                   const void *attributes, size_t attribute_length)
{
  struct ftun_nlmsghdr header;
  size_t total = FTUN_NLMSG_LENGTH(payload_length + attribute_length);
  memset(&header, 0, sizeof(header));
  header.nlmsg_len = (uint32_t)total;
  header.nlmsg_type = type;
  memcpy(blob->data + blob->length, &header, sizeof(header));
  memcpy(blob->data + blob->length + FTUN_NLMSG_HDRLEN, payload, payload_length);
  if (attribute_length != 0u) {
    memcpy(blob->data + blob->length + FTUN_NLMSG_HDRLEN + FTUN_NLMSG_ALIGN(payload_length),
           attributes, attribute_length);
    header.nlmsg_len = (uint32_t)(FTUN_NLMSG_HDRLEN + FTUN_NLMSG_ALIGN(payload_length) +
                                  attribute_length);
    memcpy(blob->data + blob->length, &header, sizeof(header));
    total = header.nlmsg_len;
  }
  blob->length += FTUN_NLMSG_ALIGN(total);
}

static void link_message(blob_t *blob, uint16_t type, int32_t index)
{
  struct ftun_ifinfomsg info;
  memset(&info, 0, sizeof(info));
  info.ifi_index = index;
  append(blob, type, &info, sizeof(info), NULL, 0u);
}

static void address_message(blob_t *blob, uint16_t type, uint32_t index)
{
  struct ftun_ifaddrmsg info;
  memset(&info, 0, sizeof(info));
  info.ifa_family = 2u;
  info.ifa_index = index;
  append(blob, type, &info, sizeof(info), NULL, 0u);
}

static void route_message(blob_t *blob, uint16_t type, uint32_t output)
{
  struct ftun_rtmsg route;
  struct { struct ftun_rtattr header; uint32_t value; } attribute;
  memset(&route, 0, sizeof(route));
  route.rtm_family = 2u;
  memset(&attribute, 0, sizeof(attribute));
  attribute.header.rta_len = (uint16_t)FTUN_RTA_LENGTH(4u);
  attribute.header.rta_type = FTUN_RTA_OIF;
  attribute.value = output;
  append(blob, type, &route, sizeof(route), &attribute, sizeof(attribute));
}

int main(void)
{
  blob_t blob;
  ftun_network_change_t change;
  size_t index;
  /* 各类消息映射到变化类型和接口。 */
  memset(&blob, 0, sizeof(blob));
  memset(&change, 0, sizeof(change));
  link_message(&blob, FTUN_RTM_NEWLINK, 5);
  CHECK(ftun_netmon_parse(blob.data, blob.length, &change) == 1u);
  CHECK(change.mask == FTUN_NETWORK_CHANGE_LINK && change.interface_count == 1u &&
        change.interfaces[0] == 5u && change.events == 1u);
  memset(&blob, 0, sizeof(blob));
  address_message(&blob, FTUN_RTM_DELADDR, 3u);
  route_message(&blob, FTUN_RTM_NEWROUTE, 7u);
  append(&blob, FTUN_RTM_DELRULE, (uint8_t[8]){0}, 8u, NULL, 0u);
  CHECK(ftun_netmon_parse(blob.data, blob.length, &change) == 3u);
  CHECK(change.mask == (FTUN_NETWORK_CHANGE_LINK | FTUN_NETWORK_CHANGE_ADDRESS |
                        FTUN_NETWORK_CHANGE_ROUTE | FTUN_NETWORK_CHANGE_RULE));
  CHECK(change.interface_count == 3u && change.interfaces[1] == 3u &&
        change.interfaces[2] == 7u && change.events == 4u);
  /* 同一接口只记一次；不认识的消息类型忽略；截断的消息不处理。 */
  memset(&blob, 0, sizeof(blob));
  memset(&change, 0, sizeof(change));
  link_message(&blob, FTUN_RTM_DELLINK, 5);
  link_message(&blob, FTUN_RTM_NEWLINK, 5);
  append(&blob, 99u, (uint8_t[4]){0}, 4u, NULL, 0u);
  CHECK(ftun_netmon_parse(blob.data, blob.length, &change) == 2u);
  CHECK(change.interface_count == 1u && change.events == 2u);
  CHECK(ftun_netmon_parse(blob.data, 7u, &change) == 0u);
  /* 接口数组满了之后事件仍计数，类型位不丢。 */
  memset(&blob, 0, sizeof(blob));
  memset(&change, 0, sizeof(change));
  for (index = 1u; index <= FTUN_NETWORK_CHANGE_INTERFACES + 2u; index++) {
    link_message(&blob, FTUN_RTM_NEWLINK, (int32_t)index);
  }
  CHECK(ftun_netmon_parse(blob.data, blob.length, &change) ==
        FTUN_NETWORK_CHANGE_INTERFACES + 2u);
  CHECK(change.interface_count == FTUN_NETWORK_CHANGE_INTERFACES &&
        change.events == FTUN_NETWORK_CHANGE_INTERFACES + 2u &&
        change.mask == FTUN_NETWORK_CHANGE_LINK);
  CHECK(ftun_netmon_parse(NULL, 0u, &change) == 0u);
  puts("Netmon: message classification, interface merge and bounds passed");
  return 0;
}

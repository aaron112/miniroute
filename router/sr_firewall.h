
/* Comment out the below line to disable firewall entirely */
/* #define SR_FIREWALL_ENABLED */

#ifndef SR_FIREWALL_H
#define SR_FIREWALL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include "sr_protocol.h"

#define SR_FW_CONN_TIMEOUT  60

typedef enum {
  DENY, ALLOW
} sr_fw_action;

typedef enum {
  ICMP  = 1,
  TCP   = 6,
  UDP   = 17
} sr_ip_protocol;

typedef enum {
  IN, OUT, BOTH
} sr_fw_direction;


typedef struct sr_connection {

  sr_ip_protocol protocol;

  uint32_t  src_addr;
  uint16_t  src_port;
  uint32_t  dst_addr;
  uint16_t  dst_port;

  uint32_t  last_fin_ack;

  time_t    last_seen;

  struct sr_connection *next;

} sr_connection_t;


typedef struct sr_fw_rule {

  sr_fw_action    action;
  sr_ip_protocol  protocol;
  sr_fw_direction direction;

  uint32_t  src_addr;
  uint32_t  src_mask;
  uint16_t  src_port;

  uint32_t  dst_addr;
  uint32_t  dst_mask;
  uint16_t  dst_port;

  struct sr_fw_rule*  next; 

} sr_fw_rule_t;

struct sr_fw {

  sr_connection_t * connections;
  sr_fw_rule_t    * rules;
};

void sr_init_fw(struct sr_fw* fw);
int sr_load_fw(struct sr_fw* fw, const char* filename);
sr_fw_action sr_fw_inspect(struct sr_fw* fw,
    uint8_t * packet /* lent */,
    unsigned int len);

#endif /* -- SR_FIREWALL_H -- */

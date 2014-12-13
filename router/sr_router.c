/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


struct sr_if* sr_find_iface(struct sr_instance* sr, uint32_t ip) {

  struct sr_if* p_if = sr->if_list;

  while (p_if != NULL)
    if (p_if->ip == ip)
      return p_if;
    else
      p_if = p_if->next;

  return NULL;
}

void sr_fill_eth(uint8_t* buf, 
  uint8_t *ether_dhost, 
  uint8_t *ether_shost, 
  uint16_t ether_type) {

  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;

  if ( !ether_dhost ) /* Broadcast address */
    memset(ehdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  else
    memcpy(ehdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);

  memcpy(ehdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
  ehdr->ether_type = htons(ether_type);

}

/**
  Fill in simple IP header with "Don't fragment".
*/
void sr_fill_simple_ip(uint8_t* buf, 
  unsigned short len,
  uint8_t ttl, 
  uint8_t protocol,
  uint32_t src,
  uint32_t dst) {

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

  iphdr->ip_v   = 4;    /* IPv4 */
  iphdr->ip_hl  = 5;   /* Header Size with no options */

  iphdr->ip_tos = 0;
  iphdr->ip_len = htons(len + sizeof(sr_ip_hdr_t));
  iphdr->ip_id  = 0;
  iphdr->ip_off = htons(0xFFFF & IP_DF);
  iphdr->ip_ttl = ttl ? ttl : INIT_TTL;
  iphdr->ip_p   = protocol;

  iphdr->ip_src = src;
  iphdr->ip_dst = dst;

  /* Clear out checksum field before recalculating */
  iphdr->ip_sum = 0x0;
  iphdr->ip_sum = cksum((void*)iphdr, sizeof(sr_ip_hdr_t));
}


struct sr_rt* sr_findroute(struct sr_instance* sr, 
  uint32_t dest) {

  struct sr_rt* p_rt = sr->routing_table;
  struct sr_rt* match = NULL;

  while (p_rt != NULL) {

    /* Longest Prefix Match */
    if ( (p_rt->dest.s_addr & p_rt->mask.s_addr) == (dest & p_rt->mask.s_addr) )
      if (match == NULL || match->mask.s_addr < p_rt->mask.s_addr)
        match = p_rt;

    p_rt = p_rt->next;
  }

  return match;
}

/*
  Find route and send out inet packet.
*/
void sr_send_inetpkt(struct sr_instance* sr,
        uint8_t * pkt/* lent */,
        unsigned int len,
        struct sr_if* src_iface/* lent */,
        int inited_by_router) {

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  /* Find route */
  struct sr_rt* nexthop = sr_findroute(sr, iphdr->ip_dst);

  if (nexthop == NULL) {
    /* No route found */
    fprintf(stderr, "sr_send_inetpkt: No route found!\n");
    if (inited_by_router)
      return;

    sr_send_icmp(sr, pkt, len, src_iface, 
      ICMP_TYPE_UNREACHABLE, ICMP_UNREACHABLE_NET);
    return;
  }

  /* Next hop is immediate host */
  uint32_t nexthop_ip = (nexthop->gw.s_addr ? nexthop->gw.s_addr : iphdr->ip_dst);
  
  /* ARP Lookup */
  struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, nexthop_ip);

  if (arpentry == NULL) {
    /* No ARP entry found in cache, request one & queue packet */
    fprintf(stderr, "sr_send_inetpkt: No ARP entry found in cache, queuing packet.\n");

    struct sr_arpreq *arpreq = sr_arpcache_queuereq(
      &sr->cache, 
      nexthop_ip, 
      pkt, len, nexthop->interface);

    /* Send ARP request if not already sent */
    if (arpreq->sent == 0) {
      sr_send_arpreq(sr, arpreq->ip, sr_get_interface(sr, nexthop->interface));
      arpreq->sent = time(NULL);
      ++arpreq->times_sent;
    }

    return;
  }

  struct sr_if* iface_nexthop = sr_get_interface(sr, nexthop->interface);
  assert(iface_nexthop);

  sr_fill_eth(pkt, (uint8_t *)arpentry->mac, 
    (uint8_t *)iface_nexthop->addr, ethertype_ip);

  free(arpentry);

  /* Send frame to next hop */
  fprintf(stderr, "sr_send_inetpkt: Ready to send frame.\n");
  
  /* Send INet Packet */
  sr_send_packet(sr, pkt, len, iface_nexthop->name);
}

void sr_send_icmp(struct sr_instance* sr,
        uint8_t * pkt/* lent */,
        unsigned int len,
        struct sr_if* iface/* lent */,
        uint8_t icmp_type,
        uint8_t icmp_code) {

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  /* Assume larger payload len first */
  const unsigned int hdr_len = sizeof(sr_ethernet_hdr_t) + 
    sizeof(sr_ip_hdr_t);
  unsigned int payload_len = 0;
  uint8_t* pktbuf;

  fprintf(stderr, "sr_send_icmp: Generating ICMP Message (Type %d)\n", icmp_type);

  /* ICMP Echo Reply (Type 0) */
  if (icmp_type == ICMP_TYPE_ECHO_REPLY) {

    /* Send ICMP echo reply and be done. */
    /* Copy data from old ICMP Echo Request */
    payload_len = len - hdr_len;
    pktbuf = calloc(1, len);

    memcpy(pktbuf+hdr_len, pkt+hdr_len, payload_len);

    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pktbuf + hdr_len);
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0x0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, payload_len);

  } else {
    /* ICMP Type 3 (Unreachable) or Type 11 (TTL Exceeded) */
    payload_len = sizeof(sr_icmp_t3_hdr_t);
    pktbuf = calloc(1, hdr_len + payload_len);

    sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(pktbuf + hdr_len);

    icmp_t3_hdr->icmp_type = icmp_type;
    icmp_t3_hdr->icmp_code = icmp_code;

    memcpy(icmp_t3_hdr->data, pkt+sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);

    icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
  }

  sr_fill_simple_ip(pktbuf, payload_len, iphdr->ip_ttl, 
    ip_protocol_icmp, iface->ip, iphdr->ip_src);
  sr_send_inetpkt(sr, pktbuf, hdr_len + payload_len, iface, 1);

  free(pktbuf);
}


void sr_forwardpkt(struct sr_instance* sr,
        uint8_t * pkt/* lent */,
        unsigned int len,
        struct sr_if* iface/* lent */) {

  assert(sr);
  assert(pkt);
  assert(iface);

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  /* Check TTL */
  if (iphdr->ip_ttl <= 1) {
    /* TTL Exceeded */
    fprintf(stderr, "sr_forwardpkt: TTL Exceeded!\n");
    sr_send_icmp(sr, pkt, len, iface, ICMP_TYPE_TTLEXCEED, 0);
    /* ICMP Type 11 0x0: Time exceeded */

    return;
  }


  /* Make a copy */
  uint8_t *outpkt = malloc(len);
  memcpy(outpkt, pkt, len);

  /* Decrement TTL */
  iphdr = (sr_ip_hdr_t *)(outpkt + sizeof(sr_ethernet_hdr_t));
  --iphdr->ip_ttl;
  /* Recalculate checksum */
  iphdr->ip_sum = 0x0;
  iphdr->ip_sum = cksum((void*)iphdr, sizeof(sr_ip_hdr_t));

  sr_send_inetpkt(sr, outpkt, len, iface, 0);

  free(outpkt);
}

void sr_send_arpreq(struct sr_instance *sr, uint32_t ip, struct sr_if* iface) {

    assert(iface);

    const int pktlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* pktbuf = calloc(1, pktlen);

    sr_fill_eth(pktbuf, NULL, iface->addr, ethertype_arp);

    /* Fill ARP Request */
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pktbuf + sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_hrd = htons(1);         /* Hardware type : Ethernet(1) */
    arp_hdr->ar_pro = htons(0x0800);    /* Protocol type : ARP (0x0800) */
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op  = htons(arp_op_request);

    /* sender hardware address */
    memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = iface->ip;    /* sender ip address */

    /* target hardware address */
    memset(arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = ip;           /* target ip address */

    /* Send ARP Request */
    sr_send_packet(sr, pktbuf, pktlen, iface->name);

    free(pktbuf);
}

void sr_send_arpreply(struct sr_instance* sr, 
  sr_arp_hdr_t *arp_req,
  struct sr_if* iface) {

  const int pktlen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* pktbuf = calloc(1, pktlen);

  sr_fill_eth(pktbuf, arp_req->ar_sha, iface->addr, ethertype_arp);

  /* Fill ARP Reply */
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pktbuf + sizeof(sr_ethernet_hdr_t));
  arp_hdr->ar_hrd = htons(1);         /* Hardware type : Ethernet(1) */
  arp_hdr->ar_pro = htons(0x0800);    /* Protocol type : ARP (0x0800) */
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = 4;
  arp_hdr->ar_op  = htons(arp_op_reply);

  /* sender hardware address */
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip; /* sender ip address */

  /* target hardware address */
  memcpy(arp_hdr->ar_tha, arp_req->ar_sha, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = arp_req->ar_sip;     /* target ip address */

  /* Send ARP Reply */
  sr_send_packet(sr, pktbuf, pktlen, iface->name);

  free(pktbuf);
}

void sr_handlearp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        struct sr_if* iface/* lent */) {

  if (len < ( sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) )) {
    fprintf(stderr, "Failed to process ARP header, insufficient length\n");
    return;
  }

  fprintf(stderr, "sr_handlearp: begin\n");

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  int isRequest = (ntohs(arp_hdr->ar_op) == arp_op_request);

  fprintf(stderr, "sr_handlearp: isRequest = 1\n");

  if (iface->ip != arp_hdr->ar_tip)  /* Not for me - ignore it */ {
    fprintf(stderr, "sr_handlearp: Not for me - ignore it\n");
    return;
  }

  if (isRequest) {  

    /* For me - genernate a reply */
    sr_send_arpreply(sr, arp_hdr, iface);

  } else {

    /* Reply - Add to ARP cache (Caches only if target is me) */
    /* This method performs two functions:
     1) Looks up this IP in the request queue. If it is found, returns a pointer
        to the sr_arpreq with this IP. Otherwise, returns NULL.
     2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
    fprintf(stderr, "sr_handlearp: ARP Reply Received.\n");

    struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, 
      (unsigned char *)(arp_hdr->ar_sha), 
      arp_hdr->ar_sip);

    if (req == NULL)
      return;

    /* Send out queued packets */
    struct sr_packet *pktq = req->packets;
    struct sr_packet *p_pkt;

    while (pktq != NULL) {
      p_pkt = pktq;

      /* Send out queued packet */
      struct sr_if* iface_s = sr_get_interface(sr, p_pkt->iface);
      assert(iface_s);
      sr_send_inetpkt(sr, p_pkt->buf, p_pkt->len, iface_s, 0);

      pktq = pktq->next;
      free(p_pkt);
    }

    free(req);
  }
}

void sr_handleincoming(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        struct sr_if* iface/* lent */) {

  /* Reply everything with 0x3 = Port unreachable */
  sr_send_icmp(sr, packet, len, iface, 
    ICMP_TYPE_UNREACHABLE, ICMP_UNREACHABLE_PORT);
}

void sr_handleicmp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        struct sr_if* iface/* lent */) {

  if (len < ( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) )) {
    fprintf(stderr, "Failed to process ICMP header, insufficient length\n");
    return;
  }

  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(
    packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Sanity Check */
  if (cksum(icmp_hdr, packet + len - (uint8_t*)icmp_hdr) != CKSUM_CORRECT) {
    fprintf(stderr, "sr_handleicmp: Corrupted ICMP Header, dropping packet.\n");
    return;
  }

  /* Ignore anything other than ICMP Echo Request */
  if (icmp_hdr->icmp_type != 8) {
    fprintf(stderr, "sr_handleicmp: ICMP Reply dropped.\n");
    return;
  }

  sr_send_icmp(sr, packet, len, iface, ICMP_TYPE_ECHO_REPLY, 0);
}

void sr_handleip(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        struct sr_if* iface/* lent */) {

  if (len < ( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) )) {
    fprintf(stderr, "Failed to process IP header, insufficient length\n");
    return;
  }

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Sanity Check */
  if (cksum(iphdr, sizeof(sr_ip_hdr_t)) != CKSUM_CORRECT) {
    fprintf(stderr, "sr_handleip: Corrupted IP Header, dropping packet.\n");
    return;
  }

#ifdef SR_FIREWALL_ENABLED

  if ( sr_fw_inspect(&(sr->fw), packet, len) == DENY ) {
    fprintf(stderr, "sr_handleip: Packet denied by firewall, dropped.\n");
    return;
  }

#endif

  /* Check if this is for me:
     Try to assoicate ip_dst to one of our interfaces */
  struct sr_if* dst_iface = sr_find_iface(sr, iphdr->ip_dst);
  if ( dst_iface != NULL ) {

    fprintf(stderr, "sr_handleip: Received packet addressed to this router.\n");
    /* Is for me: Reply */
    if (iphdr->ip_p == ip_protocol_icmp)
      sr_handleicmp(sr, packet, len, dst_iface);
    else
      sr_handleincoming(sr, packet, len, dst_iface);

  } else {
    /* Not for me: Forward it */
    sr_forwardpkt(sr, packet, len, iface);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*print_hdrs(packet, len);*/

  struct sr_if* iface = sr_get_interface(sr, interface);
  assert(iface);

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "ERROR: Packet too small.\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);
  switch (ethtype) {

  case ethertype_arp:
    sr_handlearp(sr, packet, len, iface);
    break;

  case ethertype_ip:
    sr_handleip(sr, packet, len, iface);
    break;

  default:
    fprintf(stderr, "ERROR: Unrecognized Ethernet Type: %d\n", ethtype);
  }

}

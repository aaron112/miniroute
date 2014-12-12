
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "sr_protocol.h"
#include "sr_firewall.h"
#include "sr_router.h"
#include "sr_utils.h"

#ifdef SR_FIREWALL_ENABLED

#define DELIMITER " \t\r\n"

#define ACTION_ALLOW    "allow"
#define ACTION_DENY     "deny"

#define PROTO_TCP       "tcp"
#define PROTO_UDP       "udp"
#define PROTO_ICMP      "icmp"

#define IP_BLOCK        '/'

#define FW_FROM         "from"
#define FW_TO           "to"
#define FW_ANY          "any"

#define DIR_IN          "in"
#define DIR_OUT         "out"

#define PORT_MAX        65535

int parse_ip_block(char* sp, uint32_t* addr, uint32_t* mask) {

    struct in_addr inet_addr;
    int cidr;
    char *cp;

    if (strcmp(sp, FW_ANY) == 0) {
        *addr = 0;
        *mask = 0;

    } else {
        cp = strchr(sp, IP_BLOCK);

        if (cp == NULL) {
            fprintf(stderr,
                "Error loading firewall rules, malformed ip block: %s\n",
                sp);
            return -1; 
        }

        *cp = '\0';
        ++cp;

        if (inet_aton(sp, &inet_addr) == 0) { 
            fprintf(stderr,
                "Error loading firewall rules, cannot convert %s to valid IP\n",
                sp);
            return -1; 
        }
        *addr = inet_addr.s_addr;

        cidr = atoi(cp);
        if (cidr < 0 || cidr > 32) { 
            fprintf(stderr,
                "Error loading firewall rules, cannot convert %s to valid Netmask\n",
                cp);
            return -1; 
        }
        cidr = 32 - cidr;

        *mask = htonl((0xFFFFFFFF >> cidr) << cidr);
    }

    return 1;
}

int sr_parse_fw_rule(char* line, sr_fw_rule_t* rule) {
/* <action> <protocol> from <incoming IP block> [<optional incoming port>] to <outgoing IP block>
[<optional outgoing port>] [<optional direction>] */

    int i;
    char *sp;

    /* <action> */
    sp = strtok(line, DELIMITER);

    if (strncmp(sp, ACTION_ALLOW, 5) == 0)  /* allow */
        rule->action = ALLOW;

    else if (strncmp(sp, ACTION_DENY, 4) == 0)
        rule->action = DENY;

    else {
        fprintf(stderr,
            "Error loading firewall rules, cannot convert %s to valid action.\n",
            sp);
        return -1; 
    }

    /* <protocol> */
    sp = strtok(NULL, DELIMITER);

    if (strncmp(sp, PROTO_TCP, 3) == 0)  /* allow */
        rule->protocol = TCP;

    else if (strncmp(sp, PROTO_UDP, 3) == 0)
        rule->protocol = UDP;

    else if (strncmp(sp, PROTO_ICMP, 4) == 0)
        rule->protocol = ICMP;

    else {
        fprintf(stderr,
            "Error loading firewall rules, cannot convert %s to valid protocol.\n",
            sp);
        return -1; 
    }

    /* from */
    sp = strtok(NULL, DELIMITER);

    if (strncmp(sp, FW_FROM, 4) != 0) {
        fprintf(stderr,
            "Error loading firewall rules, malformed rule: %s\n",
            line);
        return -1; 
    }

    /* <incoming IP block> */
    if ( parse_ip_block(strtok(NULL, DELIMITER), 
        &rule->src_addr, &rule->src_mask) == -1 )
        return -1;

    /* [<optional incoming port>] to */
    sp = strtok(NULL, DELIMITER);

    if (strcmp(sp, FW_TO) != 0) {
        i = atoi(sp);
        if (i < 1 || i > PORT_MAX) {
            fprintf(stderr, "Error loading firewall rules, incorrect port: %s\n", sp);
            return -1;
        }
        rule->src_port = i;

    } else
        rule->src_port = 0;

    /* <outgoing IP block> */
    if ( parse_ip_block(strtok(NULL, DELIMITER), 
        &rule->dst_addr, &rule->dst_mask) == -1 )
        return -1;


    rule->dst_port  = 0;
    rule->direction = BOTH;

    sp = strtok(NULL, DELIMITER);
    if (sp == NULL)
        return 0;

    /* [<optional outgoing port>] */
    i = atoi(sp);
    if (i < 1 || i > PORT_MAX) {
        fprintf(stderr, "Error loading firewall rules, incorrect port: %s\n", sp);
        return -1;
    }

    rule->dst_port = i;


    sp = strtok(NULL, DELIMITER);
    if (sp == NULL)
        return 0;

    /* [<optional direction>] */
    if (strncmp(sp, DIR_IN, 3) == 0)
        rule->direction = IN;

    else if (strncmp(sp, DIR_OUT, 3) == 0)
        rule->direction = OUT;

    else {
        fprintf(stderr,
            "Error loading firewall rules, cannot convert %s to valid direction.\n",
            sp);
        return -1; 
    }

    return 0;
}

void sr_print_fw_rule(sr_fw_rule_t *rule) {

    printf("FW Rule: action=%d, protocol=%d, direction=%d, src_addr=0x%x, src_mask=0x%x, src_port=%d, dst_addr=0x%x, dst_mask=0x%x, dst_port=%d\n",
        rule->action, rule->protocol, rule->direction, 
        ntohl(rule->src_addr), ntohl(rule->src_mask), rule->src_port, 
        ntohl(rule->dst_addr), ntohl(rule->dst_mask), rule->dst_port);

}

void sr_add_fw_rule(struct sr_fw* fw, 
    sr_fw_rule_t *rule /* lent */
    ) {

    sr_fw_rule_t *new_rule = malloc(sizeof(sr_fw_rule_t));
    memcpy(new_rule, rule, sizeof(sr_fw_rule_t));
    new_rule->next = NULL;

    /* Rule list is empty */
    if (fw->rules == NULL) {
        fw->rules = new_rule;
        return;
    }

    /* Add to end of list */
    sr_fw_rule_t *ptr = fw->rules;
    while (ptr->next != NULL)
        ptr = ptr->next;

    ptr->next = new_rule;
}

void sr_init_fw(struct sr_fw* fw) {
    fw->rules = NULL;
    fw->connections = NULL;
}

int sr_load_fw(struct sr_fw* fw, const char* filename) {

    FILE* fp;
    char  line[BUFSIZ];

    sr_fw_rule_t fw_rule;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while ( fgets(line,BUFSIZ,fp) != 0) {

        memset(&fw_rule, 0, sizeof(fw_rule));

        if ( sr_parse_fw_rule(line, &fw_rule) != -1 ) {
            sr_print_fw_rule(&fw_rule);
            sr_add_fw_rule(fw, &fw_rule);
        }

    } /* -- while -- */

    fclose(fp);

    return 0; /* -- success -- */
} /* -- sr_load_fw -- */

#define sr_match_netblock(host, net, mask) (( net & mask ) == ( host & mask ))

#define sr_match_bothdir(src, srcport, dst, dstport, src2, src2port, dst2, dst2port) ( (src==src2 && srcport==src2port && dst==dst2 && dstport==dst2port) || (src==dst2 && srcport==dst2port && dst==src2 && dstport==src2port) )


int sr_tcp_checksum(uint8_t * packet /* lent */,
    unsigned int len) {

    const int pseudo_pkt_len = sizeof(sr_tcp_pseudohdr_t) + 
        len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    uint8_t pseudo_pkt[pseudo_pkt_len];

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    sr_tcp_pseudohdr_t *phdr = (sr_tcp_pseudohdr_t *) pseudo_pkt;
    /* Fill in pseudo header for CRC calculation */
    phdr->ip_src = iphdr->ip_src;
    phdr->ip_dst = iphdr->ip_dst;
    phdr->reserved = 0;
    phdr->protocol = iphdr->ip_p;
    phdr->tcp_length = htons(len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    uint8_t *pdata_begin = pseudo_pkt + sizeof(sr_tcp_pseudohdr_t);
    uint8_t *data_begin = (uint8_t*)iphdr + sizeof(sr_ip_hdr_t);
    memcpy(pdata_begin, data_begin, ntohs(phdr->tcp_length));

    return cksum(pseudo_pkt, pseudo_pkt_len);
}

int sr_udp_checksum(uint8_t * packet /* lent */,
    unsigned int len) {

    const int pseudo_pkt_len = sizeof(sr_udp_pseudohdr_t) + 
        len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    uint8_t pseudo_pkt[pseudo_pkt_len];

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_udp_hdr_t *udphdr = (sr_udp_hdr_t *)((uint8_t*)iphdr + sizeof(sr_ip_hdr_t));

    sr_tcp_pseudohdr_t *phdr = (sr_tcp_pseudohdr_t *) pseudo_pkt;
    /* Fill in pseudo header for CRC calculation */
    phdr->ip_src = iphdr->ip_src;
    phdr->ip_dst = iphdr->ip_dst;
    phdr->reserved = 0;
    phdr->protocol = iphdr->ip_p;
    phdr->tcp_length = udphdr->length;

    uint8_t *pdata_begin = pseudo_pkt + sizeof(sr_udp_pseudohdr_t);
    uint8_t *data_begin = (uint8_t*)iphdr + sizeof(sr_ip_hdr_t);
    memcpy(pdata_begin, data_begin, ntohs(udphdr->length));

    return cksum(pseudo_pkt, pseudo_pkt_len);
}

/*
    Util function to extract src&dst ports from UDP/TCP packets,
    also verifies CRC checksum.

    ** tcp_seq_out, tcp_ack_out & tcp_flags_out only sets if the given packet is TCP.
*/
int sr_get_transport_details(uint8_t * packet /* lent */,
    unsigned int len,
    uint16_t *src_port_out,
    uint16_t *dst_port_out,
    uint8_t  *ip_proto_out,
    uint32_t *tcp_seq_out,
    uint32_t *tcp_ack_out,
    uint8_t  *tcp_flags_out
    ) {

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_tcp_hdr_t *tcphdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_udp_hdr_t *udphdr = (sr_udp_hdr_t *)(tcphdr);

    *ip_proto_out = iphdr->ip_p;

    switch ((sr_ip_protocol)iphdr->ip_p) {
    case ICMP:
        *src_port_out = *dst_port_out = 0;
        break;

    case TCP:
        if ( len < (sizeof(sr_tcp_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)) ) {
            fprintf(stderr, "sr_get_transport_details: Malformed TCP Header.\n");
            return 0;
        }
        
        if ( sr_tcp_checksum(packet, len) != 0xFFFF ) {
            fprintf(stderr, "sr_fw_match_connections: Incorrect TCP Header Checksum.\n");
            return 0;
        }

        *src_port_out = ntohs(tcphdr->src_port);
        *dst_port_out = ntohs(tcphdr->dst_port);
        *tcp_seq_out = ntohl(tcphdr->seq);
        *tcp_ack_out = ntohl(tcphdr->ack);
        *tcp_flags_out = tcphdr->flags;
        break;

    case UDP:
        if ( len < (sizeof(sr_udp_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)) ) {
            fprintf(stderr, "sr_get_transport_details: Malformed UDP Header.\n");
            return 0;
        }

        if ( sr_udp_checksum(packet, len) != 0xFFFF ) {
            fprintf(stderr, "sr_get_transport_details: Incorrect UDP Header Checksum.\n");
            return 0;
        }

        *src_port_out = ntohs(udphdr->src_port);
        *dst_port_out = ntohs(udphdr->dst_port);
        break;
    }

    fprintf(stderr, "sr_get_transport_details: src_port=%d, dst_port=%d\n", *src_port_out, *dst_port_out);

    return 1;
}

/**
    Match packet with current connections.
    Also remove connection entries if exprired, or
    update last seen time if matched.

    Returns 1 if match found, 0 otherwise.
*/
int sr_fw_match_connections(struct sr_fw * fw, 
    uint8_t protocol,
    uint32_t ip_src,
    uint32_t ip_dst,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t tcp_seq,
    uint32_t tcp_ack,
    uint8_t tcp_flags) {

    sr_connection_t *conn = fw->connections;
    if (conn == NULL)
        return 0;

    time_t currtime = time(NULL);

    sr_connection_t *prev = NULL;


    while (conn != NULL) {

        if ( difftime(currtime, conn->last_seen) > SR_FW_CONN_TIMEOUT ) {
            
            /* Timed out - Remove it */
            if (prev == NULL)
                fw->connections = conn->next;
            else
                prev->next = conn->next;

            free(conn);

            if (prev != NULL)
                conn = prev->next;
            else
                conn = NULL;

            continue;
        }

        if ( conn->protocol == protocol 
            && sr_match_bothdir(ip_src, src_port, ip_dst, dst_port, 
            conn->src_addr, conn->src_port, conn->dst_addr, conn->dst_port) ) {
            /*
            printf("sr_fw_match_connections: TCP Flags: ack=%x, fin=%x\n", (tcp_flags & MASK_ACK), (tcp_flags & MASK_FIN));
            printf("sr_fw_match_connections: TCP Flags: conn->last_fin_ack=%x, tcp_ack=%x\n", conn->last_fin_ack, tcp_ack);
            */
            if ( (tcp_flags & MASK_ACK) && !(tcp_flags & MASK_FIN) && 
                conn->last_fin_ack == tcp_ack-1 ) {
                /* ACK = 1, FIN = 0, Ack = last FIN+ACK */
                /* TCP FIN Detected: Remove connection */
                printf("sr_fw_match_connections: TCP FIN detected, remove connection and allow.\n");
                if (prev == NULL)
                    fw->connections = conn->next;
                else
                    prev->next = conn->next;

                free(conn);

                return 1;   /* Let this packet thorugh */
            }

            /* Record FIN+ACK seq for later use */
            if ( tcp_flags & MASK_FINACK == MASK_FINACK ) {
                printf("sr_fw_match_connections: TCP FIN+ACK detected.\n");
                conn->last_fin_ack = tcp_seq;
            }

            /*  We have a match - 
                Update last seen */
            conn->last_seen = currtime;
            /*  Move to front then return */

            if (prev != NULL) {
                prev->next = conn->next;
                conn->next = fw->connections;
                fw->connections = conn;
            }

            return 1;
        }

        prev = conn;
        conn = conn->next;
    }

    return 0;
}

void sr_fw_add_connection(struct sr_fw * fw, 
    uint8_t protocol,
    uint32_t ip_src,
    uint32_t ip_dst,
    uint16_t src_port,
    uint16_t dst_port) {

    /* Add connection to front */
    sr_connection_t *new_conn = calloc(1, sizeof(sr_connection_t));

    new_conn->protocol  = protocol;
    new_conn->src_addr  = ip_src;
    new_conn->src_port  = src_port;
    new_conn->dst_addr  = ip_dst;
    new_conn->dst_port  = dst_port;
    new_conn->last_fin_ack = 0;
    new_conn->last_seen = time(NULL);

    new_conn->next      = fw->connections;
    fw->connections     = new_conn;
}

/**
    Match packet with rule.
    Returns 1 if match, 0 otherwise.
*/
int sr_fw_match(sr_fw_rule_t * rule, /* lent */
    uint8_t protocol,
    uint32_t ip_src,
    uint32_t ip_dst,
    uint16_t src_port,
    uint16_t dst_port) {

    /* Check protocol */
    fprintf(stderr, "sr_fw_match: protocol 0x%x 0x%x\n", rule->protocol, protocol);
    if ( rule->protocol != protocol )
        return 0;

    /* Check source */
    fprintf(stderr, "sr_fw_match: 0x%x 0x%x 0x%x\n", ntohl(ip_src), ntohl(rule->src_addr), ntohl(rule->src_mask));
    if ( !sr_match_netblock(ip_src, rule->src_addr, rule->src_mask) )
        return 0;

    fprintf(stderr, "sr_fw_match: Src IP Matched.\n");

    fprintf(stderr, "sr_fw_match: 0x%x 0x%x 0x%x\n", ntohl(ip_dst), ntohl(rule->dst_addr), ntohl(rule->dst_mask));

    /* Check dest */
    if ( !sr_match_netblock(ip_dst, rule->dst_addr, rule->dst_mask) )
        return 0;

    fprintf(stderr, "sr_fw_match: Dst IP Matched.\n");

    fprintf(stderr, "sr_fw_match: %d %d %d %d\n", rule->src_port, src_port, rule->dst_port, dst_port);
    /* Check ports */
    if ( rule->src_port != 0 && rule->src_port != src_port )
        return 0;
    if ( rule->dst_port != 0 && rule->dst_port != dst_port )
        return 0;

    fprintf(stderr, "sr_fw_match: Ports matched!\n");

    return 1;
}

/**
    Inspect packet with firewall rules. 
    Returns 1 if pass, 0 if drop.
*/
sr_fw_action sr_fw_inspect(struct sr_fw* fw,
    uint8_t * packet /* lent */,
    unsigned int len) {

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* Always pass ICMP */
    if ( (sr_ip_protocol)iphdr->ip_p == ICMP )
        return ALLOW;

    uint8_t protocol = iphdr->ip_p;
    uint32_t ip_src  = iphdr->ip_src;
    uint32_t ip_dst  = iphdr->ip_dst;

    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_proto;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t  tcp_flags = 0;

    printf("sr_fw_inspect: begin\n");

    /* Attempt to get port from TCP/UDP Header, 
       also checks TCP/UDP Header checksum */
    if ( !sr_get_transport_details(packet, len, 
        &src_port, &dst_port, &ip_proto, &tcp_seq, &tcp_ack, &tcp_flags) )
        return DENY;   /* Unrecognized protocol - DENY */


    printf("sr_fw_inspect: src_port=%d, dst_port=%d\n", src_port, dst_port);

    /* Match current connections */
    if ( sr_fw_match_connections(fw, protocol, 
        ip_src, ip_dst, src_port, dst_port, tcp_seq, tcp_ack, tcp_flags) )
        return ALLOW;   /* Matched with current connection - ALLOWED */

        printf("sr_fw_inspect: Not matched with current connections.\n");

    /* New connection: Lookup rules */
    sr_fw_rule_t *rule = fw->rules;

    while (rule != NULL) {

        if ( sr_fw_match(rule, protocol, 
            ip_src, ip_dst, src_port, dst_port) ) {

            printf("sr_fw_inspect: rule matched: action=%d\n", rule->action);

            if (rule->action == ALLOW)  /* Add to connection list */
                sr_fw_add_connection(fw, protocol, 
                    ip_src, ip_dst, src_port, dst_port);

            return rule->action;
        }

        rule = rule->next;
    }

    printf("sr_fw_inspect: Not matched with any rules.\n");

    /* No matching rule: Assume DENY? */
    return DENY;
}

#endif

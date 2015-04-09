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
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Constant definitions according to ICMP, IP, and Ethernet practices */
enum {ICMP_ECHO_REQUEST = 8, ICMP_ECHO_REPLY = 0, ICMP_UNREACHABLE = 3, 
	  ICMP_TIME_EXCEEDED = 11, ICMP_NET = 0, ICMP_HOST = 1, 
	  ICMP_PORT = 3, ICMP_IP_HDR_LEN = 5, ICMP_DATAGRAM_LEN = 8, 
	  IP_MIN_LEN = 20, IP_TIME_TO_LIVE = 64, ETHER_BR_ADDR = 255};

static void send_packet(struct sr_instance *sr, uint8_t *packet, 
						unsigned int len, uint32_t ip, int sendicmp, 
						enum sr_ethertype type);
static void send_icmp(struct sr_instance *sr, uint8_t *packet, 
					  unsigned int len, uint8_t type, uint8_t code);
static void send_arpreq(struct sr_instance *sr, struct sr_arpreq *req);
static void send_arpreply(struct sr_instance *sr, sr_arp_hdr_t *arphdr, 
						  struct sr_if *iface);
static void handle_arp(struct sr_instance *sr, uint8_t *packet, 
					   char *iface);
static void handle_ip(struct sr_instance *sr, uint8_t *packet, 
					  char *iface, unsigned int len);

/*---------------------------------------------------------------------
 * Method: send_packet(struct sr_instance *sr, uint8_t *packet, 
 *					   unsigned int len, uint32_t ip, int sendicmp, 
 *					   enum sr_ethertype type)
 * Scope:  Internal
 *
 * Encapsulate an IP packet with an Ethernet header and send it, using 
 * ICMP to send a error message or generating an ARP request if 
 * appropriate.
 *
 *---------------------------------------------------------------------*/

static void send_packet(struct sr_instance *sr, uint8_t *packet, 
						unsigned int len, uint32_t ip, int sendicmp, 
						enum sr_ethertype type) {
    uint8_t *ethpacket;
    struct sr_arpentry *arpentry;
    sr_ethernet_hdr_t hdr;
    struct in_addr addr; 
    struct sr_if *interface;

	/* Search longest prefix match of IP address in routing table */
    addr.s_addr = ip;
    struct sr_rt *rt = sr_search_routing_entry(sr, addr);

	/* Send ICMP net unreachable if entry does not exist */
    if (rt == NULL) {
        if (sendicmp)
            send_icmp(sr, packet, len, ICMP_UNREACHABLE, ICMP_NET);
        return;
    }

	/* Look up IP address in ARP cache */
    interface = sr_get_interface(sr, rt->interface);
    arpentry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);

    if ((arpentry == NULL) && (type != ethertype_arp)) {
		struct sr_arpreq * arpreq;

        ethpacket = (uint8_t *) malloc(len);
        if (ethpacket == NULL) {
	    	exit(EXIT_FAILURE);
		}
		
		/* Queue an ARP request */
		memcpy((void *) ethpacket, (const void *) packet, len);
		arpreq = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, ethpacket, 
						     		  len, rt->interface);
		handle_arpreq(sr, arpreq);
    } else {
		/* Broadcast if it's an ARP request; set specific destination IP 
		   address otherwise */
		if ((type == ethertype_arp) && 
			(((struct sr_arp_hdr *) packet)->ar_op == htons(arp_op_request)))
	    	memset((void *) hdr.ether_dhost, ETHER_BR_ADDR, ETHER_ADDR_LEN);
		else 
	    	memcpy((void *) hdr.ether_dhost, 
				   (const void *) arpentry->mac, ETHER_ADDR_LEN);

		memcpy((void *) hdr.ether_shost, 
			   (const void *) interface->addr, ETHER_ADDR_LEN);
        hdr.ether_type = htons(type);

		/* Allocate memory for new packet with enough room for Ethernet 
		   header */
		ethpacket = (uint8_t *) malloc(len + sizeof(hdr));
        if (ethpacket == NULL) {
	    	exit(EXIT_FAILURE);
		}

		memcpy((void *) ethpacket, (const void *) &hdr, sizeof(hdr));
		memcpy((void *) (ethpacket + sizeof(hdr)), (const void *) packet,
						 len);

		/* Send Ethernet packet */
		sr_send_packet(sr, ethpacket, len + sizeof(hdr), rt->interface);
		free(ethpacket);
	}	
   	
	if (arpentry != NULL) free(arpentry);
}

/*---------------------------------------------------------------------
 * Method: send_icmp(struct sr_instance *sr, uint8_t *packet, 
 *					 unsigned int len, uint8_t type, uint8_t code)
 * Scope:  Internal
 *
 * Send an ICMP message of specified type and code.
 *
 *---------------------------------------------------------------------*/

static void send_icmp(struct sr_instance *sr, uint8_t *packet, 
					  unsigned int len, uint8_t type, uint8_t code) {
    uint8_t *newpacket;
    uint16_t newlen, icmplen;
    uint32_t dstip;
    sr_ip_hdr_t *oldIPhdr, *iphdr, newIPhdr;
    sr_icmp_hdr_t *pICMPhdr, ICMPhdr;
    struct sr_rt *rt;
    struct sr_if *interface;
    struct in_addr addr;
    
    if (type == ICMP_ECHO_REPLY) {
		/* Update IP header fields */
		oldIPhdr = (sr_ip_hdr_t *) packet;
		dstip = oldIPhdr->ip_src;
		oldIPhdr->ip_src = oldIPhdr->ip_dst;
		oldIPhdr->ip_dst = dstip;

		/* Update ICMP header fields */
		pICMPhdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ip_hdr_t));
		pICMPhdr->icmp_sum = 0;
		pICMPhdr->icmp_code = code;
		pICMPhdr->icmp_type = type;

		/* Allocate memory for a new IP packet */
		newlen = ntohs(oldIPhdr->ip_len);
		newpacket = (uint8_t *) malloc(newlen);
		if (newpacket == NULL) {
	    		exit(EXIT_FAILURE);
		}
		memcpy((void *) newpacket, (const void *) oldIPhdr, newlen);

		/* Calculate length of ICMP message */
		icmplen = newlen - ICMP_IP_HDR_LEN * 4;
   
    } else {
		/* Fill in ICMP header fields */
		ICMPhdr.icmp_type = type;
		ICMPhdr.icmp_code = code;
		ICMPhdr.icmp_sum = 0;

		/* Update IP header fields */
		oldIPhdr = (sr_ip_hdr_t *) packet;
		newIPhdr.ip_hl = ICMP_IP_HDR_LEN;
		newIPhdr.ip_v = 4;
		newIPhdr.ip_tos = 0;
	
		icmplen = oldIPhdr->ip_hl * 4 + ICMP_DATAGRAM_LEN 
				  + sizeof(sr_icmp_hdr_t) + 4;
		newlen = icmplen + ICMP_IP_HDR_LEN * 4;
		newIPhdr.ip_len = htons(newlen);

		newIPhdr.ip_id = oldIPhdr->ip_id;
		newIPhdr.ip_off = htons(IP_DF);
		newIPhdr.ip_ttl = IP_TIME_TO_LIVE;
		newIPhdr.ip_p = ip_protocol_icmp;
		newIPhdr.ip_sum = 0;
		newIPhdr.ip_dst = oldIPhdr->ip_src;
		dstip = oldIPhdr->ip_src;

		/* Search longest prefix match of IP address in routing table */
		addr.s_addr = newIPhdr.ip_dst;
		if ((rt = sr_search_routing_entry(sr, addr)) == NULL)
	    	return;
		interface = sr_get_interface(sr, rt->interface);

		/* Update source IP address depending on ICMP type */
        if ((type == ICMP_UNREACHABLE) && (code != ICMP_NET))
			newIPhdr.ip_src = oldIPhdr->ip_dst;
		else 
			newIPhdr.ip_src = interface->ip;

		/* Allocate memory for new IP packet with room for ICMP header */
		newpacket = (uint8_t *) malloc(newlen);
		if (newpacket == NULL) {
	   	 	exit(EXIT_FAILURE);
		}

		memcpy((void *) newpacket, (const void *) &newIPhdr, 
			   ICMP_IP_HDR_LEN * 4);
		memcpy((void *) (newpacket + ICMP_IP_HDR_LEN * 4), 
			   (const void *) &ICMPhdr, sizeof(sr_icmp_hdr_t) + 4);
		memcpy((void *) (newpacket + ICMP_IP_HDR_LEN * 4 + sizeof(sr_icmp_hdr_t) + 4), 
			   (const void *) oldIPhdr, oldIPhdr->ip_hl * 4 + ICMP_DATAGRAM_LEN);

		/* Recompute old IP header checksum */
		iphdr = (sr_ip_hdr_t *) (newpacket + ICMP_IP_HDR_LEN * 4 + sizeof(sr_icmp_hdr_t) + 4);
		iphdr->ip_sum = 0;
		iphdr->ip_sum = cksum((const void *) iphdr, oldIPhdr->ip_hl * 4);

    }

	/* Compute IP checksum */
	iphdr = (sr_ip_hdr_t *) newpacket;
	iphdr->ip_sum = 0;
	iphdr->ip_sum = cksum((const void *) iphdr, ICMP_IP_HDR_LEN * 4);

	/* Compute ICMP checksum */
	pICMPhdr = (sr_icmp_hdr_t *) (newpacket + ((sr_ip_hdr_t *) newpacket)->ip_hl * 4);
	pICMPhdr->icmp_sum = 0;
    pICMPhdr->icmp_sum = cksum((const void *) pICMPhdr, (int) icmplen);

	/* Send the new packet */
    send_packet(sr, newpacket, newlen, dstip, 0, ethertype_ip);
    free(newpacket);
}

/*---------------------------------------------------------------------
 * Method: send_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
 *
 * Scope:  Internal
 *
 * Send an ARP request with the appropriate header.
 *
 *---------------------------------------------------------------------*/

static void send_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    sr_arp_hdr_t hdr;
    struct sr_if* iface = sr_get_interface(sr, req->packets->iface);
    
	/* Fill in ARP header fields */
    hdr.ar_hrd = htons(arp_hrd_ethernet);
    hdr.ar_pro = htons(arp_pro_ip);
    hdr.ar_hln = ETHER_ADDR_LEN;
    hdr.ar_pln = sizeof(uint32_t);
    hdr.ar_op  = htons(arp_op_request);
    memcpy((void *) hdr.ar_sha, (const void *) iface->addr, 
		   ETHER_ADDR_LEN);
    hdr.ar_sip = iface->ip;
    hdr.ar_tip = req->ip;

	/* Send packet as ARP request */
    send_packet(sr, (uint8_t *) &hdr, sizeof(sr_arp_hdr_t), req->ip, 0, 
				ethertype_arp);
}

/*---------------------------------------------------------------------
 * Method: send_arpreply(struct sr_instance *sr, sr_arp_hdr_t *arphdr, 
 * 						 struct sr_if *iface)
 *
 * Scope:  Internal
 *
 * Send ARP reply to an ARP request.
 *
 *---------------------------------------------------------------------*/

static void send_arpreply(struct sr_instance *sr, sr_arp_hdr_t *arphdr, 
						  struct sr_if *iface) {
    sr_arp_hdr_t hdr;

	/* Fill in ARP header fields */    
    hdr.ar_hrd = htons(arp_hrd_ethernet);
    hdr.ar_pro = htons(arp_pro_ip);
    hdr.ar_hln = ETHER_ADDR_LEN;
    hdr.ar_pln = sizeof(uint32_t);
    hdr.ar_op  = htons(arp_op_reply);
    memcpy((void *) hdr.ar_sha, (const void *) iface->addr, 
		   ETHER_ADDR_LEN);
    hdr.ar_sip = iface->ip;
    memcpy((void *) hdr.ar_tha, (const void *) arphdr->ar_sha, 
		   ETHER_ADDR_LEN);
    hdr.ar_tip = arphdr->ar_sip;

	/* Send packet as ARP response */
    send_packet(sr, (uint8_t *) &hdr, sizeof(sr_arp_hdr_t), 
			 	arphdr->ar_sip, 1, ethertype_arp);
}

/*---------------------------------------------------------------------
 * Method: handle_arp(struct sr_instance *sr, uint8_t *packet, 
 * 					  char *iface)
 *
 * Scope:  Internal
 *
 * Handle an ARP packet received by the router.
 *
 *---------------------------------------------------------------------*/

static void handle_arp(struct sr_instance *sr, uint8_t *packet, 
					   char *iface) {
    struct sr_arpentry *arpentry;
    struct sr_if *interface = sr_get_interface(sr, iface);
    sr_arp_hdr_t *hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

	/* Check if the packet is destined for the router */
    if (hdr->ar_tip != interface->ip)
		return;
    
	/* Cache the ARP entry and forward any IP packets waiting on the entry */
    arpentry = sr_arpcache_lookup(&(sr->cache), hdr->ar_sip);
    if (arpentry != NULL) free(arpentry);
    else {
		struct sr_packet *pac;
		struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), 
													  hdr->ar_sha, hdr->ar_sip);
		if (arpreq != NULL) {
	    	for (pac = arpreq->packets; pac != NULL; pac = pac->next) {
				sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *) pac->buf;

				send_packet(sr, pac->buf, pac->len, iphdr->ip_dst, 1, 
							ethertype_ip);
	    	}
	    	sr_arpreq_destroy(&(sr->cache), arpreq);
		}
    }
   
	/* Reply to ARP request if appropriate */
    if (ntohs(hdr->ar_op) == arp_op_request)
		send_arpreply(sr, hdr, interface);
}

/*---------------------------------------------------------------------
 * Method: handle_ip(struct sr_instance *sr, uint8_t *packet, 
 * 					 char *iface, unsigned int len)
 *
 * Scope:  Internal
 *
 * Handle an IP packet received by the router.
 *
 *---------------------------------------------------------------------*/

static void handle_ip(struct sr_instance *sr, uint8_t *packet, 
					  char *iface, unsigned int len) {
    uint16_t sum;
	uint8_t *newpacket;
    struct sr_if *interface;
    sr_ip_hdr_t *hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Sanity check minimum length and checksum */
    if (len < IP_MIN_LEN) 
		return;
	
    sum = hdr->ip_sum;
    hdr->ip_sum = 0;
    if (sum != cksum((const void *) hdr, hdr->ip_hl * 4))
		return;

	
    /* If destined for one of router's IP interfaces... */
    for (interface = sr->if_list; interface != NULL; 
		 interface = interface->next) {
		if (interface->ip == hdr->ip_dst) {
	    	uint8_t protocol = ip_protocol((uint8_t *) hdr);
			
			/* Send appropriate ICMP messages depending on protocol */
			if (protocol == ip_protocol_icmp) {
				sr_icmp_hdr_t *icmphdr = (sr_icmp_hdr_t *) (packet 
										+ sizeof(sr_ethernet_hdr_t) 
										+ sizeof(sr_ip_hdr_t));
				if (icmphdr->icmp_type == ICMP_ECHO_REQUEST) {
		    		send_icmp(sr, (uint8_t *) hdr, ntohs(hdr->ip_len), 
							  ICMP_ECHO_REPLY, 0);
				}
	    	} else if ((protocol == ip_protocol_tcp) 
					   || (protocol == ip_protocol_udp)) {
				send_icmp(sr, (uint8_t *) hdr, ntohs(hdr->ip_len), 
						  ICMP_UNREACHABLE, ICMP_PORT);
	    	}
	    	return;
		}
    }

	/* Decrement TTL and recompute checksum */
    hdr->ip_ttl--;
	if (hdr->ip_ttl == 0) {
		hdr->ip_ttl++;
		send_icmp(sr, (uint8_t *) hdr, ntohs(hdr->ip_len), 
				  ICMP_TIME_EXCEEDED, 0);
    } else {
		hdr->ip_sum = 0;
    	hdr->ip_sum = cksum((const void *) hdr, hdr->ip_hl * 4);
	 
    	/* Forward IP packet */
    	newpacket = (uint8_t *) malloc(len);
		if (newpacket == NULL) {
    		exit(EXIT_FAILURE);
		}
	
		memcpy((void *) newpacket, (const void *) hdr, len);

		send_packet(sr, newpacket, len, hdr->ip_dst, 1, ethertype_ip);
		free(newpacket);
	}
}

/*---------------------------------------------------------------------
 * Method: handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req)
 *
 * Scope:  Global
 *
 * Handle sending ARP requests from the queue. An ARP request is sent 
 * to a target IP address about once every second until a reply comes 
 * in. If the ARP request is sent five times with no reply, an ICMP 
 * destination host unreachable is sent back to the source IP.
 *
 *---------------------------------------------------------------------*/

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t now = time(NULL);
    if (difftime(now, req->sent) > 1.0) {
        if (req->times_sent >= 5) {
	    	struct sr_packet *pac;
    		for (pac = req->packets; pac != NULL; pac = pac->next) {
	        	send_icmp(sr, pac->buf, pac->len, ICMP_UNREACHABLE, 
						  ICMP_HOST);
        	}
	    	sr_arpreq_destroy(&(sr->cache), req);
		} else {
	    	send_arpreq(sr, req);
	    	req->sent = now;
	    	req->times_sent++;
		}
    }
}

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
    
    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  	/* REQUIRES */
  	assert(sr);
  	assert(packet);
  	assert(interface);

  	/* Checks ethertype and handles packet accordingly */
  	if (ethertype(packet) == ethertype_arp) {
      	handle_arp(sr, packet, interface);
  	} else if (ethertype(packet) == ethertype_ip) {
 		handle_ip(sr, packet, interface, len);
	}
}/* -- sr_handlepacket -- */

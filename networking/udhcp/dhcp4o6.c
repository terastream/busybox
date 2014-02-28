/* vi: set sw=4 ts=4: */
/*
 * DHCPv4o6 utils.
 *
 * Some functions copied & modified from d6_dhcpc.c
 * Using d6_packet.c and d6_socket.c
 *
 * Copyright (C) FIXME.
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */


#include <syslog.h>
#include "common.h"
#include "dhcpd.h"
#include "dhcpc.h"
#include "dhcp4o6.h"

#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <linux/filter.h>


/*** Utility functions borrowed from d6_dhcpc.c ***/
static void *d6_find_option(uint8_t *option, uint8_t *option_end, unsigned code);
static void *d6_store_blob(void *dst, const void *src, unsigned len);
static uint8_t *init_d6_packet(struct d6_packet *packet, char type, uint32_t xid);
static uint8_t *add_d6_client_options(uint8_t *ptr);
static NOINLINE int d6_recv_raw_packet(struct d6_packet *d6_pkt, int fd);
static int d6_raw_socket(int ifindex);

/*** Utility functions borrowed from d6_dhcpc.c ***/
static void *d6_find_option(uint8_t *option, uint8_t *option_end, unsigned code)
{
#if 0
	/* "length minus 4" */
	int len_m4 = option_end - option - 4;
	while (len_m4 >= 0) {
		/* Next option's len is too big? */
		if (option[3] > len_m4)
			return NULL; /* yes. bogus packet! */
		/* So far we treat any opts with code >255
		 * or len >255 as bogus, and stop at once.
		 * This simplifies big-endian handling.
		 */
		if (option[0] != 0 || option[2] != 0)
			return NULL;
		/* Option seems to be valid */
		/* Does its code match? */
		if (option[1] == code)
			return option; /* yes! */
		option += option[3] + 4;
		len_m4 -= option[3] + 4;
	}
#else
	/* D6_OPT_DHCPV4_MSG option is larger than 255 since whole DHCPv4
	 * packet is in it, so the above assumptions are not valid */
	unsigned opt_len, opt_code;
	while (option < option_end) {
		opt_len =  (option[2]<<8) + option[3];
		opt_code = (option[0]<<8) + option[1];
		if (option + 4 + opt_len > option_end)
			return NULL; /* option not found */
		/* Does its code match? */
		if (opt_code == code)
			return option; /* yes! */
		option += opt_len;
	}
#endif
	return NULL;
}

static void *d6_store_blob(void *dst, const void *src, unsigned len)
{
	memcpy(dst, src, len);
	return dst + len;
}


/*** Sending/receiving packets ***/

/* Initialize the packet with the proper defaults */
static uint8_t *init_d6_packet(struct d6_packet *packet, char type, uint32_t xid)
{
	struct d6_option *clientid;

	memset(packet, 0, sizeof(*packet));

	packet->d6_xid32 = xid;
	packet->d6_msg_type = type;

	clientid = (void*)client_config.clientid;
	return d6_store_blob(packet->d6_options, clientid, clientid->len + 2+2);
}

static uint8_t *add_d6_client_options(uint8_t *ptr)
{
	return ptr;
	//uint8_t c;
	//int i, end, len;

	/* Add a "param req" option with the list of options we'd like to have
	 * from stubborn DHCP servers. Pull the data from the struct in common.c.
	 * No bounds checking because it goes towards the head of the packet. */
	//...

	/* Add -x options if any */
	//...
}

/* Returns -1 on errors that are fatal for the socket, -2 for those that aren't */
/* NOINLINE: limit stack usage in caller */
static NOINLINE int d6_recv_raw_packet(struct d6_packet *d6_pkt, int fd)
{
	int bytes;
	struct ip6_udp_d6_packet packet;

	bytes = safe_read(fd, &packet, sizeof(packet));
	if (bytes < 0) {
		log1("Packet read error, ignoring");
		/* NB: possible down interface, etc. Caller should pause. */
		return bytes; /* returns -1 */
	}

	if (bytes < (int) (sizeof(packet.ip6) + sizeof(packet.udp))) {
		log1("Packet is too short, ignoring");
		return -2;
	}

	if (bytes < sizeof(packet.ip6) + ntohs(packet.ip6.ip6_plen)) {
		/* packet is bigger than sizeof(packet), we did partial read */
		log1("Oversized packet, ignoring");
		return -2;
	}

	/* ignore any extra garbage bytes */
	bytes = sizeof(packet.ip6) + ntohs(packet.ip6.ip6_plen);

	/* make sure its the right packet for us, and that it passes sanity checks */
	if (packet.ip6.ip6_nxt != IPPROTO_UDP
	 || (packet.ip6.ip6_vfc >> 4) != 6
	 || packet.udp.dest != htons(CLIENT_PORT6)
	/* || bytes > (int) sizeof(packet) - can't happen */
	 || packet.udp.len != packet.ip6.ip6_plen
	) {
		log1("Unrelated/bogus packet, ignoring");
		return -2;
	}

//How to do this for ipv6?
//	/* verify UDP checksum. IP header has to be modified for this */
//	memset(&packet.ip, 0, offsetof(struct iphdr, protocol));
//	/* ip.xx fields which are not memset: protocol, check, saddr, daddr */
//	packet.ip.tot_len = packet.udp.len; /* yes, this is needed */
//	check = packet.udp.check;
//	packet.udp.check = 0;
//	if (check && check != inet_cksum((uint16_t *)&packet, bytes)) {
//		log1("Packet with bad UDP checksum received, ignoring");
//		return -2;
//	}

	log1("Received a packet");
	d6_dump_packet(&packet.data);

	bytes -= sizeof(packet.ip6) + sizeof(packet.udp);
	memcpy(d6_pkt, &packet.data, bytes);

	/* save DHCPv6 server address, for possible future usage by client */
	dhcp4o6_data.dst_ip = packet.ip6.ip6_src;
	/* FIXME is this required? */

	return bytes;
}


#define LISTEN_NONE   0
#define LISTEN_KERNEL 1
#define LISTEN_RAW    2


static int d6_raw_socket(int ifindex)
{
	int fd;
	struct sockaddr_ll sock;

	/*
	 * Comment:
	 *
	 *	I've selected not to see LL header, so BPF doesn't see it, too.
	 *	The filter may also pass non-IP and non-ARP packets, but we do
	 *	a more complete check when receiving the message in userspace.
	 *
	 * and filter shamelessly stolen from:
	 *
	 *	http://www.flamewarmaster.de/software/dhcpclient/
	 *
	 * There are a few other interesting ideas on that page (look under
	 * "Motivation").  Use of netlink events is most interesting.  Think
	 * of various network servers listening for events and reconfiguring.
	 * That would obsolete sending HUP signals and/or make use of restarts.
	 *
	 * Copyright: 2006, 2007 Stefan Rompf <sux@loplof.de>.
	 * License: GPL v2.
	 *
	 * TODO: make conditional?
	 */
#if 1
	static const struct sock_filter filter_instr[] = {
		/* load 9th byte (protocol) */
		BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 9),
		/* jump to L1 if it is IPPROTO_UDP, else to L4 */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, IPPROTO_UDP, 0, 6),
		/* L1: load halfword from offset 6 (flags and frag offset) */
		BPF_STMT(BPF_LD|BPF_H|BPF_ABS, 6),
		/* jump to L4 if any bits in frag offset field are set, else to L2 */
		BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x1fff, 4, 0),
		/* L2: skip IP header (load index reg with header len) */
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0),
		/* load udp destination port from halfword[header_len + 2] */
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 2),
		/* jump to L3 if udp dport is CLIENT_PORT6, else to L4 */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 68, 0, 1),
		/* L3: accept packet */
		BPF_STMT(BPF_RET|BPF_K, 0x7fffffff),
		/* L4: discard packet */
		BPF_STMT(BPF_RET|BPF_K, 0),
	};
	static const struct sock_fprog filter_prog = {
		.len = sizeof(filter_instr) / sizeof(filter_instr[0]),
		/* casting const away: */
		.filter = (struct sock_filter *) filter_instr,
	};
#endif

	log1("Opening raw socket on ifindex %d", ifindex); //log2?

	fd = xsocket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
	log1("Got raw socket fd %d", fd); //log2?

	sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_IPV6);
	sock.sll_ifindex = ifindex;
	xbind(fd, (struct sockaddr *) &sock, sizeof(sock));

#if 1
	if (CLIENT_PORT6 == 546) {
		/* Use only if standard port is in use */
		/* Ignoring error (kernel may lack support for this) */
		if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog,
				sizeof(filter_prog)) >= 0)
			log1("Attached filter to raw socket fd %d", fd); // log?
		else
			log1("Error attaching filter to raw socket fd %d", fd);
	}
#endif

	log1("Created raw socket");

	return fd;
}


/*** DHCP4o6 utility functions ***/

/* init dhcp4o6 data structure */
int dhcp4o6_init (int port, char *str_6d)
{
	struct in6_addr ip6;

	memset ( &dhcp4o6_data.dst_ip, 0, 16 );
	memset ( &dhcp4o6_data.src_ip, 0, 16 );

	if (port) {
		dhcp4o6_data.src_port = CLIENT_PORT;
		dhcp4o6_data.dst_port = CLIENT_PORT+1;
	}
	else {
		dhcp4o6_data.src_port = 546;
		dhcp4o6_data.dst_port = 547;
	}

	if (str_6d && inet_pton(AF_INET6, str_6d, &ip6) > 0) {
		dhcp4o6_data.dst_ip = ip6;
	}
	else {
#if 0	/* this should be activated (by rfc & draft)! */
		bb_error_msg_and_die("bad IPv6 address for DHCP4o6 server '%s'", str_6d);
#else
		/* server address = multicast address = FF02__1_2 */
		dhcp4o6_data.dst_ip.s6_addr[0] = 0xFF;
		dhcp4o6_data.dst_ip.s6_addr[1] = 0x02;
		dhcp4o6_data.dst_ip.s6_addr[13] = 0x01;
		dhcp4o6_data.dst_ip.s6_addr[15] = 0x02;
#endif
	}

	//FIXME choose between SOCKET_RAW and SOCKET_KERNEL with additional flag!
	dhcp4o6_data.socket_mode = SOCKET_RAW;

	return 0;
}

int dhcp4o6_open_socket(int mode UNUSED_PARAM)
{
	int sockfd6 = -1;

	if ( dhcp4o6_data.socket_mode == SOCKET_RAW )
		sockfd6 = d6_raw_socket(client_config.ifindex);
	else if ( dhcp4o6_data.socket_mode == SOCKET_KERNEL )
		sockfd6 = d6_listen_socket(dhcp4o6_data.src_port,
						client_config.interface);
	/* else LISTEN_NONE: sockfd stays closed */

	return sockfd6;
}

static int dhcp4o6_get_dhcpv4_from_dhcpv6 (
	struct d6_packet *d6_pkt, struct dhcp_packet *d4_pkt)
{
	uint8_t *d6opt;
	int opt_len;

	/* check DHCPv6 packet in d6_pkt */

	if ( d6_pkt->d6_msg_type != D6_MSG_DHCPV4_RESPONSE ) {
		log1("Packet is not of D6_MSG_DHCPV4_RESPONSE type");
		return -1;
	}

	d6opt = d6_find_option ( d6_pkt->d6_options, (void *) (d6_pkt+1), D6_OPT_DHCPV4_MSG );
	if ( ! d6opt ) {
		log1("D6_OPT_DHCPV4_MSG option not found");
		return -1;
	}
	/* D6_OPT_DHCPV4_MSG must be first option? Where is that defined? FIXME */

	opt_len = (d6opt[2]<<8) + d6opt[3];
	if ( opt_len < DHCP_SIZE - DHCP_OPTIONS_BUFSIZE ) {
		log1("D6_OPT_DHCPV4_MSG option too small");
		return -1;
	}

	/* extract dhcpv4 packet from dhcpv6 option */
	memcpy ( d4_pkt, d6opt + 4, opt_len );

	return opt_len;
}

int dhcp4o6_recv_packet (struct dhcp_packet *packet4, int fd)
{
	struct d6_packet packet6;
	int ret;

	if (dhcp4o6_data.socket_mode == SOCKET_RAW)
		ret = d6_recv_raw_packet(&packet6, fd);
	else if (dhcp4o6_data.socket_mode == SOCKET_KERNEL)
		ret = d6_recv_kernel_packet(NULL, &packet6, fd);
	else
		return -1;

	if ( ret < 0 )
		return -1;

	ret = dhcp4o6_get_dhcpv4_from_dhcpv6 (&packet6, packet4);
	if ( ret < 0 )
		return 0;
	else
		return ret;
}

int dhcp4o6_send_packet (struct dhcp_packet *packet4, int bcast )
{
	struct d6_packet packet6; /* is sizeof(struct d6_packet) large enough? */
	uint d4size, d6size;
	struct d6_option *opt;
	uint32_t flags;

	/* asemble DHCPv6 packet */

	if ( bcast )
		flags = 0;
	else
		flags = htonl(0x00800000); /* unicast flag */

	d4size = offsetof(struct dhcp_packet, options) +
			udhcp_end_option (packet4->options);

	/* create DHCPv6 packet of type D6_MSG_DHCPV4_QUERY */
	opt = (void *) init_d6_packet ( &packet6, D6_MSG_DHCPV4_QUERY, flags );

	/* content of DHCPv6 packet is option D6_OPT_DHCPV4_MSG with DHCPv4 packet */
	opt->code_hi = 0;
	opt->code = D6_OPT_DHCPV4_MSG;
	opt->len_hi = d4size >> 8;
	opt->len = d4size & 0x00ff;
	memcpy ( opt->data, packet4, d4size );

	d6size = 32 + 32 + d4size; /* d6 header + option header + d4 packet */

	/* send packet */
	if (dhcp4o6_data.socket_mode == SOCKET_RAW)
		return d6_send_raw_packet(
			&packet6, d6size,
			/*src*/ NULL, dhcp4o6_data.src_port, /* FIXME: can we get source ipv6? */
			/*dst*/ &dhcp4o6_data.dst_ip, dhcp4o6_data.dst_port,
			MAC_BCAST_ADDR, client_config.ifindex
		);
	else if (dhcp4o6_data.socket_mode == SOCKET_KERNEL)
		return d6_send_kernel_packet(
			&packet6, d6size,
			/*src*/ &dhcp4o6_data.src_ip, dhcp4o6_data.src_port,
			/*dst*/ &dhcp4o6_data.dst_ip, dhcp4o6_data.dst_port
		);
	else {
		log1("Socket mode in DHCP4o6 not defined");
		return -1;
	}
}

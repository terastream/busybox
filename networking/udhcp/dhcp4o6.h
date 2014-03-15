/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) (FIXME).
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
#ifndef DHCP4o6_H
#define DHCP4o6_H 1

#if ENABLE_FEATURE_DHCP4o6C

#include "d6_common.h"

PUSH_AND_SET_FUNCTION_VISIBILITY_TO_HIDDEN

/* Option HDCP4o6 may be compiled but not used; set and check following flags */
#define MODE4o6_ON           1
#define MODE4o6_UNICAST      2
#define MODE4o6_RAW_MODE     4
#define MODE4o6_KERNEL_MODE  8

/* DHCPv4o6 message types */
#define D6_MSG_DHCPV4_QUERY        32
#define D6_MSG_DHCPV4_RESPONSE     33

/* DHCPv4o6 option */
#define D6_OPT_DHCPV4_MSG          0xfe

/* send/recv/listen modes */
#define SOCKET_NONE   0
#define SOCKET_KERNEL 1
#define SOCKET_RAW    2


struct dhcp4o6_data_t {
	/* our IPv6 address & port */
	struct in6_addr src_ip;
	uint16_t src_port;

	/* peer IPv6 address & port */
	struct in6_addr dst_ip;
	uint16_t dst_port;

	unsigned socket_mode; /* SOCKET_RAW, SOCKET_KERNEL */
};

/* dhcp4o6_data is placed at the end of bb_common_bufsiz1 */
#define dhcp4o6_data (*(struct dhcp4o6_data_t*)(&bb_common_bufsiz1[COMMON_BUFSIZE - sizeof(struct dhcp4o6_data_t)]))


int dhcp4o6_init (int port, char *cip6, char *sip6);
int dhcp4o6_open_socket(int mode UNUSED_PARAM);
int dhcp4o6_send_packet (struct dhcp_packet *packet4, int bcast );
int dhcp4o6_recv_packet (struct dhcp_packet *packet, int fd);

POP_SAVED_FUNCTION_VISIBILITY

#endif /* ENABLE_FEATURE_DHCP4o6C */
#endif /* DHCP4o6_H */

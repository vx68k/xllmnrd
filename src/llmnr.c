/*
 * LLMNR functions.
 * Copyright (C) 2013  Kaz Sasa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "llmnr.h"

#include <netinet/in.h>
#include <sys/socket.h>

static const struct in6_addr in6addr_llmnr = {
    {
        {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3}
    }
};

int llmnr_new_udp_socket(void) {
    int udp_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket != -1) {
        struct sockaddr_in6 sin6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(LLMNR_PORT),
            .sin6_addr = in6addr_any,
        };
        if (bind(udp_socket, (struct sockaddr*)&sin6, sizeof sin6) == 0) {

            struct ipv6_mreq ipv6mr = {
                .ipv6mr_multiaddr = in6addr_llmnr,
            };
            int recvpktinfo = 1;
            if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                    &ipv6mr, sizeof ipv6mr) == 0 &&
                setsockopt(udp_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                    &recvpktinfo, sizeof recvpktinfo) == 0) {

                int unicast_hops = 1;
                setsockopt(udp_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &unicast_hops, sizeof unicast_hops);

#if 0
#ifdef IP_ADD_MEMBERSHIP
                struct ip_mreq imr;
                imr.imr_multiaddr.s_addr = htonl((in_addr_t)0xe00000fc);
                imr.imr_interface.s_addr = htonl(INADDR_ANY);
                setsockopt(udp_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                    &imr, sizeof imr);
#endif
#endif

                return udp_socket;
            }
        }

        close(udp_socket);
    }
    return -1;
}

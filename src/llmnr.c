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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#define _GNU_SOURCE 1

#include "llmnr.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

static const struct in6_addr in6addr_llmnr = {
    .s6_addr = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3}
};

struct llmnr_responder {
    int udp_socket;
};

static int llmnr_decode_cmsg(struct msghdr *, struct in6_pktinfo **);

int llmnr_responder_create(llmnr_responder_t *responder) {
    struct llmnr_responder *obj =
        malloc(sizeof(struct llmnr_responder));
    if (obj) {
        *obj = (struct llmnr_responder) {
            .udp_socket = llmnr_open_udp_socket(),
        };
        if (obj->udp_socket >= 0) {
            *responder = obj;
            return 0;
        }
        
        free(obj);
    }
    return -1;
}

int llmnr_responder_delete(llmnr_responder_t responder) {
    if (responder) {
        close(responder->udp_socket);
        free(responder);
        return 0;
    }
    
    errno = EINVAL;
    return -1;
}

int llmnr_responder_run(llmnr_responder_t responder) {
    for (;;) {
        struct sockaddr_in6 from;
        unsigned char packet[1500];
        unsigned char control[128];
        struct iovec iov[1] = {
            {
                .iov_base = packet,
                .iov_len = sizeof packet,
            },
        };
        struct msghdr msg = {
            .msg_name = &from,
            .msg_namelen = sizeof from,
            .msg_iov = iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = sizeof control,
        };
        if (recvmsg(responder->udp_socket, &msg, 0) >= 0) {
            struct in6_pktinfo *ipi6 = 0;
            llmnr_decode_cmsg(&msg, &ipi6);
            if (ipi6) {
                char addrbuf[INET6_ADDRSTRLEN];
                char ifnamebuf[IF_NAMESIZE];
                syslog(LOG_DEBUG, "Received packet to %s on %s",
                        inet_ntop(AF_INET6, &ipi6->ipi6_addr, addrbuf,
                        INET6_ADDRSTRLEN),
                        if_indextoname(ipi6->ipi6_ifindex, ifnamebuf));
            }
        }
    }
    
    return 0;
}

int llmnr_decode_cmsg(struct msghdr *msg, struct in6_pktinfo **ipi6) {
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
            cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6) {
            if (cmsg->cmsg_type == IPV6_PKTINFO &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof **ipi6)) {
                *ipi6 = (struct in6_pktinfo*)CMSG_DATA(cmsg);
            }
        }
    }

    return 0;
}

int llmnr_open_udp_socket(void) {
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

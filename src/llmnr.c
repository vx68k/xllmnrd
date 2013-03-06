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

#include "llmnr_header.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>

static const struct in6_addr in6addr_llmnr = {
    .s6_addr = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3}
};

static int responder_udp_socket = -1;

static ssize_t llmnr_receive_udp6(int, void *, size_t,
        struct sockaddr_in6 *, struct in6_pktinfo *);
static int llmnr_decode_cmsg(struct msghdr *, struct in6_pktinfo *);

int llmnr_responder_initialize(void) {
    if (responder_udp_socket >= 0) {
        errno = EPERM;
        return -1;
    }

    responder_udp_socket = llmnr_open_udp_socket();
    if (responder_udp_socket >= 0) {
        return 0;
    }
    return -1;
}

void llmnr_responder_finalize(void) {
    if (responder_udp_socket >= 0) {
        close(responder_udp_socket);
        responder_udp_socket = -1;
    }
}

int llmnr_responder_run(void) {
    for (;;) {
        unsigned char packetbuf[1500];
        struct sockaddr_in6 sender;
        struct in6_pktinfo pktinfo;
        ssize_t recv_size = llmnr_receive_udp6(responder_udp_socket,
                packetbuf, sizeof packetbuf, &sender, &pktinfo);
        if (recv_size >= 0) {
            if (IN6_IS_ADDR_MULTICAST(&pktinfo.ipi6_addr)) {
                struct llmnr_header *header =
                        (struct llmnr_header *)packetbuf;
                if ((size_t)recv_size >= sizeof *header &&
                        llmnr_header_is_valid_query(header)) {
                    char ifname[IF_NAMESIZE];
                    if_indextoname(pktinfo.ipi6_ifindex, ifname);
                    syslog(LOG_DEBUG, "Received query on %s", ifname);

                    /* TODO: Handle the query.  */
                } else {
                    char addrstr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &sender.sin6_addr, addrstr,
                            INET6_ADDRSTRLEN);
                    syslog(LOG_INFO,
                            "Invalid packet from %s%%%" PRIu32
                            " (discarded)",
                            addrstr, sender.sin6_scope_id);
                }
            } else {
                char addrstr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &sender.sin6_addr, addrstr,
                        INET6_ADDRSTRLEN);
                syslog(LOG_INFO,
                        "Non-multicast packet from %s%%%" PRIu32
                        " (discarded)",
                        addrstr, sender.sin6_scope_id);
            }
        }
    }

    return 0;
}

int llmnr_receive_udp6(int sock, void *restrict buf, size_t bufsize,
        struct sockaddr_in6 *restrict sender,
        struct in6_pktinfo *restrict pktinfo) {
    struct iovec iov[1] = {
        {
            .iov_base = buf,
            .iov_len = bufsize,
        },
    };
    unsigned char cmsgbuf[128];
    struct msghdr msg = {
        .msg_name = sender,
        .msg_namelen = sizeof *sender,
        .msg_iov = iov,
        .msg_iovlen = 1,
        .msg_control = cmsgbuf,
        .msg_controllen = sizeof cmsgbuf,
    };
    ssize_t recv_size = recvmsg(sock, &msg, 0);
    if (recv_size > 0) {
        if (msg.msg_namelen != sizeof *sender ||
                llmnr_decode_cmsg(&msg, pktinfo) < 0) {
            errno = ENOMSG;
            return -1;
        }
    }
    return recv_size;
}

int llmnr_decode_cmsg(struct msghdr *restrict msg,
        struct in6_pktinfo *restrict pktinfo) {
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
            cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6) {
            if (cmsg->cmsg_type == IPV6_PKTINFO &&
                    cmsg->cmsg_len >= CMSG_LEN(sizeof *pktinfo)) {
                memcpy(pktinfo, CMSG_DATA(cmsg), sizeof *pktinfo);
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

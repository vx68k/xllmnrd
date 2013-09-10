/*
 * LLMNR responder (implementation)
 * Copyright (C) 2013  Kaz Nishimura
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif
#define _GNU_SOURCE 1

#include "llmnr_responder.h"

#include "ifaddr.h"
#include "llmnr_header.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>

static const struct in6_addr in6addr_llmnr = {
    .s6_addr = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3}
};

static int responder_udp_socket = -1;

static int llmnr_open_udp_socket(void);
static ssize_t llmnr_receive_udp6(int, void *, size_t,
        struct sockaddr_in6 *, struct in6_pktinfo *);
static int llmnr_decode_cmsg(struct msghdr *, struct in6_pktinfo *);

static volatile sig_atomic_t responder_terminated;

/*
 * Logs a discarded packet with the sender address.
 */
static inline void log_discarded(const char *restrict message,
        const struct sockaddr_in6 *restrict sender) {
    if (sender && sender->sin6_family == AF_INET6) {
        char addrstr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sender->sin6_addr, addrstr,
                INET6_ADDRSTRLEN);
        syslog(LOG_INFO,
                "%s from %s%%%" PRIu32 " (discarded)", message, addrstr,
                sender->sin6_scope_id);
    } else {
        syslog(LOG_INFO, "%s (discarded)", message);
    }
}

int llmnr_responder_initialize(void) {
    if (responder_udp_socket >= 0) {
        errno = EPERM;
        return -1;
    }

    int udp = llmnr_open_udp_socket();
    if (udp >= 0) {
        responder_udp_socket = udp;
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
    while (!responder_terminated) {
        unsigned char packetbuf[1500];
        struct sockaddr_in6 sender;
        struct in6_pktinfo pktinfo;
        ssize_t recv_size = llmnr_receive_udp6(responder_udp_socket,
                packetbuf, sizeof packetbuf, &sender, &pktinfo);
        if (recv_size >= 0) {
            if (IN6_IS_ADDR_MULTICAST(&pktinfo.ipi6_addr)) {
                struct llmnr_header *header =
                        (struct llmnr_header *) packetbuf;
                if ((size_t) recv_size >= sizeof *header &&
                        llmnr_header_is_valid_query(header)) {
                    char ifname[IF_NAMESIZE];
                    if_indextoname(pktinfo.ipi6_ifindex, ifname);
                    syslog(LOG_DEBUG, "Received query on %s", ifname);

                    /* TODO: Handle the query.  */
                } else {
                    log_discarded("Invalid packet", &sender);
                }
            } else {
                log_discarded("Non-multicast packet", &sender);
            }
        }
    }
    responder_terminated = false;

    return 0;
}

void llmnr_responder_terminate(void) {
    responder_terminated = true;
}

int llmnr_open_udp_socket(void) {
    int udp_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket >= 0) {
        const struct ipv6_mreq mreq = {
            .ipv6mr_multiaddr = in6addr_llmnr,
        };
        const int v6only = 1;
        const int recvpktinfo = 1;
        if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                &mreq, sizeof mreq) == 0 &&
                setsockopt(udp_socket, IPPROTO_IPV6, IPV6_V6ONLY,
                &v6only, sizeof v6only) == 0 &&
                setsockopt(udp_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                &recvpktinfo, sizeof recvpktinfo) == 0) {
            const int unicast_hops = 1;
            if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &unicast_hops, sizeof unicast_hops) != 0) {
                // Not fatal.
                syslog(LOG_WARNING,
                        "setsockopt IPV6_UNICAST_HOPS=%d failed: %m",
                        unicast_hops);
            }

            const struct sockaddr_in6 addr = {
                .sin6_family = AF_INET6,
                .sin6_port = htons(LLMNR_PORT),
                .sin6_addr = in6addr_any,
            };
            if (bind(udp_socket, (const void *) &addr, sizeof addr) == 0) {
                return udp_socket;
            }
        }

        int saved_errno = errno;
        close(udp_socket);
        errno = saved_errno;
    }
    return -1;
}

ssize_t llmnr_receive_udp6(int sock, void *restrict buf, size_t bufsize,
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

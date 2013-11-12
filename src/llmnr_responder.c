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
#include <config.h>
#endif
#define _GNU_SOURCE 1

#include "llmnr_responder.h"

#include "ifaddr.h"
#include "llmnr_header.h"
#include <arpa/inet.h> /* inet_ntop */
#include <netinet/in.h>
#include <net/if.h> /* if_indextoname */
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>

#ifndef IN6ADDR_LLMNR_INIT
#define IN6ADDR_LLMNR_INIT { \
    .s6_addr = {0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3} \
}
#endif

static const struct in6_addr in6addr_llmnr = IN6ADDR_LLMNR_INIT;

/**
 * Sets socket options for an IPv6 UDP responder socket.
 * @param fd file descriptor of a socket.
 * @return 0 on success, or non-zero error number.
 */
static inline int set_options_udp6(int fd) {
    // We are not interested in IPv4 packets.
    static const int v6only = true;
    // We want the interface index for each received datagram.
    static const int rcvpktinfo = true;
    // The unicast hop limit SHOULD be 1.
    static const int unicast_hops = 1;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
            sizeof (int)) != 0) {
        return errno;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &rcvpktinfo,
            sizeof (int)) != 0) {
        return errno;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &unicast_hops,
            sizeof (int)) != 0) {
        syslog(LOG_WARNING,
                "Could not set IPV6_UNICAST_HOPS to %d: %s",
                unicast_hops, strerror(errno));
    }

    // TODO: Joining must be done later for each interface.
    const struct ipv6_mreq mr = {
        .ipv6mr_multiaddr = in6addr_llmnr,
        .ipv6mr_interface = 0,
    };
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr,
            sizeof (struct ipv6_mreq)) < 0) {
        return errno;
    }

    return 0;
}

/**
 * Opens an IPv6 UDP responder socket.
 * @param port port number in the network byte order.
 * @param fd_out [out] pointer to a file descriptor.
 * @return 0 on success, or non-zero error number.
 */
static inline int open_udp6(in_port_t port, int *fd_out) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    int err = errno;
    if (fd >= 0) {
        err = set_options_udp6(fd);
        if (err == 0) {
            const struct sockaddr_in6 addr = {
                .sin6_family = AF_INET6,
                .sin6_port = port,
                .sin6_flowinfo = 0,
                .sin6_addr = in6addr_any,
                .sin6_scope_id = 0,
            };
            if (bind(fd, (const struct sockaddr *) &addr,
                    sizeof (struct sockaddr_in6)) == 0) {
                *fd_out = fd;
                return 0;
            }
            err = errno;
        }
        close(fd);
    }
    return err;
}

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

/**
 * True if this module is initialized.
 */
static bool initialized;

/**
 * File descriptor of the IPv6 UDP socket.
 * This value is valid only if this module is initialized.
 */
static int udp6_socket;

/**
 * Returns true if this module is initialized.
 * @return true if initialized, or false.
 */
static inline int llmnr_responder_initialized(void) {
    return initialized;
}

/**
 * Handles a LLMNR query.
 * @param __ifindex interface index.
 * @param __header pointer to the LLMNR packet header.
 * @param __sender socket address of the sender.
 * @return 0 on success, or non-zero error number on failure.
 */
static int llmnr_responder_handle_query(unsigned int __ifindex,
        const struct llmnr_header *__header,
        const struct sockaddr_in6 *__sender);

int llmnr_responder_initialize(in_port_t port) {
    if (llmnr_responder_initialized()) {
        return EBUSY;
    }

    // If the specified port number is 0, we use the default port number.
    if (port == htons(0)) {
        port = htons(LLMNR_PORT);
    }

    int err = open_udp6(port, &udp6_socket);
    if (err == 0) {
        // TODO: Make the socket join the LLMNR multicast group for each
        // interface.
        initialized = true;
        return 0;
    }
    return err;
}

void llmnr_responder_finalize(void) {
    if (llmnr_responder_initialized()) {
        initialized = false;

        close(udp6_socket);
    }
}

int llmnr_responder_run(void) {
    while (!responder_terminated) {
        unsigned char data[1500];
        struct sockaddr_in6 sender;
        struct in6_pktinfo pi = {
            .ipi6_addr = IN6ADDR_ANY_INIT,
        };
        ssize_t recv_len = llmnr_receive_udp6(udp6_socket,
                data, sizeof data, &sender, &pi);
        if (recv_len >= 0) {
            // The destination MUST be the LLMNR multicast address.
            if (IN6_ARE_ADDR_EQUAL(&pi.ipi6_addr, &in6addr_llmnr) &&
                    (size_t) recv_len >= sizeof (struct llmnr_header)) {
                const struct llmnr_header *header =
                        (const struct llmnr_header *) data;
                if (llmnr_header_is_valid_query(header)) {
                    llmnr_responder_handle_query(pi.ipi6_ifindex, header,
                            &sender);
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

int llmnr_responder_handle_query(unsigned int ifindex,
        const struct llmnr_header *restrict header,
        const struct sockaddr_in6 *restrict sender) {
    char ifname[IF_NAMESIZE];
    if_indextoname(ifindex, ifname);
    syslog(LOG_DEBUG, "Received valid query on %s", ifname);

    struct in6_addr addr;
    int err = ifaddr_lookup(ifindex, &addr);
    if (err == 0) {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr, str, INET6_ADDRSTRLEN);
        syslog(LOG_DEBUG, "  Local address is %s", str);

        /* TODO: Handle the query.  */
    }

    return 0;
}

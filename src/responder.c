/*
 * responder - LLMNR responder (implementation)
 * Copyright (C) 2013-2014 Kaz Nishimura
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
#ifndef _GNU_SOURCE
// This definition might be required to enable RFC 3542 API.
#define _GNU_SOURCE 1
#endif
#ifndef _DARWIN_C_SOURCE
// We MUST define this for OS X to enable IPv6 if _POSIX_C_SOURCE is defined.
#define _DARWIN_C_SOURCE 1
#endif

#if __APPLE__
// We MUST define this to enable the Advanced Sockets API based on RFC 3542.
#define __APPLE_USE_RFC_3542 1
#endif

#include "responder.h"

#include "ifaddr.h"
#include "ascii.h"
#include "llmnr_packet.h"
#include "llmnr.h"
#include <net/if.h> /* if_indextoname */
#include <arpa/inet.h> /* inet_ntop */
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>

#ifndef IPV6_DONTFRAG
// Workaround for undefined 'IPV6_DONTFRAG' on Linux-based systems.
#if __linux__
#define IPV6_DONTFRAG 62
#endif
#endif /* !defined IPV6_DONTFRAG */

/**
 * Sets socket options for an IPv6 UDP responder socket.
 * @param fd file descriptor of a socket.
 * @return 0 on success, or non-zero error number.
 */
static inline int set_udp_options(int fd) {
    // We are not interested in IPv4 packets.
    static const int v6only = true;
    // We want the interface index for each received datagram.
    static const int recvpktinfo = true;
    // The unicast hop limit SHOULD be 1.
    static const int unicast_hops = 1;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
            sizeof (int)) != 0) {
        return errno;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &recvpktinfo,
            sizeof (int)) != 0) {
        return errno;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &unicast_hops,
            sizeof (int)) != 0) {
        syslog(LOG_WARNING,
                "Could not set IPV6_UNICAST_HOPS to %d: %s",
                unicast_hops, strerror(errno));
    }

#ifdef IPV6_DONTFRAG
    int dontfrag = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &dontfrag, sizeof (int))
            != 0) {
        syslog(LOG_WARNING, "Could not set IPV6_DONTFRAG to %d: %s",
                dontfrag, strerror(errno));
    }
#else
    syslog(LOG_WARNING,
            "No socket option to disable IPv6 packet fragmentation");
#endif

    return 0;
}

/**
 * Opens an IPv6 UDP responder socket.
 * @param port port number in the network byte order.
 * @param fd_out [out] pointer to a file descriptor.
 * @return 0 on success, or non-zero error number.
 */
static inline int open_udp(in_port_t port, int *fd_out) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    int err = errno;
    if (fd >= 0) {
        err = set_udp_options(fd);
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

/*
 * Implementation of the LLMNR responder object.
 */

/**
 * True if this module is initialized.
 */
static bool initialized;

/**
 * File descriptor of the UDP socket.
 * This value is valid only if this module is initialized.
 */
static int udp_fd;

/**
 * Host name in the DNS name format.
 * It MUST be composed of a single label.
 */
static uint8_t host_name[LLMNR_LABEL_MAX + 2];

static volatile sig_atomic_t responder_terminated;

/*
 * Declarations for static functions.
 */

/**
 * Handles a change notification for a network interface.
 * @param __change [in] change notification.
 */
static void responder_handle_ifaddr_change(
        const struct ifaddr_change *__change);

static ssize_t responder_receive_udp(int, void *, size_t,
        struct sockaddr_in6 *, struct in6_pktinfo *);
static int decode_cmsg(struct msghdr *, struct in6_pktinfo *);

/**
 * Handles a LLMNR query.
 * @param __index interface index.
 * @param __header [in] header.
 * @param __packet_size packet size including the header in octets.
 * @param __sender socket address of the sender.
 * @return 0 if no error is detected, or non-zero error number.
 */
static int responder_handle_query(unsigned int __index,
        const struct llmnr_header *__header, size_t __packet_size,
        const struct sockaddr_in6 *__sender);

/**
 * Responds to a query for the host name.
 * @param __index interface index.
 * @param __query [in] query.
 * @param __query_qname_end [in] end of the QNAME field in the query.
 * @param __sender [in] socket address of the sender.
 */
static int responder_respond_for_name(unsigned int __index,
        const struct llmnr_header *__query, const uint8_t *__query_qname_end,
        const struct sockaddr_in6 *__sender);

/*
 * Inline functions.
 */

/**
 * Returns true if this module is initialized.
 * @return true if initialized, or false.
 */
static inline int responder_initialized(void) {
    return initialized;
}
/**
 * Checks if the name in a question matches the host name.
 * @param question
 * @return
 */
static inline int responder_name_matches(const uint8_t *restrict question) {
    size_t n = host_name[0];
    if (*question++ == n) {
        const uint8_t *restrict p = host_name + 1;
        while (n--) {
            if (ascii_to_upper(*question++) != ascii_to_upper(*p++)) {
                return false;
            }
        }
        if (*question == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Out-of-line functions.
 */

int responder_initialize(in_port_t port) {
    if (responder_initialized()) {
        return EBUSY;
    }

    // If the specified port number is 0, we use the default port number.
    if (port == htons(0)) {
        port = htons(LLMNR_PORT);
    }

    int err = open_udp(port, &udp_fd);
    if (err == 0) {
        err = ifaddr_set_change_handler(&responder_handle_ifaddr_change, NULL);
        if (err == 0) {
            initialized = true;
            return 0;
        }

        if (close(udp_fd) != 0) {
            syslog(LOG_ERR, "Failed to close a socket: %s",
                    strerror(errno));
        }
    }
    return err;
}

void responder_finalize(void) {
    if (responder_initialized()) {
        initialized = false;

        close(udp_fd);
    }
}

void responder_set_host_name(const char *restrict name) {
    size_t label_length = strcspn(name, ".");
    if (label_length > LLMNR_LABEL_MAX) {
        syslog(LOG_WARNING, "Host name truncated to %u octets",
                LLMNR_LABEL_MAX);
        label_length = LLMNR_LABEL_MAX;
    }
    memcpy(host_name + 1, name, label_length);
    host_name[label_length + 1] = '\0';
    host_name[0] = label_length;
}

int responder_run(void) {
    while (!responder_terminated) {
        unsigned char packet[1500]; // TODO: Handle jumbo packet.
        struct sockaddr_in6 sender;
        struct in6_pktinfo pktinfo = {
            .ipi6_addr = IN6ADDR_ANY_INIT,
            .ipi6_ifindex = 0,
        };
        ssize_t packet_size = responder_receive_udp(udp_fd, packet, sizeof packet,
                &sender, &pktinfo);
        if (packet_size >= 0) {
            // The sender address must not be multicast.
            if (!IN6_IS_ADDR_MULTICAST(&sender.sin6_addr)) {
                if ((size_t) packet_size >= sizeof (struct llmnr_header)) {
                    const struct llmnr_header *header =
                            (const struct llmnr_header *) packet;
                    if (llmnr_query_is_valid(header)) {
                        responder_handle_query(pktinfo.ipi6_ifindex, header,
                                packet_size, &sender);
                    } else {
                        log_discarded("Non-query packet", &sender);
                    }
                } else {
                    log_discarded("Short packet", &sender);
                }
            } else {
                log_discarded("Packet from multicast address", &sender);
            }
        }
    }
    responder_terminated = false;

    return 0;
}

void responder_terminate(void) {
    responder_terminated = true;
}

void responder_handle_ifaddr_change(
        const struct ifaddr_change *restrict change) {
    if (responder_initialized()) {
        if (change->ifindex != 0) {
            const struct ipv6_mreq mr = {
                .ipv6mr_multiaddr = in6addr_mc_llmnr,
                .ipv6mr_interface = change->ifindex,
            };

            char ifname[IF_NAMESIZE];
            if_indextoname(change->ifindex, ifname);

            switch (change->type) {
            case IFADDR_ADDED:
                if (setsockopt(udp_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        &mr, sizeof (struct ipv6_mreq)) == 0) {
                    syslog(LOG_NOTICE,
                            "Joined the LLMNR multicast group on %s", ifname);
                } else {
                    syslog(LOG_ERR,
                            "Failed to join the LLMNR multicast group on %s",
                            ifname);
                }
                break;

            case IFADDR_REMOVED:
                if (setsockopt(udp_fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                        &mr, sizeof (struct ipv6_mreq)) == 0) {
                    syslog(LOG_NOTICE,
                            "Left the LLMNR multicast group on %s", ifname);
                } else {
                    syslog(LOG_ERR,
                            "Failed to leave the LLMNR multicast group on %s",
                            ifname);
                }
                break;
            }
        }
    }
}

ssize_t responder_receive_udp(int sock, void *restrict buf, size_t bufsize,
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
                decode_cmsg(&msg, pktinfo) < 0) {
            errno = ENOMSG;
            return -1;
        }
    }
    return recv_size;
}

int decode_cmsg(struct msghdr *restrict msg,
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

int responder_handle_query(unsigned int index,
        const struct llmnr_header *restrict header, size_t packet_size,
        const struct sockaddr_in6 *restrict sender) {
    assert(packet_size >= LLMNR_HEADER_SIZE);
    assert(sender->sin6_family == AF_INET6);

    const uint8_t *question = llmnr_data(header);
    size_t length = packet_size - LLMNR_HEADER_SIZE;

    const uint8_t *qname_end = llmnr_skip_name(question, &length);
    if (qname_end && length >= 4) {
        if (responder_name_matches(question)) {
            syslog(LOG_DEBUG, "QNAME matched my host name");

            responder_respond_for_name(index, header, qname_end, sender);
        }
    } else {
        log_discarded("Invalid question", sender);
    }

    return 0;
}

int responder_respond_for_name(unsigned int index,
        const struct llmnr_header *query, const uint8_t *query_qname_end,
        const struct sockaddr_in6 *restrict sender) {
    size_t query_size = query_qname_end + 4 - (const uint8_t *) query;
    size_t packet_size = query_size;
    size_t number_of_addr_v6 = 0;

    uint_fast16_t qtype = llmnr_get_uint16(query_qname_end);
    uint_fast16_t qclass = llmnr_get_uint16(query_qname_end + 2);
    if (qclass == LLMNR_QCLASS_IN) {
        switch (qtype) {
            int err;

        case LLMNR_QTYPE_AAAA:
        case LLMNR_QTYPE_ANY:
            err = ifaddr_lookup_v6(index, 0, NULL, &number_of_addr_v6);
            if (err == 0 && number_of_addr_v6 != 0) {
                packet_size += 1 + host_name[0];
                packet_size -= 2;
                packet_size += number_of_addr_v6 * (2 + 10
                        + sizeof (struct in6_addr));
            } else {
                char ifname[IF_NAMESIZE];
                if_indextoname(index, ifname);
                syslog(LOG_NOTICE, "No interface addresses found for %s",
                        ifname);
            }
            break;
        }
    }

    uint8_t packet[packet_size];
    memcpy(packet, query, query_size);

    struct llmnr_header *response = (struct llmnr_header *) packet;
    response->flags = htons(LLMNR_HEADER_QR);
    response->ancount = htons(0);
    response->nscount = htons(0);
    response->arcount = htons(0);

    uint8_t *packet_end = packet + query_size;
    if (number_of_addr_v6 != 0) {
        struct in6_addr addr_v6[number_of_addr_v6];
        size_t n = 0;
        int e = ifaddr_lookup_v6(index, number_of_addr_v6, addr_v6, &n);
        if (e == 0 && n < number_of_addr_v6) {
            // The number of interface addresses changed.
            // TODO: We should log it.
            number_of_addr_v6 = n;
        }

        for (size_t i = 0; i != number_of_addr_v6; ++i) {
            // TODO: Clean up the following code.
            if (packet_end == packet + query_size) {
                // The first must be a name.
                memcpy(packet_end, host_name, 1 + host_name[0]);
                packet_end += 1 + host_name[0];
                *packet_end++ = '\0';
            } else {
                llmnr_put_uint16(0xc000 + query_size, packet_end);
                packet_end += 2;
            }
            // TYPE
            llmnr_put_uint16(LLMNR_TYPE_AAAA, packet_end);
            packet_end += 2;
            // CLASS
            llmnr_put_uint16(LLMNR_CLASS_IN, packet_end);
            packet_end += 2;
            // TTL
            // TODO: We should make the TTL value configurable?
            llmnr_put_uint32(30, packet_end);
            packet_end += 4;
            // RDLENGTH
            llmnr_put_uint16(sizeof (struct in6_addr), packet_end);
            packet_end += 2;
            // RDATA
            memcpy(packet_end, &addr_v6[i], sizeof (struct in6_addr));
            packet_end += sizeof (struct in6_addr);
        }

        response->ancount = htons(ntohs(response->ancount)
                + number_of_addr_v6);
    }

    // Sends the response.
    if (sendto(udp_fd, packet, packet_end - packet, 0, sender,
            sizeof (struct sockaddr_in6)) >= 0) {
        return 0;
    }

    // TODO
    if (packet_size > 512 && errno == EMSGSIZE) {
        // Resends with truncation.
        response->flags |= htons(LLMNR_HEADER_TC);
        if (sendto(udp_fd, response, 512, 0, sender,
                sizeof (struct sockaddr_in6)) >= 0) {
            return 0;
        }
    }

    return errno;
}

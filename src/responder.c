/*
 * LLMNR responder (implementation)
 * Copyright (C) 2013 Kaz Nishimura
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

/**
 * Sets socket options for an IPv6 UDP responder socket.
 * @param fd file descriptor of a socket.
 * @return 0 on success, or non-zero error number.
 */
static inline int set_options_udp6(int fd) {
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
 * # Implementation of the LLMNR responder object.
 *
 * ## Static variables.
 */

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
 * First label of the host name in the DNS label format.
 */
static uint8_t host_label[1 + LLMNR_LABEL_MAX];

static volatile sig_atomic_t responder_terminated;

/*
 * ## Declarations for static functions.
 */

/**
 * Handles a change notification for a network interface.
 * @param __change [in] change notification.
 */
static void responder_handle_ifaddr_change(
        const struct ifaddr_change *__change);

static ssize_t receive_udp6(int, void *, size_t,
        struct sockaddr_in6 *, struct in6_pktinfo *);
static int decode_cmsg(struct msghdr *, struct in6_pktinfo *);

/**
 * Handles a LLMNR query.
 * @param __ifindex interface index.
 * @param __header pointer to the header.
 * @param __length length of the packet including the header in octets.
 * @param __sender socket address of the sender.
 * @return 0 on success, or non-zero error number on failure.
 */
static int responder_handle_query(unsigned int __ifindex,
        const struct llmnr_header *__header, size_t __length,
        const struct sockaddr_in6 *__sender);

/*
 */
static int responder_respond_empty(const struct llmnr_header *__query,
        size_t __query_size, const struct sockaddr_in6 *__sender);

/*
 * ## In-line functions.
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
    size_t n = host_label[0];
    if (*question++ == n) {
        const uint8_t *restrict p = host_label + 1;
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
 * ## Out-of-line functions.
 */

int responder_initialize(in_port_t port) {
    if (responder_initialized()) {
        return EBUSY;
    }

    // If the specified port number is 0, we use the default port number.
    if (port == htons(0)) {
        port = htons(LLMNR_PORT);
    }

    int err = open_udp6(port, &udp6_socket);
    if (err == 0) {
        err = ifaddr_set_change_handler(&responder_handle_ifaddr_change, NULL);
        if (err == 0) {
            initialized = true;
            return 0;
        }

        if (close(udp6_socket) != 0) {
            syslog(LOG_CRIT, "Failed to close 'udp6_socket': %s",
                    strerror(errno));
            abort();
        }
    }
    return err;
}

void responder_finalize(void) {
    if (responder_initialized()) {
        initialized = false;

        close(udp6_socket);
    }
}

void responder_set_host_name(const char *restrict name) {
    const char *label_end = strchrnul(name, '.');
    size_t length = label_end - name;

    if (length > LLMNR_LABEL_MAX) {
        syslog(LOG_WARNING, "Host name truncated");
        length = LLMNR_LABEL_MAX;
    }
    memcpy(host_label + 1, name, length);
    host_label[0] = length;
}

int responder_run(void) {
    while (!responder_terminated) {
        unsigned char data[1500];
        struct sockaddr_in6 sender;
        struct in6_pktinfo pi = {
            .ipi6_addr = IN6ADDR_ANY_INIT,
        };
        ssize_t recv_len = receive_udp6(udp6_socket,
                data, sizeof data, &sender, &pi);
        if (recv_len >= 0) {
            // The destination MUST be the LLMNR multicast address.
            if (IN6_ARE_ADDR_EQUAL(&pi.ipi6_addr, &in6addr_mc_llmnr) &&
                    (size_t) recv_len >= sizeof (struct llmnr_header)) {
                const struct llmnr_header *header =
                        (const struct llmnr_header *) data;
                if (llmnr_query_is_valid(header)) {
                    responder_handle_query(pi.ipi6_ifindex, header,
                            recv_len, &sender);
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
                if (setsockopt(udp6_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
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
                if (setsockopt(udp6_socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
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

ssize_t receive_udp6(int sock, void *restrict buf, size_t bufsize,
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

int responder_handle_query(unsigned int ifindex,
        const struct llmnr_header *restrict header, size_t length,
        const struct sockaddr_in6 *restrict sender) {
    assert(length >= LLMNR_HEADER_SIZE);
    assert(sender->sin6_family == AF_INET6);

    const uint8_t *question = llmnr_data(header);
    length -= LLMNR_HEADER_SIZE;

    const uint8_t *p = llmnr_skip_name(question, &length);
    if (p && length >= 4) {
        uint_fast16_t qtype = (p[0] << 16) | p[1];
        uint_fast16_t qclass = (p[2] << 16) | p[3];
        if (qclass == LLMNR_CLASS_IN) {
            char ifname[IF_NAMESIZE];
            char addrstr[INET6_ADDRSTRLEN];
            if_indextoname(ifindex, ifname);
            inet_ntop(AF_INET6, &sender->sin6_addr, addrstr,
                    INET6_ADDRSTRLEN);
            syslog(LOG_DEBUG, "Received IN query for QTYPE %" PRIuFAST16 \
                    " on %s from %s%%%" PRIu32, qtype, ifname, addrstr,
                    sender->sin6_scope_id);

            if (responder_name_matches(question)) {
                syslog(LOG_DEBUG, "  QNAME matched");

                struct in6_addr addr;
                int err = ifaddr_lookup(ifindex, &addr);
                if (err == 0) {
                    char addrstr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &addr, addrstr, INET6_ADDRSTRLEN);
                    syslog(LOG_DEBUG, "  Interface address is %s", addrstr);

                    switch (qtype) {
                    case LLMNR_TYPE_AAAA:
                    case LLMNR_QTYPE_ANY:
                        responder_respond_empty(header,
                                p + 4 - (const uint8_t *) header, sender);
                        break;

                    case LLMNR_TYPE_A:
                    default:
                        responder_respond_empty(header,
                                p + 4 - (const uint8_t *) header, sender);
                        break;
                    }
                } else {
                    char ifname[IF_NAMESIZE];
                    if_indextoname(ifindex, ifname);
                    syslog(LOG_NOTICE, "Address not found for %s", ifname);
                }
            }
        }
    } else {
        log_discarded("Invalid question", sender);
    }

    return 0;
}

int responder_respond_empty(const struct llmnr_header *restrict query,
        size_t query_size, const struct sockaddr_in6 *restrict sender) {
    assert(query_size <= 512);

    uint8_t packet[512];
    memcpy(packet, query, query_size);

    struct llmnr_header *header = (struct llmnr_header *) packet;
    header->flags = htons(LLMNR_HEADER_QR);

    if (sendto(udp6_socket, packet, query_size, 0, sender,
            sizeof (struct sockaddr_in6)) >= 0) {
        return 0;
    } else {
        if (errno == EMSGSIZE) {
            // TODO: Resend with truncation.
            header->flags |= htons(LLMNR_HEADER_TC);
            if (sendto(udp6_socket, packet, query_size, 0, sender,
                    sizeof (struct sockaddr_in6)) >= 0) {
                return 0;
            }
        }
    }

    return errno;
}

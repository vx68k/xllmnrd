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

#include "responder.h"

#include "rtnetlink.h"
#include "ascii.h"
#include "llmnr_packet.h"
#include "llmnr.h"
#include "socket_utility.h"
#include <net/if.h> /* if_indextoname */
#include <arpa/inet.h> /* inet_ntop */
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <vector>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cinttypes>
#include <cassert>

using std::error_code;
using std::swap;
using std::system_error;
using namespace xllmnrd;

int responder::open_llmnr_udp6(const in_port_t port)
{
    int udp6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp6 == -1) {
        throw system_error(error_code(), "could not open a UDP socket");
    }

    try {
        [[maybe_unused]]
        static const int ON = 1;

        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_V6ONLY, &ON) == -1) {
            throw system_error(error_code(), "could not set IPV6_V6ONLY");
        }
        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ON) == -1) {
            throw system_error(error_code(), "could not set IPV6_RECVPKTINFO");
        }

        // The unicast hop limit SHOULD be 1.
        static const int HOP_1 = 1;
        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &HOP_1) == -1) {
            syslog(LOG_WARNING, "could not set IPV6_UNICAST_HOPS to %d: %s",
                HOP_1, strerror(errno));
        }

#ifdef IPV6_DONTFRAG
        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_DONTFRAG, &ON) == -1) {
            syslog(LOG_WARNING, "could not set IPV6_DONTFRAG to %d: %s",
                ON, strerror(errno));
        }
#else
        syslog(LOG_WARNING, "socket option IPV6_DONTFRAG not defined");
#endif

        const struct sockaddr_in6 addr = {
            AF_INET6,    // .sin6_family
            port,        // .sin6_port
            0,           // .sin6_flowinfo
            in6addr_any, // .sin6_addr
            0,           // .sin6_scode_id
        };
        if (bind(udp6, &addr) == -1) {
            throw system_error(error_code(), "could not bind");
        }
    }
    catch (...) {
        close(udp6);
        throw;
    }

    return udp6;
}

responder::responder()
:
    _interface_manager {new rtnetlink_interface_manager()},
    _udp6 {open_llmnr_udp6(htons(LLMNR_PORT))}
{
    _interface_manager->refresh(true);
}

responder::~responder()
{
    int udp6 = -1;
    swap(_udp6, udp6);
    if (udp6 != -1) {
        close(udp6);
    }
}

void responder::run()
{
    _running.store(true);
    while (_running) {
        process_udp6();
    }
}

void responder::process_udp6()
{
    // TODO: Implemente this function.
}

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

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only) != 0) {
        return errno;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &recvpktinfo) != 0) {
        return errno;
    }
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &unicast_hops) != 0) {
        syslog(LOG_WARNING,
                "Could not set IPV6_UNICAST_HOPS to %d: %s",
                unicast_hops, strerror(errno));
    }

#ifdef IPV6_DONTFRAG
    int dontfrag = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &dontfrag) != 0) {
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
                AF_INET6,    // .sin6_family
                port,        // .sin6_port
                0,           // .sin6_flowinfo
                in6addr_any, // .sin6_addr
                0,           // .sin6_scode_id
            };
            if (bind(fd, &addr) == 0) {
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

// Interface manager.
static std::unique_ptr<interface_manager> if_manager;

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
        const struct interface_change_event *__change);

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

    if_manager.reset(new rtnetlink_interface_manager());
    if_manager->set_interface_change(&responder_handle_ifaddr_change);
    if_manager->refresh(true);

    // If the specified port number is 0, we use the default port number.
    if (port == htons(0)) {
        port = htons(LLMNR_PORT);
    }

    int err = open_udp(port, &udp_fd);
    if (err == 0) {
        initialized = true;
        return 0;
    }

    if_manager.reset();
    return err;
}

void responder_finalize(void) {
    if (responder_initialized()) {
        initialized = false;

        close(udp_fd);
        if_manager.reset();
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
            IN6ADDR_ANY_INIT, // .ipi6_addr
            0,                // .ipi6_ifindex
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
        const struct interface_change_event *restrict change)
{
    if (change->address_family != AF_INET6) {
        return;
    }

    if (responder_initialized()) {
        if (change->interface_index != 0) {
            const struct ipv6_mreq mr = {
                in6addr_mc_llmnr,        // .ipv6mr_multiaddr
                change->interface_index, // .ipv6mr_interface
            };

            char ifname[IF_NAMESIZE];
            if_indextoname(change->interface_index, ifname);

            switch (change->type) {
            case interface_change_event::ADDED:
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

            case interface_change_event::REMOVED:
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
            buf,     // .iov_base
            bufsize, // .iov_len
        },
    };
    unsigned char cmsgbuf[128];
    struct msghdr msg = {
        sender,         // msg_name
        sizeof *sender, // msg_namelen
        iov,            // msg_iov
        1,              // msg_iovlen
        cmsgbuf,        // msg_control
        sizeof cmsgbuf, // msg_controllen
        0,              // msg_flags
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

    auto &&in6_addresses = if_manager->in6_addresses(index);

    uint_fast16_t qtype = llmnr_get_uint16(query_qname_end);
    uint_fast16_t qclass = llmnr_get_uint16(query_qname_end + 2);
    if (qclass == LLMNR_QCLASS_IN) {
        switch (qtype) {
        case LLMNR_QTYPE_AAAA:
        case LLMNR_QTYPE_ANY:
            number_of_addr_v6 = in6_addresses.size();
            if (number_of_addr_v6 != 0) {
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

    std::vector<uint8_t> packet(packet_size);
    memcpy(packet.data(), query, query_size);

    struct llmnr_header *response = (struct llmnr_header *) packet.data();
    response->flags = htons(LLMNR_HEADER_QR);
    response->ancount = htons(0);
    response->nscount = htons(0);
    response->arcount = htons(0);

    uint8_t *packet_end = packet.data() + query_size;
    if (number_of_addr_v6 != 0) {
        auto &&addr = in6_addresses.begin();
        for (size_t i = 0; i != number_of_addr_v6; ++i) {
            // TODO: Clean up the following code.
            if (packet_end == packet.data() + query_size) {
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
            *reinterpret_cast<struct in6_addr *>(packet_end) = *addr++;
            packet_end += sizeof (struct in6_addr);
        }

        response->ancount = htons(ntohs(response->ancount)
                + number_of_addr_v6);
    }

    // Sends the response.
    if (sendto(udp_fd, packet.data(), packet_end - packet.data(), 0,
            reinterpret_cast<const struct sockaddr *>(sender),
            sizeof (struct sockaddr_in6)) >= 0) {
        return 0;
    }

    // TODO
    if (packet_size > 512 && errno == EMSGSIZE) {
        // Resends with truncation.
        response->flags |= htons(LLMNR_HEADER_TC);
        if (sendto(udp_fd, response, 512, 0,
                reinterpret_cast<const struct sockaddr *>(sender),
                sizeof (struct sockaddr_in6)) >= 0) {
            return 0;
        }
    }

    return errno;
}

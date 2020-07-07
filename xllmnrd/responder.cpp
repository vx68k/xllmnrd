// responder.cpp
// Copyright (C) 2013-2020 Kaz Nishimura
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

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
#include "socket_utility.h"
#include <net/if.h> /* if_indextoname */
#include <arpa/inet.h> /* inet_ntop */
#include <sys/socket.h>
#include <syslog.h>
#include <set>
#include <vector>
#include <algorithm>
#include <system_error>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cinttypes>
#include <cassert>

using std::copy;
using std::copy_n;
using std::error_code;
using std::for_each;
using std::set;
using std::strchr;
using std::strlen;
using std::strerror;
using std::swap;
using std::system_error;
using std::uint8_t;
using std::uint16_t;
using std::unique_ptr;
using std::vector;
using namespace xllmnrd;

static const uint32_t TTL = 30;

/*
 * Logs a message with the sender address.
 */
static inline void log(const int priority, const char *const message,
    const sockaddr_in6 *const sender)
{
    if (sender && sender->sin6_family == AF_INET6) {
        char addrstr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sender->sin6_addr, addrstr, INET6_ADDRSTRLEN);
        syslog(priority, "%s from %s%%%" PRIu32, message, addrstr,
            sender->sin6_scope_id);
    } else {
        syslog(priority, "%s", message);
    }
}

int responder::open_udp6(const in_port_t port)
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

        const sockaddr_in6 addr = {
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

responder::responder(const in_port_t port)
:
    _interface_manager {new rtnetlink_interface_manager()},
    _udp6 {open_udp6(port)}
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

void responder::terminate()
{
    _running.store(false);
}

void responder::process_udp6()
{
    if (_running) {
        ssize_t packet_size = recv(_udp6, nullptr, 0, MSG_PEEK | MSG_TRUNC);
        if (packet_size < 0) {
            syslog(LOG_ERR, "could not receive a packet: %s", strerror(errno));
            return;
        }

        unique_ptr<char []> packet {new char[packet_size]};
        sockaddr_in6 sender {};
        in6_pktinfo pktinfo {
            in6addr_any, // .ipi6_addr
            0,           // .ipi6_ifindex
        };
        packet_size = recv_udp6(&packet[0], packet_size, sender, pktinfo);
        if (packet_size < 0) {
            syslog(LOG_ERR, "cound not receive a packet: %s", strerror(errno));
            return;
        }

        // The sender address must not be multicast.
        if (IN6_IS_ADDR_MULTICAST(&sender.sin6_addr)) {
            log(LOG_INFO, "packet from a multicast address", &sender);
            return;
        }
        if (size_t(packet_size) < sizeof (llmnr_header)) {
            log(LOG_INFO, "short packet", &sender);
            return;
        }

        const llmnr_header *header =
            reinterpret_cast<const llmnr_header *>(&packet[0]);
        if (llmnr_query_is_valid(header)) {
            handle_udp6_query(header, packet_size, sender, pktinfo.ipi6_ifindex);
        }
        else {
            log(LOG_INFO, "non-query packet", &sender);
        }
    }
}

ssize_t responder::recv_udp6(void *const buffer, size_t buffer_size,
    sockaddr_in6 &sender, in6_pktinfo &pktinfo)
{
    iovec iov[] = {
        {
            buffer,      // .iov_base
            buffer_size, // .iov_len
        },
    };
    unsigned char control[128];
    msghdr msg = {
        &sender,         // .msg_name
        sizeof sender, // .msg_namelen
        iov,            // .msg_iov
        1,              // .msg_iovlen
        control,        // .msg_control
        sizeof control, // .msg_controllen
        0,              // .msg_flags
    };
    ssize_t received = recvmsg(_udp6, &msg, 0);
    if (received >= 0) {
        if (msg.msg_namelen < sizeof sender) {
            errno = ENOMSG;
            return -1;
        }

        cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg) {
            switch (cmsg->cmsg_level) {
            case IPPROTO_IPV6:
                switch (cmsg->cmsg_type) {
                case IPV6_PKTINFO:
                    if (cmsg->cmsg_len >= CMSG_LEN(sizeof pktinfo)) {
                        pktinfo = *reinterpret_cast<in6_pktinfo *>
                            (CMSG_DATA(cmsg));
                    }
                    break;
                }
                break;
            }
            cmsg = CMSG_NXTHDR(&msg, cmsg);
        }
    }
    return received;
}

void responder::handle_udp6_query(const llmnr_header *const query,
    const size_t query_size, const sockaddr_in6 &sender,
    const unsigned int interface_index)
{
    // These must be checked before.
    assert(query_size >= sizeof query);

    const uint8_t *qname = reinterpret_cast<const uint8_t *>(query + 1);
    size_t remains = query_size - sizeof *query;

    const uint8_t *qname_end = llmnr_skip_name(qname, &remains);
    if (qname_end && remains >= 4) {
        if (matches_host_name(qname)) {
            respond_for_name(_udp6, query, qname, qname_end, sender, interface_index);
        }
    }
    else {
        log(LOG_INFO, "invalid question", &sender);
    }
}

void responder::respond_for_name(const int fd, const llmnr_header *const query,
    const uint8_t *const qname, const uint8_t *const qname_end,
    const sockaddr_in6 &sender, const unsigned int interface_index)
{
    set<in6_addr> in6_addresses;

    auto &&qtype = llmnr_get_uint16(qname_end);
    auto &&qclass = llmnr_get_uint16(qname_end + 2);
    switch (qtype) {
    case LLMNR_QTYPE_ANY:
    case LLMNR_QTYPE_AAAA:
        if (qclass == LLMNR_QCLASS_IN) {
            in6_addresses = _interface_manager->in6_addresses(interface_index);
            if (in6_addresses.empty()) {
                char name[IF_NAMESIZE];
                if_indextoname(interface_index, name);
                syslog(LOG_NOTICE, "no IPv6 interface addresses for %s", name);
            }
        }
        break;
    }

    std::vector<uint8_t> response
        {reinterpret_cast<const uint8_t *>(query), qname_end + 4};

    auto &&response_header = reinterpret_cast<llmnr_header *>(response.data());
    response_header->flags = htons(LLMNR_HEADER_QR);
    response_header->ancount = htons(0);
    response_header->nscount = htons(0);
    response_header->arcount = htons(0);

    auto &&response_size = response.size();
    for_each(in6_addresses.begin(), in6_addresses.end(), [&](const in6_addr &i) {
        if (response_header->ancount == htons(0)) {
            copy(qname, qname_end, back_inserter(response));
        }
        else {
            uint8_t name[2] = {};
            llmnr_put_uint16(0xc000 + response_size, name);
            copy_n(name, 2, back_inserter(response));
        }

        uint8_t type_class_ttl[8] = {};
        llmnr_put_uint16(LLMNR_TYPE_AAAA, type_class_ttl);
        llmnr_put_uint16(LLMNR_CLASS_IN, type_class_ttl + 2);
        llmnr_put_uint32(TTL, type_class_ttl + 4);
        copy_n(type_class_ttl, 8, back_inserter(response));

        copy_n(reinterpret_cast<const uint8_t *>(&i), sizeof i,
            back_inserter(response));

        response_header->ancount = htons(ntohs(response_header->ancount) + 1);
    });

    // Sends the response.
    if (sendto(fd, response.data(), response.size(), 0,
        reinterpret_cast<const sockaddr *>(&sender), sizeof sender) == -1) {
        if (response.size() > 512 && errno == EMSGSIZE) {
            // Resends with truncation.
            response_header->flags |= htons(LLMNR_HEADER_TC);
            sendto(fd, response.data(), 512, 0,
                reinterpret_cast<const sockaddr *>(&sender), sizeof sender);
        }
    }
}

bool responder::matches_host_name(const void *const question) const
{
    // TODO: Implement this function.
    char host_name[LLMNR_LABEL_MAX + 1] = {};
    gethostname(host_name, LLMNR_LABEL_MAX);
    auto &&dot = strchr(host_name, '.');
    if (dot != nullptr) {
        *dot = '\0';
    }

    const uint8_t *i = static_cast<const uint8_t *>(question);
    const unsigned char *j = reinterpret_cast<unsigned char *>(host_name);
    size_t length = *i++;
    if (length == strlen(host_name)) {
        // This comparison must be case-insensitive in ASCII.
        while (length--) {
            if (ascii_to_upper(*i++) != ascii_to_upper(*j++)) {
                return false;
            }
        }
        if (*i++ == 0) {
            return true;
        }
    }
    return false;
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
            const sockaddr_in6 addr = {
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
        const interface_change_event *__change);

static ssize_t responder_receive_udp(int, void *, size_t,
        sockaddr_in6 *, in6_pktinfo *);
static int decode_cmsg(msghdr *, in6_pktinfo *);

/**
 * Handles a LLMNR query.
 * @param __index interface index.
 * @param __header [in] header.
 * @param __packet_size packet size including the header in octets.
 * @param __sender socket address of the sender.
 * @return 0 if no error is detected, or non-zero error number.
 */
static int responder_handle_query(unsigned int __index,
        const llmnr_header *__header, size_t __packet_size,
        const sockaddr_in6 *__sender);

/**
 * Responds to a query for the host name.
 * @param __index interface index.
 * @param __query [in] query.
 * @param __query_qname_end [in] end of the QNAME field in the query.
 * @param __sender [in] socket address of the sender.
 */
static int responder_respond_for_name(unsigned int __index,
        const llmnr_header *__query, const uint8_t *__query_qname_end,
        const sockaddr_in6 *__sender);

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
        sockaddr_in6 sender;
        in6_pktinfo pktinfo = {
            IN6ADDR_ANY_INIT, // .ipi6_addr
            0,                // .ipi6_ifindex
        };
        ssize_t packet_size = responder_receive_udp(udp_fd, packet, sizeof packet,
                &sender, &pktinfo);
        if (packet_size >= 0) {
            // The sender address must not be multicast.
            if (!IN6_IS_ADDR_MULTICAST(&sender.sin6_addr)) {
                if ((size_t) packet_size >= sizeof (llmnr_header)) {
                    const llmnr_header *header =
                            (const llmnr_header *) packet;
                    if (llmnr_query_is_valid(header)) {
                        responder_handle_query(pktinfo.ipi6_ifindex, header,
                                packet_size, &sender);
                    } else {
                        log(LOG_INFO, "Non-query packet", &sender);
                    }
                } else {
                    log(LOG_INFO, "Short packet", &sender);
                }
            } else {
                log(LOG_INFO, "Packet from multicast address", &sender);
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
        const interface_change_event *restrict change)
{
    if (change->address_family != AF_INET6) {
        return;
    }

    if (responder_initialized()) {
        if (change->interface_index != 0) {
            const ipv6_mreq mr = {
                in6addr_mc_llmnr,        // .ipv6mr_multiaddr
                change->interface_index, // .ipv6mr_interface
            };

            char ifname[IF_NAMESIZE];
            if_indextoname(change->interface_index, ifname);

            switch (change->type) {
            case interface_change_event::ADDED:
                if (setsockopt(udp_fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        &mr, sizeof (ipv6_mreq)) == 0) {
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
                        &mr, sizeof (ipv6_mreq)) == 0) {
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
        sockaddr_in6 *restrict sender,
        in6_pktinfo *restrict pktinfo) {
    iovec iov[1] = {
        {
            buf,     // .iov_base
            bufsize, // .iov_len
        },
    };
    unsigned char cmsgbuf[128];
    msghdr msg = {
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

int decode_cmsg(msghdr *restrict msg,
        in6_pktinfo *restrict pktinfo) {
    for (cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg;
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
        const llmnr_header *restrict header, size_t packet_size,
        const sockaddr_in6 *restrict sender) {
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
        log(LOG_INFO, "Invalid question", sender);
    }

    return 0;
}

int responder_respond_for_name(unsigned int index,
        const llmnr_header *query, const uint8_t *query_qname_end,
        const sockaddr_in6 *restrict sender) {
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
                        + sizeof (in6_addr));
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

    llmnr_header *response = (llmnr_header *) packet.data();
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
            llmnr_put_uint16(sizeof (in6_addr), packet_end);
            packet_end += 2;
            // RDATA
            *reinterpret_cast<in6_addr *>(packet_end) = *addr++;
            packet_end += sizeof (in6_addr);
        }

        response->ancount = htons(ntohs(response->ancount)
                + number_of_addr_v6);
    }

    // Sends the response.
    if (sendto(udp_fd, packet.data(), packet_end - packet.data(), 0,
            reinterpret_cast<const sockaddr *>(sender),
            sizeof (sockaddr_in6)) >= 0) {
        return 0;
    }

    // TODO
    if (packet_size > 512 && errno == EMSGSIZE) {
        // Resends with truncation.
        response->flags |= htons(LLMNR_HEADER_TC);
        if (sendto(udp_fd, response, 512, 0,
                reinterpret_cast<const sockaddr *>(sender),
                sizeof (sockaddr_in6)) >= 0) {
            return 0;
        }
    }

    return errno;
}

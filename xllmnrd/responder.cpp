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

#include "llmnr.h"
#include "rtnetlink.h"
#include "ascii.h"
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
using std::generic_category;
using std::set;
using std::strcspn;
using std::strlen;
using std::strerror;
using std::swap;
using std::system_error;
using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::unique_ptr;
using std::vector;
using namespace xllmnrd;

static const uint32_t TTL = 30;

/*
 * Logs a message with the sender address.
 */
static inline void log_with_sender(const int pri, const char *const message,
    const void *const sender, const size_t sender_size)
{
    if (sender != nullptr) {
        int family = static_cast<const sockaddr *>(sender)->sa_family;
        switch (family) {
        case AF_INET6:
            if (sender_size >= sizeof (sockaddr_in6)) {
                auto &&in6 = static_cast<const sockaddr_in6 *>(sender);
                char addrstr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &in6->sin6_addr, addrstr, INET6_ADDRSTRLEN);
                syslog(pri, "%s from %s%%%" PRIu32, message, addrstr,
                    in6->sin6_scope_id);
            }
            break;
        default:
            syslog(pri, "%s from an address of family %d", message, family);
            break;
        }
    }
    else {
        syslog(pri, "%s", message);
    }
}

int responder::open_udp6(const in_port_t port)
{
    int udp6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp6 == -1) {
        throw system_error(errno, generic_category(), "could not open a UDP socket");
    }

    try {
        [[maybe_unused]]
        static const int ON = 1;

        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_V6ONLY, &ON) == -1) {
            throw system_error(errno, generic_category(), "could not set IPV6_V6ONLY");
        }
        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ON) == -1) {
            throw system_error(errno, generic_category(), "could not set IPV6_RECVPKTINFO");
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
            throw system_error(errno, generic_category(), "could not bind");
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
    responder(htons(LLMNR_PORT))
{
    // Nothing to do.
}

responder::responder(const in_port_t port)
:
    _interface_manager {new rtnetlink_interface_manager()},
    _udp6 {open_udp6(port)}
{
    _interface_manager->add_interface_listener(this);
    _interface_manager->refresh();
}

responder::~responder()
{
    _interface_manager->remove_interface_listener(this);

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
            log_with_sender(LOG_INFO, "packet from a multicast address", &sender, sizeof sender);
            return;
        }
        if (size_t(packet_size) < sizeof (llmnr_header)) {
            log_with_sender(LOG_INFO, "short packet", &sender, sizeof sender);
            return;
        }

        const llmnr_header *header =
            reinterpret_cast<const llmnr_header *>(&packet[0]);
        if (llmnr_query_is_valid(header)) {
            handle_udp6_query(header, packet_size, sender, pktinfo.ipi6_ifindex);
        }
        else {
            log_with_sender(LOG_INFO, "non-query packet", &sender, sizeof sender);
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
        auto &&name = matching_host_name(qname);
        if (name != nullptr) {
            respond_for_name(_udp6, query, qname_end, name, sender, interface_index);
        }
    }
    else {
        log_with_sender(LOG_INFO, "invalid question", &sender, sizeof sender);
    }
}

void responder::respond_for_name(const int fd, const llmnr_header *const query,
    const uint8_t *const qname_end, const unique_ptr<uint8_t []> &name,
    const sockaddr_in6 &sender, const unsigned int interface_index)
{
    set<in_addr> in_addresses;
    set<in6_addr> in6_addresses;

    auto &&qtype = llmnr_get_uint16(qname_end);
    auto &&qclass = llmnr_get_uint16(qname_end + 2);
    if (qtype == LLMNR_QTYPE_A || qtype == LLMNR_QTYPE_ANY) {
        if (qclass == LLMNR_QCLASS_IN) {
            in_addresses = _interface_manager->in_addresses(interface_index);
            if (in_addresses.empty()) {
                char name[IF_NAMESIZE];
                if_indextoname(interface_index, name);
                syslog(LOG_NOTICE, "no IPv4 interface addresses for %s", name);
            }
        }
    }
    if (qtype == LLMNR_QTYPE_AAAA || qtype == LLMNR_QTYPE_ANY) {
        if (qclass == LLMNR_QCLASS_IN) {
            in6_addresses = _interface_manager->in6_addresses(interface_index);
            if (in6_addresses.empty()) {
                char name[IF_NAMESIZE];
                if_indextoname(interface_index, name);
                syslog(LOG_NOTICE, "no IPv6 interface addresses for %s", name);
            }
        }
    }

    std::vector<uint8_t> response
        {reinterpret_cast<const uint8_t *>(query), qname_end + 4};

    auto response_header = reinterpret_cast<llmnr_header *>(response.data());
    response_header->flags = htons(LLMNR_FLAG_QR);
    response_header->ancount = htons(0);
    response_header->nscount = htons(0);
    response_header->arcount = htons(0);

    auto &&answer_offset = response.size();
    for_each(in_addresses.begin(), in_addresses.end(), [&](const in_addr &i) {
        auto &&response_back = back_inserter(response);

        if (response_header->ancount == htons(0)) {
            copy_n(&name[0], name[0] + 1, response_back);
            response.push_back(0);
        }
        else {
            llmnr_put_uint16(0xc000 + answer_offset, response_back);
        }

        llmnr_put_uint16(LLMNR_TYPE_A, response_back);
        llmnr_put_uint16(LLMNR_CLASS_IN, response_back);

        llmnr_put_uint32(TTL, response_back);
        llmnr_put_uint16(sizeof i, response_back);
        copy_n(reinterpret_cast<const uint8_t *>(&i), sizeof i, response_back);

        response_header = reinterpret_cast<llmnr_header *>(response.data());
        response_header->ancount = htons(ntohs(response_header->ancount) + 1);
    });
    for_each(in6_addresses.begin(), in6_addresses.end(), [&](const in6_addr &i) {
        auto &&response_back = back_inserter(response);

        if (response_header->ancount == htons(0)) {
            copy_n(&name[0], name[0] + 1, response_back);
            response.push_back(0);
        }
        else {
            llmnr_put_uint16(0xc000 + answer_offset, response_back);
        }

        llmnr_put_uint16(LLMNR_TYPE_AAAA, response_back);
        llmnr_put_uint16(LLMNR_CLASS_IN, response_back);

        llmnr_put_uint32(TTL, response_back);
        llmnr_put_uint16(sizeof i, response_back);
        copy_n(reinterpret_cast<const uint8_t *>(&i), sizeof i, response_back);

        response_header = reinterpret_cast<llmnr_header *>(response.data());
        response_header->ancount = htons(ntohs(response_header->ancount) + 1);
    });

    // Sends the response.
    if (sendto(fd, response.data(), response.size(), 0, &sender) == -1) {
        if (response.size() > 512 && errno == EMSGSIZE) {
            // Resends with truncation.
            response_header->flags |= htons(LLMNR_FLAG_TC);
            sendto(fd, response.data(), 512, 0, &sender);
        }
    }
}

auto responder::matching_host_name(const void *const qname) const
    -> unique_ptr<uint8_t []>
{
    char host_name[LLMNR_LABEL_MAX + 1] = {};
    gethostname(host_name, LLMNR_LABEL_MAX);

    auto &&host_name_length = strcspn(host_name, ".");
    host_name[host_name_length] = '\0';

    const uint8_t *i = static_cast<const uint8_t *>(qname);
    const unsigned char *j = reinterpret_cast<unsigned char *>(host_name);
    size_t length = *i++;
    if (length != host_name_length) {
        return nullptr;
    }
    // This comparison must be case-insensitive in ASCII.
    while (length--) {
        if (ascii_toupper(*i++) != ascii_toupper(*j++)) {
            return nullptr;
        }
    }
    if (*i++ != 0) {
        return nullptr;
    }

    unique_ptr<uint8_t []> name {new uint8_t [host_name_length + 2]};
    name[0] = host_name_length;
    copy_n(host_name, host_name_length, &name[1]);
    name[host_name_length + 1] = 0;
    return name;
}

void responder::interface_added(const interface_event &event)
{
    if (event.interface_index != 0) {
        char interface_name[IF_NAMESIZE];
        if_indextoname(event.interface_index, interface_name);

        const ipv6_mreq mr = {
            in6addr_mc_llmnr,        // .ipv6mr_multiaddr
            event.interface_index, // .ipv6mr_interface
        };
        if (setsockopt(_udp6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mr) == 0) {
            syslog(LOG_NOTICE, "joined the IPv6 LLMNR multicast group on %s",
                interface_name);
        }
        else {
            syslog(LOG_ERR, "could not join the IPv6 LLMNR multicast group on %s",
                interface_name);
        }
    }
}

void responder::interface_removed(const interface_event &event)
{
    if (event.interface_index != 0) {
        char interface_name[IF_NAMESIZE];
        if_indextoname(event.interface_index, interface_name);

        const ipv6_mreq mr = {
            in6addr_mc_llmnr,        // .ipv6mr_multiaddr
            event.interface_index, // .ipv6mr_interface
        };
        if (setsockopt(_udp6, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mr) == 0) {
            syslog(LOG_NOTICE, "left the IPv6 LLMNR multicast group on %s",
                interface_name);
        }
        else {
            syslog(LOG_ERR, "could not leave the IPv6 LLMNR multicast group on %s",
                interface_name);
        }
    }
}

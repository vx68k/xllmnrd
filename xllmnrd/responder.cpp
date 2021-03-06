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

static const uint32_t TIME_TO_LIVE = 30;

/*
 * Logs a message with the sender address.
 */
inline void log_with_sender(const int pri, const char *const message,
    const void *const sender, const size_t sender_size)
{
    if (sender != nullptr) {
        int family = static_cast<const sockaddr *>(sender)->sa_family;
        switch (family) {
        case AF_INET6:
            if (sender_size >= sizeof (sockaddr_in6)) {
                auto &&in6 = static_cast<const sockaddr_in6 *>(sender);
                char addrstr[INET6_ADDRSTRLEN] {};
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

template<class T>
inline void log_with_sender(const int pri, const char *const message,
    const T *const sender)
{
    log_with_sender(pri, message, sender, sizeof *sender);
}

// Member functions.

int responder::open_udp6(const in_port_t port)
{
    int udp6 = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp6 == -1) {
        throw system_error(errno, generic_category(),
            "could not open an IPv6 UDP socket");
    }

    try {
        [[maybe_unused]]
        static const int ON = 1;

        // This option is mandatory.

        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &ON) == -1) {
            throw system_error(errno, generic_category(),
                "could not set socket option 'IPV6_RECVPKTINFO'");
        }

        // Others are not.

        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_V6ONLY, &ON) == -1) {
            syslog(LOG_WARNING,
                "could not set socket option 'IPV6_V6ONLY' to %d: %s",
                ON, strerror(errno));
        }

        // The unicast hop limit SHOULD be 1.
        static const int HOP_1 = 1;
        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &HOP_1) == -1) {
            syslog(LOG_WARNING,
                "could not set socket option 'IPV6_UNICAST_HOPS' to %d: %s",
                HOP_1, strerror(errno));
        }

#ifdef IPV6_DONTFRAG
        if (setsockopt(udp6, IPPROTO_IPV6, IPV6_DONTFRAG, &ON) == -1) {
            syslog(LOG_WARNING,
                "could not set socket option 'IPV6_DONTFRAG' to %d: %s",
                ON, strerror(errno));
        }
#else
        syslog(LOG_WARNING, "socket option 'IPV6_DONTFRAG' not defined");
#endif

        const sockaddr_in6 addr {
            AF_INET6,    // .sin6_family
            port,        // .sin6_port
            0,           // .sin6_flowinfo
            in6addr_any, // .sin6_addr
            0,           // .sin6_scode_id
        };
        if (bind(udp6, &addr) == -1) {
            throw system_error(errno, generic_category(),
                "could not bind the UDP socket");
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
    _running = true;
    while (_running) {
        process_udp6();
    }
}

void responder::terminate()
{
    _running = false;
    // TODO: Should the recv call be interrupted?
}

void responder::process_udp6()
{
    if (_running) {
        auto &&packet_size = recv(_udp6, nullptr, 0, MSG_PEEK | MSG_TRUNC);
        if (packet_size == -1) {
            if (errno != EINTR) {
                syslog(LOG_ERR,
                    "could not receive a packet: %s", strerror(errno));
            }
            return;
        }

        vector<char> buffer(packet_size);

        sockaddr_in6 sender {};
        unsigned int ifindex = 0;
        packet_size = recv_udp6(&buffer[0], packet_size, sender, ifindex);
        if (packet_size == -1) {
            if (errno != EINTR) {
                syslog(LOG_ERR,
                    "cound not receive a packet: %s", strerror(errno));
            }
            return;
        }

        // The sender address must not be multicast.
        if (IN6_IS_ADDR_MULTICAST(&sender.sin6_addr)) {
            log_with_sender(LOG_INFO, "invalid source packet", &sender);
            return;
        }
        if (size_t(packet_size) < sizeof (llmnr_header)) {
            log_with_sender(LOG_INFO, "short packet", &sender);
            return;
        }

        auto &&packet = reinterpret_cast<const llmnr_header *>(&buffer[0]);
        if (llmnr_is_valid_query(packet)) {
            if ((packet->flags & htons(LLMNR_FLAG_C)) == 0) {
                handle_udp6_query(packet, packet_size, sender, ifindex);
            }
        }
        else {
            log_with_sender(LOG_INFO, "non-query packet", &sender);
        }
    }
}

ssize_t responder::recv_udp6(void *const buffer, const size_t buffer_size,
    sockaddr_in6 &sender, unsigned int &ifindex)
{
    iovec iov[1] {
        {
            buffer,      // .iov_base
            buffer_size, // .iov_len
        },
    };
    char control[128] {};
    msghdr msg {
        &sender,        // .msg_name
        sizeof sender,  // .msg_namelen
        iov,            // .msg_iov
        1,              // .msg_iovlen
        control,        // .msg_control
        sizeof control, // .msg_controllen
        0,              // .msg_flags
    };
    auto &&received = recvmsg(_udp6, &msg, 0);
    if (received >= 0) {
        if (msg.msg_namelen < sizeof sender) {
            errno = ENOMSG;
            return -1;
        }

        auto &&cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != nullptr) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
                if (cmsg->cmsg_len >= CMSG_LEN(sizeof (in6_pktinfo))) {
                    auto &&ipi6 = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cmsg));
                    ifindex = ipi6->ipi6_ifindex;
                }
            }

            cmsg = CMSG_NXTHDR(&msg, cmsg);
        }
    }
    return received;
}

void responder::handle_udp6_query(const llmnr_header *const query,
    const size_t query_size, const sockaddr_in6 &sender, const unsigned int ifindex)
{
    // These must already be checked.
    assert(query_size >= sizeof query);

    auto &&qname = reinterpret_cast<const uint8_t *>(llmnr_data(query));
    size_t remains = query_size - LLMNR_HEADER_SIZE;

    auto &&qname_end = llmnr_skip_name(qname, &remains);
    if (qname_end && remains >= 4) {
        auto &&name = matching_host_name(qname);
        if (name != nullptr) {
            respond_for_name(_udp6, query, qname_end, name.get(), sender, ifindex);
        }
    }
    else {
        log_with_sender(LOG_INFO, "invalid question", &sender);
    }
}

void responder::respond_for_name(const int fd, const llmnr_header *const query,
    const uint8_t *const qname_end, const uint8_t *const label,
    const sockaddr_in6 &sender, const unsigned int interface_index)
{
    set<in_addr> in_addresses;
    set<in6_addr> in6_addresses;

    auto &&qtype = llmnr_get_uint16(qname_end);
    auto &&qclass = llmnr_get_uint16(qname_end + 2);
    if (qclass == LLMNR_QCLASS_IN) {
        if (qtype == LLMNR_QTYPE_A || qtype == LLMNR_QTYPE_ANY) {
            in_addresses = _interface_manager->in_addresses(interface_index);
        }
        if (qtype == LLMNR_QTYPE_AAAA || qtype == LLMNR_QTYPE_ANY) {
            in6_addresses = _interface_manager->in6_addresses(interface_index);
        }
    }

    std::vector<uint8_t> buffer {
        reinterpret_cast<const uint8_t *>(query), qname_end + 4};

    auto &&response = reinterpret_cast<llmnr_header *>(buffer.data());
    response->flags = htons(LLMNR_FLAG_QR);
    response->ancount = htons(0);
    response->nscount = htons(0);
    response->arcount = htons(0);

    auto &&answer_offset = buffer.size();
    auto &&buffer_back = back_inserter(buffer);
    for_each(in_addresses.begin(), in_addresses.end(), [&](const in_addr &i) {
        if (response->ancount == htons(0)) {
            copy_n(&label[0], label[0] + 1, buffer_back);
            buffer.push_back(0);
        }
        else {
            llmnr_put_uint16(0xc000 + answer_offset, buffer_back);
        }

        llmnr_put_uint16(LLMNR_TYPE_A, buffer_back);
        llmnr_put_uint16(LLMNR_CLASS_IN, buffer_back);

        llmnr_put_uint32(TIME_TO_LIVE, buffer_back);
        llmnr_put_uint16(sizeof i, buffer_back);
        copy_n(reinterpret_cast<const uint8_t *>(&i), sizeof i, buffer_back);

        response = reinterpret_cast<llmnr_header *>(buffer.data());
        response->ancount = htons(ntohs(response->ancount) + 1);
    });
    for_each(in6_addresses.begin(), in6_addresses.end(), [&](const in6_addr &i) {
        if (response->ancount == htons(0)) {
            copy_n(&label[0], label[0] + 1, buffer_back);
            buffer.push_back(0);
        }
        else {
            llmnr_put_uint16(0xc000 + answer_offset, buffer_back);
        }

        llmnr_put_uint16(LLMNR_TYPE_AAAA, buffer_back);
        llmnr_put_uint16(LLMNR_CLASS_IN, buffer_back);

        llmnr_put_uint32(TIME_TO_LIVE, buffer_back);
        llmnr_put_uint16(sizeof i, buffer_back);
        copy_n(reinterpret_cast<const uint8_t *>(&i), sizeof i, buffer_back);

        response = reinterpret_cast<llmnr_header *>(buffer.data());
        response->ancount = htons(ntohs(response->ancount) + 1);
    });

    // Sends the response.
    if (sendto(fd, buffer.data(), buffer.size(), 0, &sender) == -1) {
        if (buffer.size() > 512 && errno == EMSGSIZE) {
            // Resends with truncation.
            response->flags |= htons(LLMNR_FLAG_TC);
            sendto(fd, buffer.data(), 512, 0, &sender);
        }
    }
}

auto responder::matching_host_name(const uint8_t *const qname) const
    -> unique_ptr<uint8_t []>
{
    char host_name[LLMNR_LABEL_MAX + 1] {};
    gethostname(host_name, LLMNR_LABEL_MAX);

    auto &&host_name_length = strcspn(host_name, ".");
    host_name[host_name_length] = '\0';

    auto i = qname;
    auto j = reinterpret_cast<unsigned char *>(host_name);
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

void responder::interface_enabled(const interface_event &event)
{
    if (event.interface_index != 0) {
        char interface_name[IF_NAMESIZE] = "?";
        if_indextoname(event.interface_index, interface_name);

        const ipv6_mreq mr {
            in6addr_mc_llmnr,      // .ipv6mr_multiaddr
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

void responder::interface_disabled(const interface_event &event)
{
    if (event.interface_index != 0) {
        char interface_name[IF_NAMESIZE] = "?";
        if_indextoname(event.interface_index, interface_name);

        const ipv6_mreq mr {
            in6addr_mc_llmnr,      // .ipv6mr_multiaddr
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

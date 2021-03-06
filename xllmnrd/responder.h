// responder.h -*- C++ -*-
// Copyright (C) 2013-2021 Kaz Nishimura
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

#ifndef RESPONDER_H
#define RESPONDER_H 1

#include "llmnr_packet.h"
#include "interface.h"
#include <netinet/in.h>
#include <unistd.h>
#include <atomic>
#include <memory>

using xllmnrd::interface_event;
using xllmnrd::interface_listener;
using xllmnrd::interface_manager;


/**
 * LLMNR responder objects.
 */
class responder: public interface_listener
{
private:

    std::unique_ptr<interface_manager> _interface_manager;

    int _udp6 = -1;

    std::atomic<bool> _running {false};

protected:

    /**
     * Opens an IPv6 UDP socket for LLMNR.
     *
     * @param port a port to bind the socket, in network byte order.
     */
    [[nodiscard]]
    static int open_udp6(in_port_t port);

public:

    responder();

    explicit responder(in_port_t port);

    // This class is not copy-constructible.
    responder(const responder &) = delete;


    virtual ~responder();


    // This class is not copy-assignable.
    void operator =(const responder &) = delete;


    /**
     * Enters the responder loop.
     */
    void run();

    /**
     * Requests termination of the responder loop.
     *
     * This function is to be called by signal handlers.
     */
    void terminate();

protected:

    void process_udp6();

    ssize_t recv_udp6(void *buffer, size_t buffer_size, sockaddr_in6 &sender,
        unsigned int &ifindex);

    void handle_udp6_query(const llmnr_header *query, size_t query_size,
        const sockaddr_in6 &sender, unsigned int ifindex);

    void respond_for_name(int fd, const llmnr_header *query,
        const uint8_t *qname_end, const uint8_t *label,
        const sockaddr_in6 &sender, unsigned int interface_index);

    /**
     * Returns the matching host name, or null if nothing matches.
     */
    auto matching_host_name(const std::uint8_t *qname) const
        -> std::unique_ptr<std::uint8_t []>;

public:

    void interface_enabled(const interface_event &event) override;

    void interface_disabled(const interface_event &event) override;
};

#endif

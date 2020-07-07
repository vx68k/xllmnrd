// responder.h -*- C++ -*-
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

#ifndef RESPONDER_H
#define RESPONDER_H 1

#include "llmnr.h"
#include "interface.h"
#include <netinet/in.h>
#include <unistd.h>
#include <atomic>
#include <memory>

using namespace xllmnrd;

#if __cplusplus
#define BEGIN_C_LINKAGE extern "C" {
#define END_C_LINKAGE }
#else
#define BEGIN_C_LINKAGE
#define END_C_LINKAGE
#endif

/**
 * LLMNR responder objects.
 */
class responder
{
private:
    std::unique_ptr<interface_manager> _interface_manager;

private:
    int _udp6 = -1;

private:
    std::atomic<bool> _running;

protected:
    [[nodiscard]]
    int open_llmnr_udp6(in_port_t port);

public:
    explicit responder(in_port_t port = htons(LLMNR_PORT));

    responder(const responder &) = delete;

public:
    void operator =(const responder &) = delete;

public:
    virtual ~responder();

public:
    void run();

public:
    /**
     * Requests termination of the responder loop.
     *
     * This function is to be called by signal handlers.
     */
    void terminate();

protected:
    void process_udp6();

protected:
    ssize_t recv_udp6(void *buffer, size_t buffer_size,
        struct sockaddr_in6 &sender, struct in6_pktinfo &pktinfo);

protected:
    void handle_udp6_query(const struct llmnr_header *packet,
        size_t packet_size, const struct sockaddr_in6 &sender,
        unsigned int interface_index);
};

BEGIN_C_LINKAGE

/**
 * Initializes the responder object.
 * @param __port port number in the network byte order; if this value is 0,
 * the default port number will be used.
 * @return 0 if succeeded, or non-zero error number.
 */
int responder_initialize(in_port_t __port);

/*
 * Finalizes the responder object.
 */
void responder_finalize(void);

/**
 * Sets the host name for which the responder object is authoritative.
 * Only the first label of the host name is used.  If it is longer than
 * 'LLMNR_LABEL_MAX' octets, it will be truncated.
 * @param __name host name.
 * @return 0 if succeeded, or non-zero error number.
 */
extern void responder_set_host_name(const char *__name);

/*
 * Runs the responder in a loop.
 */
int responder_run(void);

/*
 * Requests the termination of the responder loop.
 * This function is atomic regarding signals.
 */
extern void responder_terminate(void);

END_C_LINKAGE

#undef END_C_LINKAGE
#undef BEGIN_C_LINKAGE

#endif

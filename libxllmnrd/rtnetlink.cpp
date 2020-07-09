// rtnetlink.cpp -*- C++ -*-
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

#include "rtnetlink.h"

#if XLLMNRD_RTNETLINK

#include <linux/rtnetlink.h>
#include <net/if.h> /* if_indextoname */
#include <syslog.h>
#include <vector>
#include <cstring>
#include <cerrno>
#include <cassert>

using std::generic_category;
using std::lock_guard;
using std::make_shared;
using std::runtime_error;
using std::shared_ptr;
using std::size_t;
using std::system_error;
using std::thread;
using std::unique_lock;
using std::unique_ptr;
using namespace xllmnrd;

int rtnetlink_interface_manager::open_rtnetlink(
    const shared_ptr<posix> &os)
{
    int &&rtnetlink = os->socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtnetlink < 0) {
        throw system_error(errno, generic_category(), "could not open a RTNETLINK socket");
    }

    try {
        const sockaddr_nl address = {
            AF_NETLINK, // .nl_family
            0,          // .nl_pad
            0,          // .nl_pid
            RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, // .nl_groups
        };
        if (os->bind(rtnetlink, &address) == -1) {
            throw system_error(errno, generic_category(), "could not bind the RTNETLINK socket");
        }
    }
    catch (...) {
        os->close(rtnetlink);
        throw;
    }

    return rtnetlink;
}

rtnetlink_interface_manager::rtnetlink_interface_manager()
:
    rtnetlink_interface_manager(make_shared<posix>())
{
}

rtnetlink_interface_manager::rtnetlink_interface_manager(
    const shared_ptr<posix> &os)
:
    _os {os}, _rtnetlink {open_rtnetlink(_os)}
{
}

rtnetlink_interface_manager::~rtnetlink_interface_manager()
{
    stop_worker();

    auto result = _os->close(_rtnetlink);
    if (result < 0) {
        syslog(LOG_ERR, "Failed to close the RTNETLINK socket: %s",
            strerror(errno));
    }
}

void rtnetlink_interface_manager::run()
{
    while (_running) {
        process_messages();
    }
}

void rtnetlink_interface_manager::request_ifinfos()
{
    char request[NLMSG_LENGTH(sizeof (ifinfomsg))] = {};

    auto nlmsg = reinterpret_cast<nlmsghdr *>(&request[0]);
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof (ifinfomsg));
    nlmsg->nlmsg_type = RTM_GETLINK;
    nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

    auto ifi = static_cast<ifinfomsg *>(NLMSG_DATA(nlmsg));
    ifi->ifi_family = AF_UNSPEC;

    ssize_t sent = _os->send(_rtnetlink, nlmsg, nlmsg->nlmsg_len, 0);
    if (sent == -1) {
        throw system_error(errno, generic_category(), "could not send a RTNETLINK request");
    }
}

void rtnetlink_interface_manager::request_ifaddrs()
{
    char request[NLMSG_LENGTH(sizeof (ifaddrmsg))] = {};

    auto nlmsg = reinterpret_cast<nlmsghdr *>(&request[0]);
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof (ifaddrmsg));
    nlmsg->nlmsg_type = RTM_GETADDR;
    nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

    auto ifa = static_cast<ifaddrmsg *>(NLMSG_DATA(nlmsg));
    ifa->ifa_family = AF_UNSPEC;

    ssize_t sent = _os->send(_rtnetlink, nlmsg, nlmsg->nlmsg_len, 0);
    if (sent == -1) {
        throw system_error(errno, generic_category(), "could not send a RTNETLINK request");
    }
}

void rtnetlink_interface_manager::process_messages()
{
    // Gets the required buffer size.
    auto &&packet_size = _os->recv(_rtnetlink, nullptr, 0, MSG_PEEK | MSG_TRUNC);
    if (packet_size == -1) {
        throw system_error(errno, generic_category(), "could not receive from RTNETLINK");
    }
    if (packet_size != 0) {
        unique_ptr<char []> buffer {new char [packet_size]};

        // This must not block.
        packet_size = _os->recv(_rtnetlink, buffer.get(), packet_size, 0);
        if (packet_size == -1) {
            throw system_error(errno, generic_category(), "could not receive from RTNETLINK");
        }

        dispatch_messages(buffer.get(), packet_size);
    }
}

void rtnetlink_interface_manager::dispatch_messages(const void *messages,
    size_t size)
{
    bool done = false;
    auto &&message = static_cast<const nlmsghdr *>(messages);
    while (NLMSG_OK(message, size)) {
        switch (message->nlmsg_type) {

        case NLMSG_NOOP:
            if (debug_level() >= 1) {
                syslog(LOG_DEBUG, "Got NLMSG_NOOP");
            }
            break;

        case NLMSG_DONE:
            if (!done) {
                done = true;
                end_refresh();
            }
            break;

        case NLMSG_ERROR:
            handle_error(message);
            break;

        case RTM_NEWLINK:
        case RTM_DELLINK:
            handle_ifinfo(message);
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            handle_ifaddrmsg(message);
            break;

        default:
            syslog(LOG_DEBUG, "Unknown NETLINK message type: %u",
                static_cast<unsigned int>(message->nlmsg_type));
            break;
        }

        if ((message->nlmsg_flags & NLM_F_MULTI) == 0 && !done) {
            // There should be no more messages.
            done = true;
            end_refresh();
        }
        message = NLMSG_NEXT(message, size);
    }
}

void rtnetlink_interface_manager::handle_error(const nlmsghdr *message)
{
    if (message->nlmsg_len >= NLMSG_LENGTH(sizeof (nlmsgerr))) {
        auto &&e = static_cast<const nlmsgerr *>(NLMSG_DATA(message));
        syslog(LOG_ERR, "Got NETLINK error: %s", strerror(-(e->error)));
    }
}

void rtnetlink_interface_manager::handle_ifinfo(const nlmsghdr *nlmsg)
{
    if (nlmsg->nlmsg_len >= NLMSG_LENGTH(sizeof (ifinfomsg))) {
        auto ifi = static_cast<const ifinfomsg *>(NLMSG_DATA(nlmsg));
        const unsigned int flags_mask = IFF_MULTICAST;
        if ((ifi->ifi_flags & flags_mask) == flags_mask) {
            switch (nlmsg->nlmsg_type) {
            case RTM_NEWLINK:
                syslog(LOG_DEBUG, "RTM_NEWLINK %d", ifi->ifi_index);
                break;
            case RTM_DELLINK:
                syslog(LOG_DEBUG, "RTM_DELLINK %d", ifi->ifi_index);
                break;
            }
        }
    }
}

void rtnetlink_interface_manager::handle_ifaddrmsg(const nlmsghdr *message)
{
    if (message->nlmsg_len >= NLMSG_LENGTH(sizeof (ifaddrmsg))) {
        auto ifa = static_cast<const ifaddrmsg *>(NLMSG_DATA(message));
        // Only handles non-temporary and at least link-local addresses.
        if ((ifa->ifa_flags & (IFA_F_TEMPORARY | IFA_F_TENTATIVE)) == 0
            && ifa->ifa_scope <= RT_SCOPE_LINK) {
            auto rta = reinterpret_cast<const rtattr *>(ifa + 1);
            unsigned int remains =
                message->nlmsg_len - NLMSG_LENGTH(sizeof (ifaddrmsg));
            while (RTA_OK(rta, remains)) {
                if (rta->rta_type == IFA_ADDRESS && rta->rta_len >= RTA_LENGTH(0)) {
                    switch (message->nlmsg_type) {
                    case RTM_NEWADDR:
                        add_interface_address(ifa->ifa_index,
                            ifa->ifa_family, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        break;
                    case RTM_DELADDR:
                        remove_interface_address(ifa->ifa_index,
                            ifa->ifa_family, RTA_DATA(rta), RTA_PAYLOAD(rta));
                        break;
                    }
                }

                rta = RTA_NEXT(rta, remains);
            }
        }
    }
}

void rtnetlink_interface_manager::refresh(bool maybe_asynchronous)
{
    start_worker();
    begin_refresh();

    if (not(maybe_asynchronous)) {
        unique_lock<decltype(_refresh_mutex)> lock(_refresh_mutex);

        while (_running && _refreshing) {
            _refresh_completion.wait(lock);
        }
    }
}

void rtnetlink_interface_manager::begin_refresh()
{
    lock_guard<decltype(_refresh_mutex)> lock(_refresh_mutex);

    if (not(_refreshing)) {
        _refreshing = true;

        remove_interfaces();

        request_ifaddrs();
    }
}

void rtnetlink_interface_manager::end_refresh()
{
    lock_guard<decltype(_refresh_mutex)> lock(_refresh_mutex);

    if (_refreshing) {
        _refreshing = false;
        _refresh_completion.notify_all();
    }
}

void rtnetlink_interface_manager::start_worker()
{
    lock_guard<decltype(_worker_mutex)> lock(_worker_mutex);

    if (!_worker_thread.joinable()) {
        _running.store(true);
        _worker_thread = thread(&rtnetlink_interface_manager::run, this);
    }
}

void rtnetlink_interface_manager::stop_worker()
{
    lock_guard<decltype(_worker_mutex)> lock(_worker_mutex);

    if (_worker_thread.joinable()) {
        _running.store(false);

        // This should make a blocking recv call return.
        begin_refresh();

        _worker_thread.join();
    }
}

#endif /* XLLMNRD_RTNETLINK */

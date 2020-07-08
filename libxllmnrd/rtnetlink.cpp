/*
 * rtnetlink.cpp
 * Copyright (C) 2013-2020 Kaz Nishimura
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

#include "rtnetlink.h"

#if XLLMNRD_RTNETLINK

#include <linux/rtnetlink.h>
#include <net/if.h> /* if_indextoname */
#include <syslog.h>
#include <vector>
#include <cstring>
#include <cstdlib> /* abort */
#include <cerrno>
#include <cassert>

using std::generic_category;
using std::system_error;
using namespace xllmnrd;

int rtnetlink_interface_manager::open_rtnetlink(
    const std::shared_ptr<posix> &os)
{
    int &&rtnetlink = os->socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtnetlink < 0) {
        throw system_error(errno, generic_category(), "could not open a RTNETLINK socket");
    }

    try {
        const struct sockaddr_nl address = {
            AF_NETLINK, // .nl_family
            0,          // .nl_pad
            0,          // .nl_pid
            RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, // .nl_groups
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
    rtnetlink_interface_manager(std::make_shared<posix>())
{
}

rtnetlink_interface_manager::rtnetlink_interface_manager(
    const std::shared_ptr<posix> &os)
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
    while (_worker_running) {
        process_messages();
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
        std::unique_ptr<char []> buffer {new char [packet_size]};

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
    auto &&message = static_cast<const struct nlmsghdr *>(messages);
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
    if (message->nlmsg_len >= NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
        auto &&e = static_cast<const struct nlmsgerr *>(NLMSG_DATA(message));
        syslog(LOG_ERR, "Got NETLINK error: %s", strerror(-(e->error)));
    }
}

void rtnetlink_interface_manager::handle_ifaddrmsg(const nlmsghdr *message)
{
    // Uses 'NLMSG_SPACE' instead of 'NLMSG_LENGTH' since the payload must be
    // aligned.
    auto &&rtattr_offset = NLMSG_SPACE(sizeof (struct ifaddrmsg));
    if (message->nlmsg_len >= rtattr_offset) {
        auto &&ifaddrmsg = static_cast<const struct ifaddrmsg *>(
            NLMSG_DATA(message));
        // Only handles non-temporary and at least link-local addresses.
        if ((ifaddrmsg->ifa_flags & (IFA_F_TEMPORARY | IFA_F_TENTATIVE)) == 0
            && ifaddrmsg->ifa_scope <= RT_SCOPE_LINK) {
            auto &&rtattr = reinterpret_cast<const struct rtattr *>(
                    reinterpret_cast<const char *>(message) + rtattr_offset);
            std::size_t rtattr_size = message->nlmsg_len - rtattr_offset;

            while (RTA_OK(rtattr, rtattr_size)) {
                if (rtattr->rta_type == IFA_ADDRESS
                    && rtattr->rta_len >= RTA_LENGTH(0)) {
                    auto &&addr = RTA_DATA(rtattr);
                    switch (message->nlmsg_type) {
                    case RTM_NEWADDR:
                        add_interface_address(ifaddrmsg->ifa_index,
                            ifaddrmsg->ifa_family, addr, RTA_PAYLOAD(rtattr));
                        break;

                    case RTM_DELADDR:
                        remove_interface_address(ifaddrmsg->ifa_index,
                            ifaddrmsg->ifa_family, addr, RTA_PAYLOAD(rtattr));
                        break;
                    }
                }

                rtattr = RTA_NEXT(rtattr, rtattr_size);
            }
        }
    }
}

void rtnetlink_interface_manager::refresh(bool maybe_asynchronous)
{
    start_worker();
    begin_refresh();

    if (not(maybe_asynchronous)) {
        std::unique_lock<std::mutex> lock(_refresh_mutex);

        while (_worker_running && _refreshing) {
            _refresh_completion.wait(lock);
        }
    }
}

void rtnetlink_interface_manager::begin_refresh()
{
    std::lock_guard<std::mutex> lock(_refresh_mutex);

    if (not(_refreshing)) {
        _refreshing = true;

        remove_interfaces();

        unsigned char buffer[NLMSG_LENGTH(sizeof (ifaddrmsg))];
        nlmsghdr *nl = reinterpret_cast<nlmsghdr *>(buffer);
        *nl = nlmsghdr();
        nl->nlmsg_len = NLMSG_LENGTH(sizeof (ifaddrmsg));
        nl->nlmsg_type = RTM_GETADDR;
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

        ifaddrmsg *ifa = static_cast<ifaddrmsg *>(NLMSG_DATA(nl));
        *ifa = ifaddrmsg();
        ifa->ifa_family = AF_UNSPEC;

        ssize_t send_size = _os->send(_rtnetlink, nl, nl->nlmsg_len, 0);
        if (send_size < 0) {
            syslog(LOG_ERR, "Failed to send to RTNETLINK: %s",
                    strerror(errno));
            throw system_error(errno, generic_category(), "could not send to RTNETLINK");
        }
        else if (send_size != ssize_t(nl->nlmsg_len)) {
            syslog(LOG_CRIT, "RTNETLINK request truncated");
            throw std::runtime_error("RTNETLINK request truncated");
        }
    }
}

void rtnetlink_interface_manager::end_refresh()
{
    std::lock_guard<std::mutex> lock(_refresh_mutex);

    if (_refreshing) {
        _refreshing = false;
        _refresh_completion.notify_all();
    }
}

void rtnetlink_interface_manager::start_worker()
{
    std::lock_guard<std::mutex> lock(_worker_mutex);

    if (!_worker_thread.joinable()) {
        _worker_running = true;
        _worker_thread = std::thread(&rtnetlink_interface_manager::run, this);
    }
}

void rtnetlink_interface_manager::stop_worker()
{
    std::lock_guard<std::mutex> lock(_worker_mutex);

    _worker_running = false;
    if (_worker_thread.joinable()) {
        // This should make a blocking recv call return.
        begin_refresh();

        _worker_thread.join();
    }
}

#endif /* XLLMNRD_RTNETLINK */

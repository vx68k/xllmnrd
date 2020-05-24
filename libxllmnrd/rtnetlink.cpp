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

#if HAVE_LINUX_RTNETLINK_H

#include <linux/rtnetlink.h>
#include <net/if.h> /* if_indextoname */
#include <syslog.h>
#include <vector>
#include <cstring>
#include <cstdlib> /* abort */
#include <cerrno>
#include <cassert>

using namespace xllmnrd;

int rtnetlink_interface_manager::open_rtnetlink(
    const std::shared_ptr<posix> &os)
{
    int &&rtnetlink = os->socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (rtnetlink < 0) {
        throw std::runtime_error(std::strerror(errno));
    }

    try {
        const struct sockaddr_nl address = {
            AF_NETLINK, // .nl_family
            0,          // .nl_pad
            0,          // .nl_pid
            RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, // .nl_groups
        };

        auto &&result = os->bind(rtnetlink,
            reinterpret_cast<const struct sockaddr *>(&address),
            sizeof (struct sockaddr_nl));
        if (result < 0) {
            throw std::runtime_error(std::strerror(errno));
        }
    }
    catch (...) {
        os->close(rtnetlink);
        throw;
    }

    return rtnetlink;
}

rtnetlink_interface_manager::rtnetlink_interface_manager()
    : rtnetlink_interface_manager(std::make_shared<posix>())
{
}

rtnetlink_interface_manager::rtnetlink_interface_manager(
    const std::shared_ptr<posix> &os)
    : _os {os}, _rtnetlink {open_rtnetlink(_os)}
{
}

rtnetlink_interface_manager::~rtnetlink_interface_manager()
{
    stop();

    auto result = _os->close(_rtnetlink);
    if (result < 0) {
        syslog(LOG_ERR, "Failed to close the RTNETLINK socket: %s",
            strerror(errno));
    }
}

void rtnetlink_interface_manager::finish_refresh()
{
    std::unique_lock<std::mutex> lock(refresh_mutex);

    refresh_in_progress = false;
    refresh_finished.notify_all();
}

void rtnetlink_interface_manager::run()
{
    while (!worker_stopped) {
        receive_netlink(_rtnetlink, &worker_stopped);
    }
}

void rtnetlink_interface_manager::receive_netlink(int fd,
        volatile std::atomic_bool *stopped)
{
    // Gets the required buffer size.
    ssize_t recv_size = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
    if (!stopped || !*stopped) {
        if (recv_size < 0) {
            syslog(LOG_ERR, "Failed to recv from RTNETLINK: %s",
                    strerror(errno));
            throw std::system_error(errno, std::generic_category());
        }

        std::vector<unsigned char> buffer(recv_size);
        // This must not block.
        recv_size = recv(fd, buffer.data(), recv_size, 0);
        if (recv_size < 0) {
            syslog(LOG_ERR, "Failed to recv from RTNETLINK: %s",
                    strerror(errno));
            throw std::system_error(errno, std::generic_category());
        }

        decode_nlmsg(buffer.data(), recv_size);
    }
}

void rtnetlink_interface_manager::decode_nlmsg(const void *data, size_t size)
{
    auto nlmsg = static_cast<const nlmsghdr *>(data);

    while (NLMSG_OK(nlmsg, size)) {
        bool done = false;

        switch (nlmsg->nlmsg_type) {
        case NLMSG_NOOP:
            syslog(LOG_INFO, "Got NLMSG_NOOP");
            break;

        case NLMSG_ERROR:
            handle_nlmsgerr(nlmsg);
            break;

        case NLMSG_DONE:
            finish_refresh();
            done = true;
            break;

        case RTM_NEWADDR:
        case RTM_DELADDR:
            handle_ifaddrmsg(nlmsg);
            break;

        default:
            syslog(LOG_DEBUG, "Unknown netlink message type: %u",
                    (unsigned int) nlmsg->nlmsg_type);
            break;
        }

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0 || done) {
            // There are no more messages.
            break;
        }
        nlmsg = NLMSG_NEXT(nlmsg, size);
    }
}

void rtnetlink_interface_manager::handle_nlmsgerr(const nlmsghdr *nlmsg)
{
    auto &&err = static_cast<const struct nlmsgerr *>(NLMSG_DATA(nlmsg));
    if (nlmsg->nlmsg_len >= NLMSG_LENGTH(sizeof (struct nlmsgerr))) {
        syslog(LOG_ERR, "Got RTNETLINK error: %s", strerror(-(err->error)));
    }
}

void rtnetlink_interface_manager::handle_ifaddrmsg(const nlmsghdr *nlmsg)
{
    // Uses 'NLMSG_SPACE' instead of 'NLMSG_LENGTH' since the payload must be
    // aligned.
    auto &&rtattr_offset = NLMSG_SPACE(sizeof (struct ifaddrmsg));
    if (nlmsg->nlmsg_len >= rtattr_offset) {
        auto &&ifaddrmsg = static_cast<const struct ifaddrmsg *>(
            NLMSG_DATA(nlmsg));
        // Only handles non-temporary and at least link-local addresses.
        if ((ifaddrmsg->ifa_flags & (IFA_F_TEMPORARY | IFA_F_TENTATIVE)) == 0
            && ifaddrmsg->ifa_scope <= RT_SCOPE_LINK) {
            auto &&rtattr = reinterpret_cast<const struct rtattr *>(
                    reinterpret_cast<const char *>(nlmsg) + rtattr_offset);
            std::size_t rtattr_size = nlmsg->nlmsg_len - rtattr_offset;

            while (RTA_OK(rtattr, rtattr_size)) {
                if (rtattr->rta_type == IFA_ADDRESS
                    && rtattr->rta_len >= RTA_LENGTH(0)) {
                    auto &&addr = RTA_DATA(rtattr);
                    switch (nlmsg->nlmsg_type) {
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

void rtnetlink_interface_manager::add_interface_address(unsigned int index,
    int family, const void *address, std::size_t address_size)
{
    // TODO: Implement this function.
    char ifname[IF_NAMESIZE];
    switch (family) {
    case AF_INET:
        break;

    case AF_INET6:
        break;

    default:
        if_indextoname(index, ifname);
        syslog(LOG_INFO, "Ignored unknown address family %d on %s",
            family, ifname);
        break;
    }
}

void rtnetlink_interface_manager::remove_interface_address(unsigned int index,
    int family, const void *address, std::size_t address_size)
{
    // TODO: Implement this function.
    char ifname[IF_NAMESIZE];
    switch (family) {
    case AF_INET:
        break;

    case AF_INET6:
        break;

    default:
        if_indextoname(index, ifname);
        syslog(LOG_INFO, "Ignored unknown address family %d on %s",
            family, ifname);
        break;
    }
}

void rtnetlink_interface_manager::refresh()
{
    std::unique_lock<std::mutex> lock(refresh_mutex);

    if (!refresh_in_progress) {
        interface_addresses.clear();

        unsigned char buffer[NLMSG_LENGTH(sizeof (ifaddrmsg))];
        nlmsghdr *nl = reinterpret_cast<nlmsghdr *>(buffer);
        *nl = nlmsghdr();
        nl->nlmsg_len = NLMSG_LENGTH(sizeof (ifaddrmsg));
        nl->nlmsg_type = RTM_GETADDR;
        nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

        ifaddrmsg *ifa = static_cast<ifaddrmsg *>(NLMSG_DATA(nl));
        *ifa = ifaddrmsg();
        ifa->ifa_family = AF_UNSPEC;

        ssize_t send_size = send(_rtnetlink, nl, nl->nlmsg_len, 0);
        if (send_size < 0) {
            syslog(LOG_ERR, "Failed to send to RTNETLINK: %s",
                    strerror(errno));
            throw std::system_error(errno, std::generic_category());
        } else if (send_size != ssize_t(nl->nlmsg_len)) {
            syslog(LOG_CRIT, "RTNETLINK request truncated");
            throw std::runtime_error("RTNETLINK request truncated");
        }

        refresh_in_progress = true;
    }
}

void rtnetlink_interface_manager::start()
{
    std::lock_guard<std::mutex> lock(worker_mutex);

    if (!worker_thread.joinable()) {
        // Implementation note:
        // <code>operator=</code> of volatile atomic classes are somehow
        // deleted on GCC 4.7.
        worker_stopped.store(false);
        worker_thread = std::thread([this]() {
            run();
        });

        refresh();
    }
}

void rtnetlink_interface_manager::stop()
{
    std::lock_guard<std::mutex> lock(worker_mutex);

    // Implementation note:
    // <code>operator=</code> of volatile atomic classes are somehow deleted
    // on GCC 4.7.
    worker_stopped.store(true);
    if (worker_thread.joinable()) {
        // This should make a blocking recv call return.
        refresh();

        worker_thread.join();
    }
}

#endif /* HAVE_LINUX_RTNETLINK_H */

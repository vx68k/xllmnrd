/*
 * interface.cpp
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

#include "interface.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <syslog.h>
#include <cstring>
#include <cassert>

using namespace xllmnrd;

/*
 * Methods of the 'std::less' specializations.
 */

bool std::less<struct in_addr>::operator ()(
    const struct in_addr &x, const struct in_addr &y) const
{
    return std::memcmp(&x, &y, sizeof (struct in_addr)) < 0;
}

bool std::less<struct in6_addr>::operator ()(
    const struct in6_addr &x, const struct in6_addr &y) const
{
    return std::memcmp(&x, &y, sizeof (struct in6_addr)) < 0;
}

interface_manager::interface_manager()
{
}

interface_manager::~interface_manager()
{
    remove_interfaces();
}

interface_change_handler interface_manager::set_interface_change(
    interface_change_handler interface_change)
{
    std::lock_guard<decltype(mutex())> lock {mutex()};

    auto previous_interface_change = _interface_change;
    _interface_change = interface_change;
    return previous_interface_change;
}

void interface_manager::remove_interfaces()
{
    std::lock_guard<decltype(mutex())> lock {mutex()};

    // TODO: Implement this function.
    _interfaces.clear();
}

void interface_manager::add_interface_address(unsigned int index,
    int family, const void *address, std::size_t address_size)
{
    char interface_name[IF_NAMESIZE];
    if_indextoname(index, interface_name);

    std::lock_guard<decltype(mutex())> lock {mutex()};

    switch (family) {
    case AF_INET:
        if (address_size >= sizeof (struct in_addr)) {
            auto &addrs = _interfaces[index].in_addrs;
            addrs.insert(*static_cast<const struct in_addr *>(address));

            char ipv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, address, ipv4, INET_ADDRSTRLEN);
            syslog(LOG_DEBUG, "Added an IPv4 address %s on %s", ipv4,
                interface_name);
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv4 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    case AF_INET6:
        if (address_size >= sizeof (struct in6_addr)) {
            auto &addrs = _interfaces[index].in6_addrs;
            addrs.insert(*static_cast<const struct in6_addr *>(address));

            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, address, ipv6, INET6_ADDRSTRLEN);
            syslog(LOG_DEBUG, "Added an IPv6 address %s on %s", ipv6,
                interface_name);
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv6 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    default:
        syslog(LOG_INFO, "Ignored an address of unknown family %d on %s",
            family, interface_name);
        break;
    }
}

void interface_manager::remove_interface_address(unsigned int index,
    int family, const void *address, std::size_t address_size)
{
    char interface_name[IF_NAMESIZE];
    if_indextoname(index, interface_name);

    std::lock_guard<decltype(mutex())> lock {mutex()};

    switch (family) {
    case AF_INET:
        if (address_size >= sizeof (struct in_addr)) {
            auto &addrs = _interfaces[index].in_addrs;
            addrs.erase(*static_cast<const struct in_addr *>(address));

            char ipv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, address, ipv4, INET_ADDRSTRLEN);
            syslog(LOG_DEBUG, "Removed an IPv4 address %s on %s", ipv4,
                interface_name);
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv4 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    case AF_INET6:
        if (address_size >= sizeof (struct in6_addr)) {
            auto &addrs = _interfaces[index].in6_addrs;
            addrs.erase(*static_cast<const struct in6_addr *>(address));

            char ipv6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, address, ipv6, INET6_ADDRSTRLEN);
            syslog(LOG_DEBUG, "Removed an IPv6 address %s on %s", ipv6,
                interface_name);
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv6 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    default:
        syslog(LOG_INFO, "Ignored an address of unknown family %d on %s",
            family, interface_name);
        break;
    }

    auto &&found = _interfaces.find(index);
    if (found != _interfaces.end() && found->second.empty()) {
        _interfaces.erase(found);
    }
}

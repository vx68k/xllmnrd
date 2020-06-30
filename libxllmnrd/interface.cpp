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
#include <algorithm>
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
    const interface_change_handler interface_change)
{
    return this->_interface_change.exchange(interface_change);
}

void interface_manager::fire_interface_change(
    const interface_change_event *const event)
{
    auto &&handler = _interface_change.load();
    if (handler != nullptr) {
        handler(event);
    }
}

std::set<struct in_addr> interface_manager::in_addresses(
    const unsigned int index) const
{
    std::lock_guard<decltype(_interfaces_mutex)> lock(_interfaces_mutex);

    auto &&found = _interfaces.find(index);
    if (found != _interfaces.end()) {
        return found->second.in_addresses;
    }

    return std::set<struct in_addr>();
}

std::set<struct in6_addr> interface_manager::in6_addresses(
    const unsigned int index) const
{
    std::lock_guard<decltype(_interfaces_mutex)> lock(_interfaces_mutex);

    auto &&found = _interfaces.find(index);
    if (found != _interfaces.end()) {
        return found->second.in6_addresses;
    }

    return std::set<struct in6_addr>();
}

void interface_manager::remove_interfaces()
{
    std::lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    std::for_each(_interfaces.begin(), _interfaces.end(),
        [this](decltype(_interfaces)::reference i) {
            if (i.second.in6_addresses.size() != 0) {
                interface_change_event event {
                    interface_change_event::REMOVED, i.first, AF_INET6};
                fire_interface_change(&event);
            }
            if (i.second.in_addresses.size() != 0) {
                interface_change_event event {
                    interface_change_event::REMOVED, i.first, AF_INET};
                fire_interface_change(&event);
            }
        });

    _interfaces.clear();
}

void interface_manager::add_interface_address(unsigned int index,
    int family, const void *address, std::size_t address_size)
{
    char interface_name[IF_NAMESIZE];
    if_indextoname(index, interface_name);

    std::lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    switch (family) {
    case AF_INET:
        if (address_size >= sizeof (struct in_addr)) {
            auto &addresses = _interfaces[index].in_addresses;
            auto &&inserted = addresses.insert(
                *static_cast<const struct in_addr *>(address));

            if (debug_level() >= 0) {
                char ipv4[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, address, ipv4, INET_ADDRSTRLEN);
                syslog(LOG_DEBUG, "IPv4 address %s added on %s", ipv4,
                    interface_name);
            }

            if (inserted.second && addresses.size() == 1) {
                interface_change_event event {
                    interface_change_event::ADDED, index, AF_INET};
                fire_interface_change(&event);
            }
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv4 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    case AF_INET6:
        if (address_size >= sizeof (struct in6_addr)) {
            auto &addresses = _interfaces[index].in6_addresses;
            auto &&inserted = addresses.insert(
                *static_cast<const struct in6_addr *>(address));

            if (debug_level() >= 0) {
                char ipv6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, address, ipv6, INET6_ADDRSTRLEN);
                syslog(LOG_DEBUG, "IPv6 address %s added on %s", ipv6,
                    interface_name);
            }

            if (inserted.second && addresses.size() == 1) {
                interface_change_event event {
                    interface_change_event::ADDED, index, AF_INET6};
                fire_interface_change(&event);
            }
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

    std::lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    switch (family) {
    case AF_INET:
        if (address_size >= sizeof (struct in_addr)) {
            auto &addresses = _interfaces[index].in_addresses;
            auto &&erased = addresses.erase(
                *static_cast<const struct in_addr *>(address));

            if (debug_level() >= 0) {
                char ipv4[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, address, ipv4, INET_ADDRSTRLEN);
                syslog(LOG_DEBUG, "IPv4 address %s removed on %s", ipv4,
                    interface_name);
            }

            if (erased != 0 && addresses.empty()) {
                interface_change_event event {
                    interface_change_event::REMOVED, index, AF_INET};
                fire_interface_change(&event);
            }
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv4 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    case AF_INET6:
        if (address_size >= sizeof (struct in6_addr)) {
            auto &addresses = _interfaces[index].in6_addresses;
            auto &&erased = addresses.erase(
                *static_cast<const struct in6_addr *>(address));

            if (debug_level() >= 0) {
                char ipv6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, address, ipv6, INET6_ADDRSTRLEN);
                syslog(LOG_DEBUG, "IPv6 address %s removed on %s", ipv6,
                    interface_name);
            }

            if (erased != 0 && addresses.empty()) {
                interface_change_event event {
                    interface_change_event::REMOVED, index, AF_INET6};
                fire_interface_change(&event);
            }
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

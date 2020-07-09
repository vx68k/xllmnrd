// interface.cpp
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

#include "interface.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <syslog.h>
#include <algorithm>
#include <cstring>
#include <cassert>

using std::for_each;
using std::lock_guard;
using std::memcmp;
using std::set;
using std::size_t;
using namespace xllmnrd;

/*
 * Methods of the 'std::less' specializations.
 */

bool std::less<in_addr>::operator ()(
    const in_addr &x, const in_addr &y) const
{
    return memcmp(&x, &y, sizeof (in_addr)) < 0;
}

bool std::less<in6_addr>::operator ()(
    const in6_addr &x, const in6_addr &y) const
{
    return memcmp(&x, &y, sizeof (in6_addr)) < 0;
}

interface_manager::interface_manager()
{
}

interface_manager::~interface_manager()
{
    remove_interfaces();
}

void interface_manager::add_interface_listener(interface_listener *listener)
{
    interface_listener *expected = nullptr;
    _interface_listener.compare_exchange_weak(expected, listener);
}

void interface_manager::remove_interface_listener(interface_listener *listener)
{
    interface_listener *expected = listener;
    _interface_listener.compare_exchange_weak(expected, nullptr);
}

void interface_manager::fire_interface_added(const interface_event &event)
{
    auto &&listener = _interface_listener.load();
    if (listener != nullptr) {
        listener->interface_added(event);
    }
}

void interface_manager::fire_interface_removed(const interface_event &event)
{
    auto &&listener = _interface_listener.load();
    if (listener != nullptr) {
        listener->interface_removed(event);
    }
}

set<in_addr> interface_manager::in_addresses(
    const unsigned int index) const
{
    lock_guard<decltype(_interfaces_mutex)> lock(_interfaces_mutex);

    auto &&found = _interfaces.find(index);
    if (found != _interfaces.end()) {
        return found->second.in_addresses;
    }

    return set<in_addr>();
}

set<in6_addr> interface_manager::in6_addresses(
    const unsigned int index) const
{
    lock_guard<decltype(_interfaces_mutex)> lock(_interfaces_mutex);

    auto &&found = _interfaces.find(index);
    if (found != _interfaces.end()) {
        return found->second.in6_addresses;
    }

    return set<in6_addr>();
}

void interface_manager::remove_interfaces()
{
    lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    for_each(_interfaces.begin(), _interfaces.end(),
        [this](decltype(_interfaces)::reference i) {
            if (i.second.in6_addresses.size() != 0) {
                fire_interface_removed({i.first, AF_INET6});
            }
            if (i.second.in_addresses.size() != 0) {
                fire_interface_removed({i.first, AF_INET});
            }
        });

    _interfaces.clear();
}

void interface_manager::enable_interface(const unsigned int interface_index)
{
    lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    auto &interface = _interfaces[interface_index];
    if (not(interface.enabled)) {
        interface.enabled = true;

        if (debug_level() >= 0) {
            char interface_name[IF_NAMESIZE];
            if_indextoname(interface_index, interface_name);
            syslog(LOG_DEBUG, "device enabled: %s", interface_name);
        }
    }
}

void interface_manager::disable_interface(const unsigned int interface_index)
{
    lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    auto &interface = _interfaces[interface_index];
    if (interface.enabled) {
        interface.enabled = false;

        if (debug_level() >= 0) {
            char interface_name[IF_NAMESIZE];
            if_indextoname(interface_index, interface_name);
            syslog(LOG_DEBUG, "device disabled: %s", interface_name);
        }
    }
}

void interface_manager::add_interface_address(unsigned int index,
    int family, const void *address, size_t address_size)
{
    char interface_name[IF_NAMESIZE];
    if_indextoname(index, interface_name);

    lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    switch (family) {
    case AF_INET:
        if (address_size >= sizeof (in_addr)) {
            auto &addresses = _interfaces[index].in_addresses;
            auto &&inserted = addresses.insert(
                *static_cast<const in_addr *>(address));

            if (inserted.second) {
                if (debug_level() >= 0) {
                    char ipv4[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, address, ipv4, INET_ADDRSTRLEN);
                    syslog(LOG_DEBUG, "IPv4 address %s added on %s", ipv4,
                        interface_name);
                }

                if (addresses.size() == 1) {
                    fire_interface_added({index, AF_INET});
                }
            }
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv4 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    case AF_INET6:
        if (address_size >= sizeof (in6_addr)) {
            auto &addresses = _interfaces[index].in6_addresses;
            auto &&inserted = addresses.insert(
                *static_cast<const in6_addr *>(address));

            if (inserted.second) {
                if (debug_level() >= 0) {
                    char ipv6[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, address, ipv6, INET6_ADDRSTRLEN);
                    syslog(LOG_DEBUG, "IPv6 address %s added on %s", ipv6,
                        interface_name);
                }

                if (addresses.size() == 1) {
                    fire_interface_added({index, AF_INET6});
                }
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
    int family, const void *address, size_t address_size)
{
    char interface_name[IF_NAMESIZE];
    if_indextoname(index, interface_name);

    lock_guard<decltype(_interfaces_mutex)> lock {_interfaces_mutex};

    switch (family) {
    case AF_INET:
        if (address_size >= sizeof (in_addr)) {
            auto &addresses = _interfaces[index].in_addresses;
            auto &&erased = addresses.erase(
                *static_cast<const in_addr *>(address));

            if (erased != 0) {
                if (debug_level() >= 0) {
                    char ipv4[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, address, ipv4, INET_ADDRSTRLEN);
                    syslog(LOG_DEBUG, "IPv4 address %s removed on %s", ipv4,
                        interface_name);
                }

                if (addresses.empty()) {
                    fire_interface_removed({index, AF_INET});
                }
            }
        }
        else {
            syslog(LOG_INFO, "Ignored a short IPv4 address (size = %zu) on %s",
                address_size, interface_name);
        }
        break;

    case AF_INET6:
        if (address_size >= sizeof (in6_addr)) {
            auto &addresses = _interfaces[index].in6_addresses;
            auto &&erased = addresses.erase(
                *static_cast<const in6_addr *>(address));

            if (erased != 0) {
                if (debug_level() >= 0) {
                    char ipv6[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, address, ipv6, INET6_ADDRSTRLEN);
                    syslog(LOG_DEBUG, "IPv6 address %s removed on %s", ipv6,
                        interface_name);
                }

                if (addresses.empty()) {
                    fire_interface_removed({index, AF_INET6});
                }
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

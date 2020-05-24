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

#include <cstring>
#include <cassert>

using namespace xllmnrd;

constexpr bool std::less<struct in_addr>::operator ()(
    const struct in_addr &x, const struct in_addr &y) const
{
    return std::memcmp(&x, &y, sizeof (struct in_addr)) < 0;
}

constexpr bool std::less<struct in6_addr>::operator ()(
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

void interface_manager::set_change_handler(ifaddr_change_handler change_handler,
        ifaddr_change_handler *old_change_handler)
{
    std::lock_guard<decltype(object_mutex)> lock(object_mutex);

    if (old_change_handler) {
        *old_change_handler = this->change_handler;
    }
    this->change_handler = change_handler;
}

void interface_manager::remove_interfaces()
{
    // TODO: Implement this function.
    _interfaces.clear();
}

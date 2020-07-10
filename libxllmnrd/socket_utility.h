// socket_utility.h -*- C++ -*-
// Copyright (C) 2020 Kaz Nishimura
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

#ifndef SOCKET_UTILITY_H
#define SOCKET_UTILITY_H 1

#include <sys/socket.h>

template<class T>
inline int bind(const int fd, const T *const addr)
{
    return bind(fd, reinterpret_cast<const sockaddr *>(addr), sizeof *addr);
}

template<class T>
inline int setsockopt(const int fd, const int level, const int option,
    const T *const value)
{
    return setsockopt(fd, level, option, value, sizeof *value);
}

/**
 * Typed wrapper function for 'sendto'.
 */
template<class T>
inline ssize_t sendto(const int fd, const void *const buf, const size_t n,
    const int flags, const T *const addr)
{
    return sendto(fd, buf, n, flags, reinterpret_cast<const sockaddr *>(addr),
        sizeof *addr);
}

#endif

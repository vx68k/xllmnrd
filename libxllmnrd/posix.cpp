// posix.cpp
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "posix.h"

#include <unistd.h>

using namespace xllmnrd;


// Implementation of class 'default_posix'

int default_posix::socket(const int domain, const int type, const int protocol)
{
    return ::socket(domain, type, protocol);
}

int default_posix::bind(const int socket, const sockaddr *const address,
    const socklen_t address_len)
{
    return ::bind(socket, address, address_len);
}

int default_posix::close(const int fildes)
{
    return ::close(fildes);
}

ssize_t default_posix::recv(const int socket, void *const buffer,
    const ::size_t length, const int flags)
{
    return ::recv(socket, buffer, length, flags);
}

ssize_t default_posix::send(const int socket, const void *const buffer,
    const ::size_t length, const int flags)
{
    return ::send(socket, buffer, length, flags);
}

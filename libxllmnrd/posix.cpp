/*
 * posix.cpp
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

#include "posix.h"

#include <unistd.h>

using namespace xllmnrd;

posix::~posix()
{
}

int posix::socket(int domain, int type, int protocol)
{
    return ::socket(domain, type, protocol);
}

int posix::bind(int fd, const sockaddr *addr, socklen_t len)
{
    return ::bind(fd, addr, len);
}

int posix::close(int fd)
{
    return ::close(fd);
}

ssize_t posix::recv(int fd, void *buf, ::size_t n, int flags)
{
    return ::recv(fd, buf, n, flags);
}

ssize_t posix::send(int fd, const void *buf, ::size_t n, int flags)
{
    return ::send(fd, buf, n, flags);
}

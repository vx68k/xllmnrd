/*
 * posix.h
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

#ifndef POSIX_H
#define POSIX_H 1

#include <sys/socket.h>

namespace xllmnrd
{
    class posix
    {
    public:
        virtual ~posix();

    public:
        virtual int socket(int domain, int type, int protocol);
        virtual int bind(int fd, const struct sockaddr *addr, socklen_t len);

        template<class T>
        int bind(int fd, T *addr) {
            return bind(fd, reinterpret_cast<const struct sockaddr *>(addr),
                sizeof *addr);
        }

        virtual int close(int fd);

        /// Receives a message from a socket.
        ///
        /// This implementations calls '::recv'.
        virtual ssize_t recv(int fd, void *buf, ::size_t n, int flags);

        /// Send a message to a socket.
        ///
        /// This implementation calls '::send'.
        virtual ssize_t send(int fd, const void *buf, ::size_t n, int flags);
    };
}

#endif

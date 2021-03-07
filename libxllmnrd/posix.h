// posix.h -*- C++ -*-
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

#ifndef POSIX_H
#define POSIX_H 1

#include <sys/socket.h>

namespace xllmnrd
{
    /**
     * Operating system interface.
     */
    class posix
    {
    protected:

        // Constructors.

        posix() = default;

        posix(const posix &) = delete;

    public:

        // Destructor.

        virtual ~posix() = default;


        // Assignment operators.

        void operator =(const posix &) = delete;


        virtual int socket(int domain, int type, int protocol) = 0;

        virtual int bind(int socket, const sockaddr *address,
            socklen_t address_len) = 0;

        template<class T>
        int bind(int socket, T *address) {
            return bind(socket, reinterpret_cast<const sockaddr *>(address),
                sizeof *address);
        }

        /**
         * Closes a file descriptor.
         *
         * @param fildes a file descriptor to be closed
         */
        virtual int close(int fildes) = 0;

        /// Receives a message from a socket.
        ///
        /// This implementations calls '::recv'.
        virtual ::ssize_t recv(int socket, void *buffer, ::size_t length,
            int flags) = 0;

        /// Send a message to a socket.
        ///
        /// This implementation calls '::send'.
        virtual ::ssize_t send(int socket, const void *buffer, ::size_t length,
            int flags) = 0;
    };


    /**
     * Default POSIX implementation.
     */
    class default_posix: public posix
    {
    public:

        int socket(int domain, int type, int protocol) override;

        int bind(int socket, const sockaddr *address,
            socklen_t address_len) override;

        int close(int fildes) override;

        ::ssize_t recv(int socket, void *buffer, ::size_t length,
            int flags) override;

        ::ssize_t send(int socket, const void *buffer, ::size_t length,
            int flags) override;
    };
}

#endif

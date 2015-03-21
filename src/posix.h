/*
 * posix - POSIX class (interface)
 * Copyright (C) 2013-2015 Kaz Nishimura
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

namespace xllmnrd {

    class posix {
    public:
        virtual ~posix();

        virtual int socket(int __domain, int __type, int __protocol);
        virtual int close(int __fd);
    };
}

#endif

/*
 * Dependencies for ifaddr (interface)
 * Copyright (C) 2013-2014 Kaz Nishimura
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

#ifndef IFADDR_DEPS_H
#define IFADDR_DEPS_H 1

/**
 * Function dependencies for the 'ifaddr' unit.
 */
struct ifaddr_deps {
    int (*close)(int __fd);
    int (*socket)(int __domain, int __type, int __protocol);
};

/**
 * Initializes dependencies with their default values.
 * @param __deps pointer to a dependency record.
 */
extern void ifaddr_deps_init(struct ifaddr_deps *__deps);

#endif

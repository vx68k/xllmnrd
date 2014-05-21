/*
 * Interface address lookups (interface)
 * Copyright (C) 2013  Kaz Nishimura
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

#ifndef IFADDR_H
#define IFADDR_H 1

#include <netinet/in.h>

enum ifaddr_change_type {
    IFADDR_ADDED,
    IFADDR_REMOVED,
};

struct ifaddr_change {
    enum ifaddr_change_type type;
    unsigned int ifindex;
};

/**
 * Function dependencies.
 */
struct ifaddr_deps {
    int (*close)(int __fd);
    int (*socket)(int __domain, int __type, __protocol);
};

typedef void (*ifaddr_change_handler)(const struct ifaddr_change *);

/**
 * Initializes this module.
 * @param __sig signal number that will be used to interrupt the worker
 * thread; if its value is 0, no signal will be used.
 * @param __deps dependencies for this module; if its value is NULL, default
 * dependencies will be used.
 * @return 0 if no error is detected, 'EBUSY' if this module is already
 * initialized, or any non-zero error number.
 */
extern int ifaddr_initialize(int __sig, const struct ifaddr_deps *__deps);

extern void ifaddr_finalize(void);

/**
 * Sets the interface change handler.
 * It will be called on each interface address change.
 * No handler function is set right after initialization.
 * @param __handler pointer to the handler function; if its value is null, no
 * handler function will be called.
 * @param __old_handler [out] pointer to the old handler function; if its
 * value is null, no output will be retrieved.
 * @return 0 if no error is detected, or any non-zero error number.
 */
extern int ifaddr_set_change_handler(ifaddr_change_handler __handler,
        ifaddr_change_handler *__old_handler);

/**
 * Starts the internal worker thread.
 * This module MUST be initialized.
 * This function will do nothing and return 0 if already started.
 * @return 0 if no error is detected, or any non-zero error number.
 */
extern int ifaddr_start(void);

/**
 * Refreshes the interface table.
 * This module MUST be initialized and started.
 * @return 0 if no error is detected, 'ENXIO' if this module is not started,
 * or any non-zero error number.
 */
extern int ifaddr_refresh(void);

/**
 * Looks up the address of an interface.
 * This module MUST be initialized and started.
 * @param __ifindex interface index.
 * @param __addr [out] interface address; if its value is null, no output will
 * be retrieved.
 * @return 0 if any address is found, 'ENODEV' if no address is found, 'ENXIO'
 * if this module is not started, or any non-zero error number.
 */
extern int ifaddr_lookup(unsigned int __ifindex, struct in6_addr *__addr);

#endif

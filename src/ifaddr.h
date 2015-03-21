/*
 * ifaddr - interface addresses (interface)
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

#ifndef IFADDR_H
#define IFADDR_H 1

#if __cplusplus
#include <posix.h>
#endif
#include <netinet/in.h>
#if __cplusplus
#include <memory>
#endif

#if __cplusplus
#define BEGIN_C_LINKAGE extern "C" {
#define END_C_LINKAGE }
#else
#define BEGIN_C_LINKAGE
#define END_C_LINKAGE
#endif

#if __cplusplus
namespace xllmnrd {

    using namespace std;

    class if_manager {
    public:

        explicit if_manager(shared_ptr<posix> os = make_shared<posix>())
                : os(os) {
        }

    private:
        shared_ptr<posix> os;
    };
}
#endif

BEGIN_C_LINKAGE

enum ifaddr_change_type {
    IFADDR_ADDED,
    IFADDR_REMOVED,
};

struct ifaddr_change {
    enum ifaddr_change_type type;
    unsigned int ifindex;
};

typedef void (*ifaddr_change_handler)(const struct ifaddr_change *);

/**
 * Initializes this module.
 * @param __sig signal number that will be used to interrupt the worker
 * thread; if its value is 0, no signal will be used.
 * @return 0 if no error is detected, 'EBUSY' if this module is already
 * initialized, or any non-zero error number.
 */
extern int ifaddr_initialize(int __sig);

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
 * Looks up the IPv6 addresses of an interface.
 * This module MUST be initialized and started.
 * @param __index interface index.
 * @param __addr_size maximum size of the output array.
 * @param __addr array pointer to the interface addresses.  If the actual
 * number of interface addresses is greater than the array size, ones that do
 * not fit this array will be discarded.
 * @param __number_of_addresses [out] number of the interface addresses.
 * @return 0 if the interface index is valid, 'ENODEV' if not, 'ENXIO' if this
 * module is not started, or any non-zero error number.
 */
extern int ifaddr_lookup_v6(unsigned int __index, size_t __addr_size,
        struct in6_addr __addr[], size_t *__number_of_addresses);

END_C_LINKAGE

#undef END_C_LINKAGE
#undef BEGIN_C_LINKAGE

#endif

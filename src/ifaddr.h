/*
 * ifaddr - interface addresses (interface)
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

#ifndef IFADDR_H
#define IFADDR_H 1

#include <posix.h>
#include <netinet/in.h>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>
#include <forward_list>
#include <memory>

#if __cplusplus
#define BEGIN_C_LINKAGE extern "C" {
#define END_C_LINKAGE }
#else
#define BEGIN_C_LINKAGE
#define END_C_LINKAGE
#endif

namespace xllmnrd {

    using namespace std;

    // Interface address change.
    struct ifaddr_change {

        enum change_type {
            ADDED,
            REMOVED,
        };

        change_type type;
        unsigned int ifindex;
    };

    // Pointer to the interface address change handler.
    typedef void (*ifaddr_change_handler)(const ifaddr_change *);

    // Abstract interface address manager.
    class ifaddr_manager {
    public:

        // Constructs this object.
        // <var>interrupt_signal</var> is the signal number used to interrupt
        // blocking system calls and its handler is expected to do nothing.
        explicit ifaddr_manager(shared_ptr<posix> os = make_shared<posix>());

        // Destructs this object and cleans up the allocated resources.
        virtual ~ifaddr_manager() noexcept;

        // Set the interface address change handler that is called on each
        // interface address change.
        //
        // This function is thread-safe.
        void set_change_handler(ifaddr_change_handler change_handler,
                ifaddr_change_handler *old_change_handler = nullptr);

        // Refreshes the interface addresses.
        //
        // This function is thread safe.
        virtual void refresh() = 0;

        // Starts the worker threads that monitors interface address changes.
        // This function does nothing if no worker threads are needed.
        //
        // This function is thread-safe.
        virtual void start() {
        }

    protected:
        const shared_ptr<posix> os;

    private:
        recursive_mutex object_mutex;

        ifaddr_change_handler change_handler = nullptr;
    };

    // Interface address manager based on RTNETLINK.
    class rtnetlink_ifaddr_manager : public ifaddr_manager {
    public:
        explicit rtnetlink_ifaddr_manager(shared_ptr<posix> os
                = make_shared<posix>());
        virtual ~rtnetlink_ifaddr_manager() noexcept;

        void run();

        void refresh() override;
        void start() override;

    protected:
        // Opens a RTNETLINK socket and returns its file descriptor.
        int open_rtnetlink() const;

        // Receive a RTNETLINK message.
        void receive_netlink(int fd, volatile atomic_bool *stopped);

        // Decode a NETLINK message.
        void decode_nlmsg(const void *message, size_t size);

        // Finishes the refresh of the interface addresses.
        void finish_refresh();

    private:

        // Addresses assigned to an interface.
        struct addresses {
            forward_list<struct in_addr> address_v4;
            forward_list<struct in6_addr> address_v6;

            // Returns true if there are no addresses.
            bool empty() const noexcept {
                return address_v4.empty() && address_v6.empty();
            }
        };

        // Map from an interface to its addresses.
        map<unsigned int, addresses> interface_addresses;

        // Mutex for refresh_in_progress.
        mutex refresh_mutex;

        // Condition variable for refresh_in_progress.
        condition_variable refresh_finished;

        // Indicates if a refresh is in progress.
        volatile bool refresh_in_progress = false;

        // File descriptor for the RTNETLINK socket.
        int rtnetlink_fd;

        // Mutex for worker.
        mutex worker_mutex;

        // Worker thread.
        thread worker;

        // Indicates if the worker thread is terminated.
        volatile atomic_bool worker_terminated;

        // Stops the worker thread if started.
        void stop();
    };
}

BEGIN_C_LINKAGE

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
extern int ifaddr_set_change_handler(xllmnrd::ifaddr_change_handler __handler,
        xllmnrd::ifaddr_change_handler *__old_handler);

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

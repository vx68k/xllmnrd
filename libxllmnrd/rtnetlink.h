/*
 * rtnetlink.h
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

#ifndef RTNETLINK_H
#define RTNETLINK_H 1

#include "interface.h"
#include "posix.h"

#if HAVE_LINUX_RTNETLINK_H

#include <linux/netlink.h>
#include <netinet/in.h>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>
#include <forward_list>
#include <memory>
#include <cstddef>

namespace xllmnrd
{
    using std::size_t;

    /// Interface manager class based on the Linux RTNETLINK socket.
    class rtnetlink_interface_manager: public interface_manager
    {
    private:
        /// Operating system interface.
        std::shared_ptr<posix> _os;

        /// File descriptor for the RTNETLINK socket.
        int _rtnetlink = -1;

    protected:
        /// Opens the RTNETLINK socket.
        static int open_rtnetlink(const std::shared_ptr<posix> &os);

    public:
        rtnetlink_interface_manager();

        explicit rtnetlink_interface_manager(const std::shared_ptr<posix> &os);

    public:
        virtual ~rtnetlink_interface_manager();

    public:
        void run();

        void refresh() override;
        void start() override;

    protected:
        // Finishes the refresh of the interface addresses.
        void finish_refresh();

        // Receives a RTNETLINK message.
        void receive_netlink(int fd, volatile std::atomic_bool *stopped);

        // Decodes a NETLINK message.
        void decode_nlmsg(const void *message, size_t size);

        // Handles a NETLINK error message.
        void handle_nlmsgerr(const nlmsghdr *nlmsg);

        // Handles a RTNETLINK message for an interface address change.
        void handle_ifaddrmsg(const nlmsghdr *nlmsg);

    private:

        // Addresses assigned to an interface.
        struct addresses {
            std::forward_list<struct in_addr> address_v4;
            std::forward_list<struct in6_addr> address_v6;

            // Returns true if there are no addresses.
            bool empty() const noexcept {
                return address_v4.empty() && address_v6.empty();
            }
        };

        // Map from an interface to its addresses.
        std::map<unsigned int, addresses> interface_addresses;

        // Mutex for refresh_in_progress.
        std::mutex refresh_mutex;

        // Condition variable for refresh_in_progress.
        std::condition_variable refresh_finished;

        // Indicates if a refresh is in progress.
        volatile bool refresh_in_progress = false;

        // Mutex for worker.
        std::mutex worker_mutex;

        // Worker thread.
        std::thread worker_thread;

        // Indicates if the worker thread is terminated.
        volatile std::atomic_bool worker_stopped;

        // Stops the worker thread if started.
        void stop();
    };
}

#endif /* HAVE_LINUX_RTNETLINK_H */

#endif

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

// Defined to non-zero if libxllmnrd has RTNETLINK support.
#define XLLMNRD_RTNETLINK 1

#include <linux/netlink.h>
#include <netinet/in.h>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <atomic>
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

        /// Mutex for refresh.
        std::mutex _refresh_mutex;

        /// Indicates if a refresh is in progress.
        bool _refreshing = false;

        // Condition variable for refresh_in_progress.
        std::condition_variable _refresh_completion;

    protected:
        /// Opens the RTNETLINK socket.
        static int open_rtnetlink(const std::shared_ptr<posix> &os);

    public:
        rtnetlink_interface_manager();

        explicit rtnetlink_interface_manager(const std::shared_ptr<posix> &os);

    public:
        virtual ~rtnetlink_interface_manager();

    public:
        /**
         * Starts a thread that monitors interface changes and returns 'this'.
         *
         * This function is thread-safe.
         */
        rtnetlink_interface_manager *start();

        /**
         * Returns true if the worker thread is running; false otherwise.
         */
        bool running() const
        {
            return worker_thread.joinable();
        }

        void run();

        void refresh(bool maybe_asynchronous = false) override;

    protected:
        /// Processes NETLINK messages.
        void process_messages();

        /// Dispatches NETLINK messages.
        void dispatch_messages(const void *messages, size_t size);

        /// Handles a NETLINK error message.
        void handle_error(const struct nlmsghdr *message);

        /**
         * Handles a NETLINK done message.
         *
         * This function completes the running refresh task.
         */
        void handle_done();

        // Handles a RTNETLINK message for an interface address change.
        void handle_ifaddrmsg(const nlmsghdr *message);

    private:

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

// rtnetlink.h
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

        enum class refresh_state: char
        {
            standby,
            ifinfo,
            ifaddr,
        };

        /// Operating system interface.
        std::shared_ptr<posix> _os;

        /// File descriptor for the RTNETLINK socket.
        int _rtnetlink {-1};

        /// Indicates if a refresh is in progress.
        bool _refreshing {false};

        refresh_state _refresh_state = refresh_state::standby;

        /// Mutex for the refresh task.
        mutable std::mutex _refresh_mutex;

        // Condition variable for the refresh task.
        mutable std::condition_variable _refresh_completion;

        // Indicates if the interface manager loop is running.
        std::atomic<bool> _running {false};

        // Worker thread.
        std::thread _worker_thread;

        // Mutex for the worker.
        mutable std::mutex _worker_mutex;

    protected:

        /*
         * Opens a RTNETLINK socket.
         *
         * @param os an operation system interface
         */
        [[nodiscard]]
        static int open_rtnetlink(const std::shared_ptr<posix> &os);

    public:

        // Constructors.

        rtnetlink_interface_manager();

        explicit rtnetlink_interface_manager(const std::shared_ptr<posix> &os);


        // Destructor.

        ~rtnetlink_interface_manager() override;


        void refresh(bool maybe_asynchronous = false) override;

    protected:

        /**
         * Begins a refresh task if not running.
         */
        void begin_refresh();

        /**
         * Ends the current refresh task if running.
         */
        void end_refresh();

        /**
         * Starts a worker thread that monitors interface changes.
         *
         * This function is thread-safe.
         */
        void start_worker();

        /**
         * Stops the worker thread if running.
         */
        void stop_worker();

        void run();

        void request_ifinfos() const;

        void request_ifaddrs() const;

        /// Processes NETLINK messages.
        void process_messages();

    private:

        /// Dispatches NETLINK messages.
        void dispatch_messages(const void *messages, size_t size);

        /// Handles a NETLINK error message.
        void handle_nlmsgerr(const nlmsghdr *nlmsg) const;

        void handle_ifinfomsg(const nlmsghdr *nlmsg);

        // Handles a RTNETLINK message for an interface address change.
        void handle_ifaddrmsg(const nlmsghdr *nlmsg);
    };
}

#endif /* HAVE_LINUX_RTNETLINK_H */

#endif

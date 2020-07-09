// rtnetlink.h
// Copyright (C) 2013-2020 Kaz Nishimura
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
        /// Operating system interface.
        std::shared_ptr<posix> _os;

    private:
        /// File descriptor for the RTNETLINK socket.
        int _rtnetlink {-1};

    private:
        /// Indicates if a refresh is in progress.
        bool _refreshing {false};

    private:
        enum class refresh_state: char {
            STANDBY = 0,
            IFINFO,
            IFADDR,
        } _refresh_state = refresh_state::STANDBY;

    private:
        /// Mutex for the refresh task.
        mutable std::mutex _refresh_mutex;

    private:
        // Condition variable for the refresh task.
        mutable std::condition_variable _refresh_completion;

    private:
        // Indicates if the interface manager loop is running.
        std::atomic<bool> _running {false};

    private:
        // Worker thread.
        std::thread _worker_thread;

    private:
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
        rtnetlink_interface_manager();

        explicit rtnetlink_interface_manager(const std::shared_ptr<posix> &os);

    public:
        virtual ~rtnetlink_interface_manager();

    public:
        void refresh(bool maybe_asynchronous = false) override;

    protected:
        /**
         * Begins a refresh task if not running.
         */
        void begin_refresh();

    protected:
        /**
         * Ends the current refresh task if running.
         */
        void end_refresh();

    protected:
        /**
         * Starts a worker thread that monitors interface changes.
         *
         * This function is thread-safe.
         */
        void start_worker();

    protected:
        /**
         * Stops the worker thread if running.
         */
        void stop_worker();

    protected:
        void run();

    protected:
        void request_ifinfos();

    protected:
        void request_ifaddrs();

    protected:
        /// Processes NETLINK messages.
        void process_messages();

    private:
        /// Dispatches NETLINK messages.
        void dispatch_messages(const void *messages, size_t size);

    private:
        /// Handles a NETLINK error message.
        void handle_error(const nlmsghdr *nlmsg);

    private:
        void handle_ifinfo(const nlmsghdr *nlmsg);

    private:
        // Handles a RTNETLINK message for an interface address change.
        void handle_ifaddrmsg(const nlmsghdr *nlmsg);
    };
}

#endif /* HAVE_LINUX_RTNETLINK_H */

#endif

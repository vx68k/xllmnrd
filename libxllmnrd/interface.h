/*
 * interface.h
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

#ifndef INTERFACE_H
#define INTERFACE_H 1

#include "posix.h"
#include <netinet/in.h>
#include <mutex>
#include <memory>

namespace xllmnrd
{
    using std::size_t;

    // Interface address change.
    struct ifaddr_change
    {

        enum change_type
        {
            ADDED,
            REMOVED,
        };

        change_type type;
        unsigned int ifindex;
    };

    // Pointer to the interface address change handler.
    typedef void (*ifaddr_change_handler)(const ifaddr_change *);

    /// Abstract interface manager class.
    class interface_manager
    {
    public:
        // Constructs this object.
        // <var>interrupt_signal</var> is the signal number used to interrupt
        // blocking system calls and its handler is expected to do nothing.
        explicit interface_manager(std::shared_ptr<posix> os = std::make_shared<posix>());

        // The copy constructor is deleted.
        interface_manager(const interface_manager &) = delete;

        // The copy assignment operator is deleted.
        void operator =(const interface_manager &) = delete;

    public:
        // Destructs this object and cleans up the allocated resources.
        virtual ~interface_manager();

    public:
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
        virtual void start()
        {
        }

    protected:
        const std::shared_ptr<posix> os;

    private:
        std::recursive_mutex object_mutex;

        ifaddr_change_handler change_handler = nullptr;
    };
}

#endif

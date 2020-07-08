// interface.h -*- C++ -*-
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

#ifndef INTERFACE_H
#define INTERFACE_H 1

#include "posix.h"
#include <netinet/in.h>
#include <mutex>
#include <unordered_map>
#include <set>
#include <atomic>
#include <cstddef>

/*
 * Specializations of 'std::less'.
 */

template <>
struct std::less<in_addr>
{
    bool operator ()(const in_addr &x, const in_addr &y) const;
};

template <>
struct std::less<in6_addr>
{
    bool operator ()(const in6_addr &x, const in6_addr &y) const;
};

namespace xllmnrd
{
    using std::size_t;

    /**
     * Event objects about interfaces.
     */
    struct interface_event
    {
        unsigned int interface_index;
        int address_family;

        constexpr interface_event(const unsigned int interface_index,
            const int address_family)
        :
            interface_index {interface_index},
            address_family {address_family}
        {
            // Nothing to do.
        }
    };

    /**
     * Listener objects for interface events.
     */
    class interface_listener
    {
    protected:
        interface_listener() = default;

    protected:
        ~interface_listener() = default;

    public:
        virtual void interface_added(const interface_event &event) = 0;

    public:
        virtual void interface_removed(const interface_event &event) = 0;
    };

    /// Abstract interface manager class.
    class interface_manager
    {
    protected:
        struct interface
        {
            std::set<in_addr> in_addresses;
            std::set<in6_addr> in6_addresses;

            /// Returns true if no address is stored, false otherwise.
            bool empty() const
            {
                return in_addresses.empty() && in6_addresses.empty();
            }
        };

    private:
        int _debug_level {0};

    private:
        std::atomic<interface_listener *> _interface_listener {nullptr};

    private:
        /// Map from interface indices to interfaces.
        std::unordered_map<unsigned int, interface> _interfaces;

    private:
        mutable std::recursive_mutex _interfaces_mutex;

    protected:
        /// Constructs an interface manager.
        interface_manager();

        // The copy constructor is deleted.
        interface_manager(const interface_manager &) = delete;

        // The copy assignment operator is deleted.
        void operator =(const interface_manager &) = delete;

    public:
        /// Destructs an interface manager.
        virtual ~interface_manager();

    public:
        int debug_level() const
        {
            return _debug_level;
        }

    public:
        void set_debug_level(const int debug_level)
        {
            _debug_level = debug_level;
        }

    public:
        /**
         * Adds a listener object for interface change events.
         */
        void add_interface_listener(interface_listener *listener);

    public:
        /**
         * Removes a listener object for interface change events.
         */
        void remove_interface_listener(interface_listener *listener);

    private:
        // Fires an event for an added interface.
        void fire_interface_added(const interface_event &event);

    private:
        // Fires an event for a removed interface.
        void fire_interface_removed(const interface_event &event);

    public:
        /**
         * Returns a copy of the IPv4 addresses of an interface.
         *
         * This function is thread-safe.
         *
         * @param {unsigned int} index an interface index
         * @return a copy of the IPv4 addresses of the interface
         */
        std::set<in_addr> in_addresses(unsigned int index) const;

    public:
        /**
         * Returns a copy of the IPv6 addresses of an interface.
         *
         * This function is thread-safe.
         *
         * @param {unsigned int} index an interface index
         * @return a copy of the IPv6 addresses of the interface
         */
        std::set<in6_addr> in6_addresses(unsigned int index) const;

    public:
        // Refreshes the interface addresses.
        //
        // This function is thread safe.
        virtual void refresh(bool maybe_asynchronous = false) = 0;

    protected:
        /// Removes all the interfaces.
        void remove_interfaces();

    protected:
        void add_interface_address(unsigned int index, int family,
            const void *address, size_t address_size);

    protected:
        void remove_interface_address(unsigned int index, int family,
            const void *address, size_t address_size);
    };
}

#endif

// interface.h -*- C++ -*-
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

#ifndef INTERFACE_H
#define INTERFACE_H 1

#include "posix.h"
#include <netinet/in.h>
#include <unistd.h>
#include <mutex>
#include <unordered_map>
#include <set>
#include <atomic>

// Specializations of 'std::less' for address types.

template<>
struct std::less<in_addr>
{
    bool operator ()(const in_addr &x, const in_addr &y) const;
};

template<>
struct std::less<in6_addr>
{
    bool operator ()(const in6_addr &x, const in6_addr &y) const;
};


namespace xllmnrd
{
    class interface_manager;

    /**
     * Event objects about interfaces.
     */
    struct interface_event
    {
        interface_manager *source = nullptr;
        unsigned int interface_index = 0;

        constexpr interface_event(interface_manager *const source,
            const unsigned int interface_index)
        :
            source {source},
            interface_index {interface_index}
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

        ~interface_listener() = default;

    public:

        virtual void interface_enabled(const interface_event &event) = 0;

        virtual void interface_disabled(const interface_event &event) = 0;
    };

    /**
     * Abstract class of interface managers.
     *
     * This class keeps a table of interface addresses for IPv4 and IPv6.
     */
    class interface_manager
    {
    protected:

        struct interface
        {
            bool enabled = false;
            std::set<in_addr> in_addresses;
            std::set<in6_addr> in6_addresses;

            /// Returns true if no address is stored, false otherwise.
            bool empty() const
            {
                return in_addresses.empty() && in6_addresses.empty();
            }
        };

    private:

        int _debug_level = 0;

        std::atomic<interface_listener *> _interface_listener {nullptr};

        /// Map from interface indices to interfaces.
        std::unordered_map<unsigned int, interface> _interfaces;

        mutable std::recursive_mutex _interfaces_mutex;

    protected:

        /**
         * Constructs an interface manager object.
         */
        interface_manager();

        // This class is not copy-constructible.
        interface_manager(const interface_manager &) = delete;

    public:

        /**
         * Destructs an interface manager object.
         */
        virtual ~interface_manager();


        // This class is not copy-assignable.
        void operator =(const interface_manager &) = delete;


        int debug_level() const
        {
            return _debug_level;
        }

        void set_debug_level(const int debug_level)
        {
            _debug_level = debug_level;
        }


        /**
         * Adds a listener for interface events.
         */
        void add_interface_listener(interface_listener *listener);

        /**
         * Removes a listener for interface events.
         */
        void remove_interface_listener(interface_listener *listener);

    private:

        // Fires an event for an added interface.
        void fire_interface_enabled(const interface_event &event);

        // Fires an event for a removed interface.
        void fire_interface_disabled(const interface_event &event);

    public:

        /**
         * Returns a copy of the IPv4 addresses of an interface.
         *
         * This function is thread-safe.
         *
         * @param {unsigned int} index an interface index
         * @return a copy of the IPv4 addresses of the interface
         */
        std::set<in_addr> in_addresses(unsigned int interface_index) const;

        /**
         * Returns a copy of the IPv6 addresses of an interface.
         *
         * This function is thread-safe.
         *
         * @param {unsigned int} index an interface index
         * @return a copy of the IPv6 addresses of the interface
         */
        std::set<in6_addr> in6_addresses(unsigned int interface_index) const;

        // Refreshes the interface addresses.
        //
        // This function is thread safe.
        virtual void refresh(bool maybe_asynchronous = false) = 0;

    protected:

        /// Removes all the interfaces.
        void remove_interfaces();

        /**
         * Enables an interface.
         */
        void enable_interface(unsigned int interface_index);

        /**
         * Disables an interface.
         */
        void disable_interface(unsigned int interface_index);

        /**
         * Adds an interface address.
         */
        void add_interface_address(unsigned int interface_index,
            int address_family, const void *address, size_t address_size);

        /**
         * Adds an interface address.
         *
         * This overload takes a typed address argument.
         */
        template<class T>
        void add_interface_address(const unsigned int interface_index,
            const int address_family, T *const address)
        {
            add_interface_address(interface_index, address_family, address,
                sizeof *address);
        }

        /**
         * Removes an interface address.
         */
        void remove_interface_address(unsigned int interface_index,
            int address_family, const void *address, size_t address_size);

        /**
         * Removes an interface address.
         *
         * This overload takes a typed address argument.
         */
        template<class T>
        void remove_interface_address(const unsigned int interface_index,
            const int address_family, T *const address)
        {
            remove_interface_address(interface_index, address_family, address,
                sizeof *address);
        }
    };
}

#endif

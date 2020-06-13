/*
 * test_rtnetlink.cpp
 * Copyright (C) 2020 Kaz Nishimura
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "rtnetlink.h"

#if XLLMNRD_RTNETLINK

#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/TestFixture.h>
#include <unistd.h>
#include <iostream>

using CppUnit::TestFixture;
using xllmnrd::rtnetlink_interface_manager;
using xllmnrd::interface_change_event;
using namespace std;

/*
 * Tests for rtnetlink_interface_manager.
 */
class RtnetlinkTests: public TestFixture
{
    CPPUNIT_TEST_SUITE(RtnetlinkTests);
    CPPUNIT_TEST(testSetInterfaceChange);
    CPPUNIT_TEST(testStart);
    CPPUNIT_TEST_SUITE_END();

private:
    static unsigned int addInCount;
    static unsigned int addIn6Count;
    static unsigned int removeInCount;
    static unsigned int removeIn6Count;

private:
    unique_ptr<rtnetlink_interface_manager> manager;

private:
    static void handle_interface_change(
        const interface_change_event *const event)
    {
        switch (event->type)
        {
        case interface_change_event::ADDED:
            switch (event->address_family)
            {
            case AF_INET:
                addInCount++;
                clog << "Add an IPv4 address " << addInCount << endl;
                break;

            case AF_INET6:
                addIn6Count++;
                clog << "Add an IPv6 address " << addIn6Count << endl;
                break;

            default:
                break;
            }
            break;

        case interface_change_event::REMOVED:
            switch (event->address_family)
            {
            case AF_INET:
                removeInCount++;
                clog << "Remove an IPv4 address " << removeInCount << endl;
                break;

            case AF_INET6:
                removeIn6Count++;
                clog << "Remove an IPv6 address " << removeIn6Count << endl;
                break;

            default:
                break;
            }
            break;
        }
    }

public:
    void setUp() override
    {
        manager.reset(new rtnetlink_interface_manager());
        addInCount = 0;
        removeInCount = 0;
        addIn6Count = 0;
        removeIn6Count = 0;
    }

    void testSetInterfaceChange()
    {
        // No handler SHALL be set by default.
        auto old = manager->set_interface_change(handle_interface_change);
        CPPUNIT_ASSERT_EQUAL(xllmnrd::interface_change_handler(), old);

        // The handler that was set SHALL be returned.
        old = manager->set_interface_change(nullptr);
        CPPUNIT_ASSERT_EQUAL(&handle_interface_change, old);
    }

    void testStart()
    {
        manager->set_interface_change(handle_interface_change);
        CPPUNIT_ASSERT_EQUAL(0U, addInCount);
        CPPUNIT_ASSERT_EQUAL(0U, addIn6Count);
        CPPUNIT_ASSERT_EQUAL(0U, removeInCount);
        CPPUNIT_ASSERT_EQUAL(0U, removeIn6Count);

        manager->start();
        sleep(1);
        CPPUNIT_ASSERT(addInCount > removeInCount);
        CPPUNIT_ASSERT(addIn6Count > removeIn6Count);
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(RtnetlinkTests);

unsigned int RtnetlinkTests::addInCount;
unsigned int RtnetlinkTests::addIn6Count;
unsigned int RtnetlinkTests::removeInCount;
unsigned int RtnetlinkTests::removeIn6Count;

#endif /* XLLMNRD_RTNETLINK */

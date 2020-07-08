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
#include <syslog.h>
#include <unistd.h>
#include <iostream>

#ifndef LOG_PERROR
#define LOG_PERROR 0
#endif

using CppUnit::TestFixture;
using xllmnrd::rtnetlink_interface_manager;
using xllmnrd::interface_event;
using xllmnrd::interface_listener;
using namespace std;

/*
 * Tests for rtnetlink_interface_manager.
 */
class RtnetlinkTest: public TestFixture, public interface_listener
{
    CPPUNIT_TEST_SUITE(RtnetlinkTest);
    CPPUNIT_TEST(testRefresh1);
    CPPUNIT_TEST(testRefresh2);
    CPPUNIT_TEST_SUITE_END();

private:
    unsigned int addInCount = 0;
    unsigned int addIn6Count = 0;
    unsigned int removeInCount = 0;
    unsigned int removeIn6Count = 0;

private:
    unique_ptr<rtnetlink_interface_manager> manager;

public:
    RtnetlinkTest()
    {
        openlog(NULL, LOG_PERROR, LOG_USER);
    }

public:
    ~RtnetlinkTest()
    {
        closelog();
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

public:
    void tearDown() override
    {
        manager.reset();
    }

public:
    void interface_added(const interface_event &event) override
    {
        switch (event.address_family)
        {
        case AF_INET:
            addInCount++;
            clog << "Add an IPv4 address " << addInCount << endl;
            break;

        case AF_INET6:
            addIn6Count++;
            clog << "Add an IPv6 address " << addIn6Count << endl;
            break;
        }
    }

public:
    void interface_removed(const interface_event &event) override
    {
        switch (event.address_family)
        {
        case AF_INET:
            removeInCount++;
            clog << "Remove an IPv4 address " << removeInCount << endl;
            break;

        case AF_INET6:
            removeIn6Count++;
            clog << "Remove an IPv6 address " << removeIn6Count << endl;
            break;
        }
    }

private:
    void testRefresh1()
    {
        manager->add_interface_listener(this);
        CPPUNIT_ASSERT_EQUAL(0U, addInCount);
        CPPUNIT_ASSERT_EQUAL(0U, addIn6Count);
        CPPUNIT_ASSERT_EQUAL(0U, removeInCount);
        CPPUNIT_ASSERT_EQUAL(0U, removeIn6Count);
    }

private:
    void testRefresh2()
    {
        manager->add_interface_listener(this);
        manager->refresh();
        CPPUNIT_ASSERT(addInCount > removeInCount);
        CPPUNIT_ASSERT(addIn6Count > removeIn6Count);

        clog << "End testStart2\n";
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(RtnetlinkTest);

#endif /* XLLMNRD_RTNETLINK */

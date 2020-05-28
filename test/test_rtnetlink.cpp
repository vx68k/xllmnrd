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

using CppUnit::TestFixture;
using xllmnrd::rtnetlink_interface_manager;
using namespace std;

/*
 * Tests for rtnetlink_interface_manager.
 */
class RtnetlinkTests: public TestFixture
{
    CPPUNIT_TEST_SUITE(RtnetlinkTests);
    CPPUNIT_TEST_SUITE_END();

private:
    unique_ptr<rtnetlink_interface_manager> manager;

public:
    void setUp() override
    {
        manager.reset(new rtnetlink_interface_manager());
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(RtnetlinkTests);

#endif /* XLLMNRD_RTNETLINK */

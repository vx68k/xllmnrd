/*
 * Test fixture for the ifaddr module
 * Copyright (C) 2013  Kaz Nishimura
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
#define _GNU_SOURCE 1

extern "C" {
#include <ifaddr.h>
}

#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/TestFixture.h>
#include <netinet/in.h>
#include <csignal>

using namespace std;
using CppUnit::TestFixture;

class IfaddrTest : public TestFixture {
    CPPUNIT_TEST_SUITE(IfaddrTest);
    CPPUNIT_TEST(testUninitialized);
    CPPUNIT_TEST(testNormal);
    CPPUNIT_TEST(testRefresh);
    CPPUNIT_TEST_SUITE_END();

public:
    virtual void setUp() override {
        struct sigaction sa = {};
        sa.sa_handler = &handle_signal;
        sigaction(SIGUSR2, &sa, NULL);
    }

    virtual void tearDown() override {
        ifaddr_finalize();

        struct sigaction sa = {};
        sa.sa_handler = SIG_DFL;
        sigaction(SIGUSR2, &sa, NULL);
    }

    void testUninitialized() {
        CPPUNIT_ASSERT(ifaddr_start() != 0);
    }

    void testNormal() {
        CPPUNIT_ASSERT(ifaddr_initialize(SIGUSR2) == 0);
        CPPUNIT_ASSERT(ifaddr_initialize(SIGUSR2) != 0);
        CPPUNIT_ASSERT(ifaddr_start() == 0);
        CPPUNIT_ASSERT(ifaddr_start() == 0); // Multiple calls are OK.
        
        struct in6_addr address;
        ifaddr_lookup(0, &address);
        ifaddr_finalize();
    }

    void testRefresh() {
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This must fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));
        ifaddr_initialize(SIGUSR2);
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This still must fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));
        ifaddr_start();
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh());
        ifaddr_finalize();
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This also must fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));
    }

protected:
    static void handle_signal(int sig) {
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(IfaddrTest);

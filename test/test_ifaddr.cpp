/*
 * testifaddr - test fixtures for ifaddr
 * Copyright (C) 2013-2014 Kaz Nishimura
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
#undef _GNU_SOURCE

#include "ifaddr.h"

#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/TestFixture.h>
#include <netinet/in.h>
#include <net/if.h>
#include <vector>
#include <csignal>
#include <cerrno>

using CppUnit::TestFixture;
using namespace xllmnrd;

/*
 * Uninitialized tests for ifaddr.
 */
class IfaddrPreTests : public TestFixture {
    CPPUNIT_TEST_SUITE(IfaddrPreTests);
    CPPUNIT_TEST(testInitialize);
    CPPUNIT_TEST(testFailures);
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

    void testInitialize() {
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_initialize(SIGUSR2));
        CPPUNIT_ASSERT_EQUAL(EBUSY, ifaddr_initialize(SIGUSR2));
        ifaddr_finalize();
        // This MUST succeed again.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_initialize(SIGUSR2));
    }

    void testFailures() {
        interface_change_handler handler = &handle_change;
        // Without initialization, an error MUST be detected.
        CPPUNIT_ASSERT_EQUAL(ENXIO, ifaddr_set_change_handler(&handle_change,
                &handler));

        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_start()));
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));

        size_t size;
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_lookup_v6(0, 0, NULL, &size)));
    }

protected:
    static void handle_signal(int sig) {
    }

    static void handle_change(const struct interface_change_event *change) {
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(IfaddrPreTests);

/*
 * Initialized tests for ifaddr.
 */
class IfaddrTests : public TestFixture {
    CPPUNIT_TEST_SUITE(IfaddrTests);
    CPPUNIT_TEST(testSetHandler);
    CPPUNIT_TEST(testStart);
    CPPUNIT_TEST(testRefresh);
    CPPUNIT_TEST(testLookup);
    CPPUNIT_TEST_SUITE_END();

public:
    virtual void setUp() override {
        struct sigaction sa = {};
        sa.sa_handler = &handle_signal;
        sigaction(SIGUSR2, &sa, NULL);

        ifaddr_initialize(SIGUSR2);
    }

    virtual void tearDown() override {
        ifaddr_finalize();

        struct sigaction sa = {};
        sa.sa_handler = SIG_DFL;
        sigaction(SIGUSR2, &sa, NULL);
    }

    void testSetHandler() {
        interface_change_handler handler = &handle_change;
        // The initial handler function MUST be null.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(&handle_change,
                &handler));
        CPPUNIT_ASSERT(handler == NULL);
        // The set function MUST be retrieved.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(NULL, &handler));
        CPPUNIT_ASSERT(handler == &handle_change);
        // And null MUST be retrieved again.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(&handle_change,
                &handler));
        CPPUNIT_ASSERT(handler == NULL);

        // TODO: The handler function MUST be called on each interface change.
    }

    void testStart() {
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_start());
        // This MUST also succeed.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_start());
    }

    void testRefresh() {
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This still MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));

        ifaddr_start();

        CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh());
    }

    void testLookup() {
        // TODO: These values may be missing.
        auto lo = if_nametoindex("lo");
        auto eth0 = if_nametoindex("eth0");
        if (eth0 == 0) {
            CPPUNIT_FAIL("eth0 not found");
        }

        size_t size;
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This still MUST fail.
                CPPUNIT_ASSERT_EQUAL(0,
                ifaddr_lookup_v6(eth0, 0, NULL, &size)));

        ifaddr_start();

        // The loopback interface SHALL be ignored.
        CPPUNIT_ASSERT_EQUAL(ENODEV, ifaddr_lookup_v6(lo, 0, NULL, &size));

        CPPUNIT_ASSERT_EQUAL(0, ifaddr_lookup_v6(eth0, 0, NULL, &size));
        CPPUNIT_ASSERT(size >= 0);

        std::vector<struct in6_addr> addr(size);
        CPPUNIT_ASSERT_EQUAL(0,
                ifaddr_lookup_v6(eth0, size, &addr[0], &size));
    }

protected:
    static void handle_signal(int sig) {
    }

    static void handle_change(const struct interface_change_event *change) {
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(IfaddrTests);

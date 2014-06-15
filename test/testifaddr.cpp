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
#undef _GNU_SOURCE

extern "C" {
#include <ifaddr.h>
}

#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/TestFixture.h>
#include <netinet/in.h>
#include <csignal>
#include <cerrno>

using namespace std;
using CppUnit::TestFixture;

class IfaddrTest : public TestFixture {
    CPPUNIT_TEST_SUITE(IfaddrTest);
    CPPUNIT_TEST(testInitialize);
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
    }

    virtual void tearDown() override {
        ifaddr_finalize();

        struct sigaction sa = {};
        sa.sa_handler = SIG_DFL;
        sigaction(SIGUSR2, &sa, NULL);
    }

    void testInitialize() {
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_initialize(SIGUSR2, NULL));
        CPPUNIT_ASSERT_EQUAL(EBUSY, ifaddr_initialize(SIGUSR2, NULL));
        ifaddr_finalize();
        // This MUST succeed again.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_initialize(SIGUSR2, NULL));
        ifaddr_finalize();
    }

    void testSetHandler() {
        ifaddr_change_handler handler = &handle_change;
        // Before initialization, an error MUST be detected.
        CPPUNIT_ASSERT_EQUAL(ENXIO, ifaddr_set_change_handler(&handle_change,
                &handler));
        ifaddr_initialize(SIGUSR2, NULL);
        // After initialization, the handler function MUST be null.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(&handle_change,
                &handler));
        CPPUNIT_ASSERT(handler == NULL);
        // The function MUST be retrieved.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(NULL, &handler));
        CPPUNIT_ASSERT(handler == &handle_change);
        // And null MUST be retrieved again.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(&handle_change,
                &handler));
        CPPUNIT_ASSERT(handler == NULL);
        // The handler function remains set.
        ifaddr_finalize();
        // After finalization, an error MUST be detected.
        CPPUNIT_ASSERT_EQUAL(ENXIO, ifaddr_set_change_handler(&handle_change,
                &handler));
        ifaddr_initialize(SIGUSR2, NULL);
        // After initialization, the handler function MUST be null again.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(NULL, &handler));
        CPPUNIT_ASSERT(handler == NULL);
        // Setting the function without retrieving the old one.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(&handle_change,
                NULL));
        // And the function MUST be retrieved.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_set_change_handler(NULL, &handler));
        CPPUNIT_ASSERT(handler == &handle_change);

        // TODO: The handler function MUST be called on each interface change.
    }

    void testStart() {
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_start()));
        ifaddr_initialize(SIGUSR2, NULL);
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_start());
        // This MUST succeed.
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_start());
        ifaddr_finalize();
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail again.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_start()));
    }

    void testRefresh() {
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));
        ifaddr_initialize(SIGUSR2, NULL);
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This still MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));
        ifaddr_start();
        CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh());
        ifaddr_finalize();
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail again.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_refresh()));
    }

    void testLookup() {
        struct in6_addr addr;
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_lookup(0, &addr)));
        ifaddr_initialize(SIGUSR2, NULL);
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This still MUST fail.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_lookup(0, &addr)));
        ifaddr_start();
        CPPUNIT_ASSERT_EQUAL(ENODEV, ifaddr_lookup(0, &addr));
        ifaddr_finalize();
        CPPUNIT_ASSERT_ASSERTION_FAIL(
                // This MUST fail again.
                CPPUNIT_ASSERT_EQUAL(0, ifaddr_lookup(0, &addr)));
    }

protected:
    static void handle_signal(int sig) {
    }

    static void handle_change(const struct ifaddr_change *change) {
    }
};
CPPUNIT_TEST_SUITE_REGISTRATION(IfaddrTest);

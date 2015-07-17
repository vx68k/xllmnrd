/*
 * testmain - unit test driver (main)
 * Copyright (C) 2013-2015 Nishimura Software Studio
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

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/XmlOutputter.h>
#include <cppunit/ui/text/TestRunner.h>
#include <iostream>
#include <cstdlib>

using namespace std;
using CppUnit::TextUi::TestRunner;
using CppUnit::XmlOutputter;
using CppUnit::TestFactoryRegistry;

int main(int argc, char *argv[]) {
    string xmlout_name = argv[0];
    xmlout_name.replace(xmlout_name.rfind("."), xmlout_name.size(), ".xml");

    ofstream xmlout;
    xmlout.open(xmlout_name);

    TestRunner runner;
    runner.addTest(TestFactoryRegistry::getRegistry().makeTest());
    runner.setOutputter(new XmlOutputter(&runner.result(), xmlout, "UTF-8"));

    if (!runner.run()) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

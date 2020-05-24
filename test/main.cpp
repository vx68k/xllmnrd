// main.cpp
// Copyright (C) 2012-2020 Kaz Nishimura
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "xmlreport.h"
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <sysexits.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fstream>
#include <cstdlib>

using namespace std;
using CppUnit::TextUi::TestRunner;
using CppUnit::TestFactoryRegistry;

static const char *xml_output_name;

int main(int argc, char *argv[]) {
    int opt;
    do {
        opt = getopt(argc, argv, "x:");
        switch (opt) {
        case 'x':
            xml_output_name = optarg;
            break;
        case '?':
            exit(EX_USAGE);
        }
    } while (opt >= 0);

    TestRunner runner;
    runner.addTest(TestFactoryRegistry::getRegistry().makeTest());

    ofstream out;
    if (xml_output_name) {
        out.open(xml_output_name);
        runner.setOutputter(new CustomXmlOutputter(&runner.result(), out));
    }

    if (!runner.run()) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

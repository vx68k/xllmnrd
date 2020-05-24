// xmlreport.cpp
// Copyright (C) 2020 Kaz Nishimura
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "xmlreport.h"
#include <cppunit/TestFailure.h>
#include <cppunit/Test.h>
#include <cppunit/Exception.h>
#include <algorithm>

using namespace std;
using CppUnit::Test;
using CppUnit::TestFailure;
using CppUnit::TestResultCollector;

CustomXmlOutputter::CustomXmlOutputter(TestResultCollector *const result,
    ostream &stream)
    : _result(result), _stream(stream)
{
}

CustomXmlOutputter::~CustomXmlOutputter()
{
}

void CustomXmlOutputter::write()
{
    _stream << "<?xml version=\"1.0\"?>\n";

    auto attributes = AttributeMap();
    attributes["name"] = "CppUnit";
    attributes["tests"] = to_string(_result->runTests());
    attributes["skipped"] = to_string(0);
    attributes["failures"] = to_string(_result->testFailures());
    attributes["errors"] = to_string(_result->testErrors());
    writeElement("testsuite", attributes, [this]() {
        auto failures = _result->failures();
        auto failureMap = unordered_map<Test *, TestFailure *>();
        for_each(failures.begin(), failures.end(),
            [&](TestResultCollector::TestFailures::const_reference e) {
            failureMap[e->failedTest()] = e;
        });

        auto tests = _result->tests();
        for_each(tests.begin(), tests.end(),
            [&](TestResultCollector::Tests::const_reference e) {
            auto attributes = AttributeMap();
            attributes["name"] = e->getName();
            attributes["time"] = "0.000";
            writeElement("testcase", attributes, [this, &failureMap, &e]() {
                auto found = failureMap.find(e);
                if (found != failureMap.end()) {
                    auto failure = found->second;
                    auto thrown = failure->thrownException();
                    auto attributes = AttributeMap();
                    attributes["type"] = thrown->what();
                    attributes["message"] =
                        thrown->message().shortDescription();
                    if (failure->isError()) {
                        writeElement("error", attributes);
                    }
                    else {
                        writeElement("failure", attributes);
                    }
                }
            });
        });
    });
}

void CustomXmlOutputter::writeElement(const string &name,
    const AttributeMap &attributes, function<void ()> &&content)
{
    _stream << "<" << name;
    writeAttributes(attributes);
    if (content) {
        _stream << ">\n";
        content();
        _stream << "</" << name << ">\n";
    }
    else {
        _stream << "/>\n";
    }
}

void CustomXmlOutputter::writeAttributes(const AttributeMap &attributes)
{
    for_each(attributes.begin(), attributes.end(),
        [&](AttributeMap::const_reference element) {
        // TODO: Handle unsafe characters specially.
        _stream << " " << element.first << "=\"" << element.second << "\"";
    });
}

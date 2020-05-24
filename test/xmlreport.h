// xmlreport.h
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

#ifndef XMLREPORT_H
#define XMLREPORT_H 1

#include <cppunit/Outputter.h>
#include <cppunit/TestResultCollector.h>
#include <unordered_map>
#include <functional>
#include <ostream>
#include <string>

/// Class to generate XML test reports similar to those by the Maven Surefire
/// Plugin.
class CustomXmlOutputter final : public CppUnit::Outputter
{
protected:
    using AttributeMap = std::unordered_map<std::string, std::string>;

private:
    CppUnit::TestResultCollector *_result;
    std::ostream &_stream;

public:
    CustomXmlOutputter(CppUnit::TestResultCollector *result,
        std::ostream &stream);

public:
    ~CustomXmlOutputter();

public:
    void write() override;

protected:
    void writeElement(const std::string &name, const AttributeMap &attributes,
        std::function<void ()> &&content = nullptr);

    void writeAttributes(const AttributeMap &attributes);
};

#endif

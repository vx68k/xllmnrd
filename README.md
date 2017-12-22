# Description

XLLMNRD is a [LLMNR][RFC 4795] responder daemon (primarily for GNU/Linux operating
systems).  It allows Microsoft Windows clients to get the IPv6 addresses of a
server on the same local network _without any DNS configuration_ and
supplements IPv4-only NetBIOS name resolution typically provided by [Samba][].

XLLMNRD is *[free software][]*: you can redistribute it and/or modify it
under the terms of the [GNU General Public License][].  You should be able to find a copy of
it in the 'COPYING' file.

For more information about XLLMNRD, visit <https://www.vx68k.org/xllmnrd>.

[![(GNU General Public License v3.0 or later)](https://img.shields.io/badge/license-GPL--3.0+-blue.svg)][GPL-3.0]
[![(Open Issues)](https://img.shields.io/bitbucket/issues/vx68k/xllmnrd.svg)][open issues]
[![(Build Status)](https://linuxfront-functions.azurewebsites.net/api/bitbucket/build/vx68k/xllmnrd?branch=master)][pipelines]

[RFC 4795]: https://tools.ietf.org/html/rfc4795 "Link-Local Multicast Name Resolution (LLMNR)"
[Samba]: <https://www.samba.org/>
[Free software]: <https://www.gnu.org/philosophy/free-sw.html> "What is free software?"
[GNU General Public License]: <https://www.gnu.org/licenses/gpl.html>

[GPL-3.0]: https://opensource.org/licenses/GPL-3.0
[Open issues]: https://bitbucket.org/vx68k/xllmnrd/issues?status=new&status=open
[Pipelines]: https://bitbucket.org/vx68k/xllmnrd/addon/pipelines/home

# Installation

See the 'INSTALL' file for installation instructions.  The 'configure' should
work for most GNU/Linux operating systems (distributions).

If you find any problem while installation, please report it to
<https://bitbucket.org/vx68k/xllmnrd/issues>.

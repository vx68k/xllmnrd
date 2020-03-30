# Description

XLLMNRD is a [LLMNR][RFC 4795] responder daemon (primarily for GNU/Linux operating
systems).  It allows Microsoft Windows clients to get the IPv6 addresses of a
server on the same local network _without any DNS configuration_ and
supplements IPv4-only NetBIOS name resolution typically provided by [Samba][].

This program is provided under the terms and conditions of the [GNU General Public License, version 3][GPL-3.0] or any later version.

See <https://www.vx68k.org/xllmnrd> (and the [repository wiki][wiki]) for more information.

[![(GNU General Public License v3.0 or later)](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)][GPL-3.0]
[![(Open Issues)](https://img.shields.io/bitbucket/issues/vx68k/xllmnrd.svg)][open issues]
[![(Build Status)](https://linuxfront-functions.azurewebsites.net/api/bitbucket/build/vx68k/xllmnrd?branch=master)][pipelines]

[RFC 4795]: https://tools.ietf.org/html/rfc4795 "Link-Local Multicast Name Resolution (LLMNR)"
[Samba]: <https://www.samba.org/>
[GPL-3.0]: https://opensource.org/licenses/GPL-3.0

[Wiki]: https://bitbucket.org/vx68k/xllmnrd/wiki
[Open issues]: https://bitbucket.org/vx68k/xllmnrd/issues?status=new&status=open
[Pipelines]: https://bitbucket.org/vx68k/xllmnrd/addon/pipelines/home

# Installation

See the 'INSTALL' file for installation instructions.  The 'configure' should
work for most GNU/Linux operating systems (distributions).

If you find any problem while installation, please report it to
<https://bitbucket.org/vx68k/xllmnrd/issues>.

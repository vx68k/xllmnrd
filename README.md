**Note**: this file is provided as a repository 'README' file and *should not*
be distributed with the XLLMNRD package.

---

This repository contains the source code for XLLMNRD.

XLLMNRD is an IPv6 [LLMNR][] responder daemon (primarily for GNU/Linux operating
systems).  It allows Microsoft Windows clients to get the IPv6 address of a
server on the same local network _without any DNS configuration_ and
effectively complements IPv4-only NetBIOS name resolution provided by [Samba][].

XLLMNRD is *[free software][]*: you can redistribute it and/or modify it
under the terms of the [GNU General Public License][].  You should be able to find a copy of
it in the 'COPYING' file.

For more information about XLLMNRD, visit <https://www.vx68k.org/xllmnrd>.

[LLMNR]: <http://tools.ietf.org/html/rfc4795>
         "Link-Local Multicast Name Resolution (LLMNR) [RFC 4795]"
[Samba]: <http://www.samba.org/>
[Free software]: <http://www.gnu.org/philosophy/free-sw.html>
                 "What is free software?"
[GNU General Public License]: <http://www.gnu.org/licenses/gpl.html>

# Installation

See the 'INSTALL' file for installation instructions.  The 'configure' should
work for most GNU/Linux operating systems (distributions).

If you find any problem while installation, please report it to
<https://bitbucket.org/vx68k/xllmnrd/issues>.

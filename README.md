[**Note**: this file _should not_ be distributed with the xllmnrd package.]

This repository contains the source code for xllmnrd.

xllmnrd is an IPv6 LLMNR responder daemon (primarily for GNU/Linux operating
systems).
It allows Microsoft Windows clients to get the IPv6 address of a server
on the same local network _without any DNS configuration_ and
effectively complements IPv4-only NetBIOS name resolution
provided by [Samba][].

xllmnrd is [free software][]: you can redistribute it and/or modify it
under the terms of the [GNU General Public License][].

For more information about xllmnrd, visit the xllmnrd project
at <http://www.vx68k.org/xllmnrd>.

[Samba]: <http://www.samba.org/>
[Free software]: <http://www.gnu.org/philosophy/free-sw.html>
    "What is free software?"
[GNU General Public License]: <http://www.gnu.org/licenses/gpl.html>

# Installation

For generic installation instructions, read the 'INSTALL' file.  If you are
also planning to run the included test suite with GCC, you might have to set
the environment variable 'CXX' to `g++ -std=gnu++11` (or to `g++ -std=gnu++0x`
depending on the compiler version) before you run 'configure'.

If you find any other problem while installation, please report it to our
issue tracker at <https://bitbucket.org/kazssym/xllmnrd/issues>.

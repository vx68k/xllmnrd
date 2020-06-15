# Introduction

<dfn>Xenium LLMNR Responder</dfn> (xllmnrd) is an IPv6 network service daemon
that responds to name queries from Microsoft Windows computers on the same
network link so that you can get the IPv6 addresses of the server *without
any DNS configuration*.  It effectively supplements IPv4-only NetBIOS name
resolution typically provided by [Samba][].

This program implements Link-Local Multicast Name Resolution (LLMNR) as
described in [RFC 4795][] and currently supports Linux-based operating systems
only.

See the [home page][] for more information about this program.

[Home page]: https://www.vx68k.org/xllmnrd
[RFC 4795]: https://tools.ietf.org/html/rfc4795 "Link-Local Multicast Name Resolution (LLMNR)"
[Samba]: https://www.samba.org/

[![(License)](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)][GPL-3.0]
[![(Open issues)](https://img.shields.io/bitbucket/issues/kazssym/xllmnrd.svg)][open issues]

[Open issues]: https://bitbucket.org/kazssym/xllmnrd/issues?status=new&status=open

# Installation

See the 'INSTALL' file for installation instructions.  The 'configure' should
work for most supported operating systems.

If you find any problem while installation, please report it to
<https://bitbucket.org/kazssym/xllmnrd/issues>.

# License

This program is provided under the terms and conditions of the [GNU General
Public License, version 3][GPL-3.0] or any later version.

[GPL-3.0]: https://opensource.org/licenses/GPL-3.0

# See also

  - [RFC 4795][].

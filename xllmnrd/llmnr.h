// llmnr.h -*- C -*-
// Copyright (C) 2013 Kaz Nishimura
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

#ifndef LLMNR_H
#define LLMNR_H 1

#include <netinet/in.h> /* struct in6_addr */

/**
 * UDP port for LLMNR.
 */
#define LLMNR_PORT 5355

#ifndef IN6ADDR_MC_LLMNR_INIT
/**
 * IPv6 multicast address for LLMNR.
 */
extern const struct in6_addr in6addr_mc_llmnr;
#define IN6ADDR_MC_LLMNR_INIT { \
    {{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3}} \
}
#endif

#endif

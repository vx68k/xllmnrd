/*
 * responder - LLMNR responder (interface)
 * Copyright (C) 2013-2014 Kaz Nishimura
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

#ifndef RESPONDER_H
#define RESPONDER_H 1

#include "ifaddr.h" /* struct ifaddr_change */
#include "llmnr.h"
#include <netinet/in.h> /* in_port_t */

/**
 * Initializes the responder object.
 * @param __port port number in the network byte order; if this value is 0,
 * the default port number will be used.
 * @return 0 if succeeded, or non-zero error number.
 */
int responder_initialize(in_port_t __port);

/*
 * Finalizes the responder object.
 */
void responder_finalize(void);

/**
 * Sets the host name for which the responder object is authoritative.
 * Only the first label of the host name is used.  If it is longer than
 * 'LLMNR_LABEL_MAX' octets, it will be truncated.
 * @param __name host name.
 * @return 0 if succeeded, or non-zero error number.
 */
extern void responder_set_host_name(const char *__name);

/*
 * Runs the responder in a loop.
 */
int responder_run(void);

/*
 * Requests the termination of the responder loop.
 * This function is atomic regarding signals.
 */
extern void responder_terminate(void);

#endif

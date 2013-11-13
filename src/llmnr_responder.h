/*
 * LLMNR responder (interface)
 * Copyright (C) 2013  Kaz Nishimura
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

#ifndef LLMNR_RESPONDER_H
#define	LLMNR_RESPONDER_H 1

#include <netinet/in.h> /* in_port_t */

/*
 * Port number.
 */
#define LLMNR_PORT 5355

/**
 * Initializes this module.
 * @param __port port number in the network byte order; if this value is 0,
 * the default port number will be used.
 * @return 0 on success, or non-zero error number.
 */
int llmnr_responder_initialize(in_port_t __port);

/*
 * Finalizes this module.
 */
void llmnr_responder_finalize(void);

/*
 * Runs the responder in a loop.
 */
int llmnr_responder_run(void);

/*
 * Requests the termination of the responder loop.
 * This function is atomic regarding signals.
 */
extern void llmnr_responder_terminate(void);

#endif

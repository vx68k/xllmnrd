/*
 * Declarations for the LLMNR protocol
 * Copyright (C) 2013  Kaz Sasa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LLMNR_H
#define	LLMNR_H 1

/*
 * Port number.
 */
#define LLMNR_PORT 5355

/*
 * Initializes the responder.
 */
int llmnr_responder_initialize(void);

/*
 * Finalizes the responder.
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

/*
 * Declarations for the LLMNR protocol
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

#ifndef LLMNR_HEADER_H
#define LLMNR_HEADER_H 1

#include <arpa/inet.h>
#include <stdint.h>

#define LLMNR_HEADER_QR     0x8000
#define LLMNR_HEADER_OPCODE 0x7800
#define LLMNR_HEADER_C      0x0400
#define LLMNR_HEADER_TC     0x0200
#define LLMNR_HEADER_T      0x0100
#define LLMNR_HEADER_RCODE  0x000f

/*
 * LLMNR header structure.
 * All fields are in network byte order.
 */
struct llmnr_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

static inline int llmnr_header_is_valid_query(
        const struct llmnr_header *header) {
    /* These bits must be zero for queries.  */
    const uint16_t mask = htons(LLMNR_HEADER_QR | LLMNR_HEADER_OPCODE);
    if (header &&
            (header->flags & mask) == htons(0) &&
            header->qdcount == htons(1) &&
            header->ancount == htons(0) &&
            header->nscount == htons(0)) {
        return 1;
    }
    return 0;
}

#endif

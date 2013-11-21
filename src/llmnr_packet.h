/*
 * LLMNR packet manipulation
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

#ifndef LLMNR_PACKET_H
#define LLMNR_PACKET_H 1

#include <arpa/inet.h>
#include <stdint.h>

/*
 * Size of a header in octets.
 */
#define LLMNR_HEADER_SIZE 12

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

/**
 * Returns true if a header is valid as a query.
 * @param header pointer to a LLMNR header.
 * @return true if the query is valid, or false.
 */
static inline int llmnr_query_is_valid(
        const struct llmnr_header *restrict header) {
    // The following bits must be zero in any query.
    const uint_fast16_t mask = htons(LLMNR_HEADER_QR | LLMNR_HEADER_OPCODE);
    if ((header->flags & mask) == htons(0) && header->qdcount == htons(1) &&
            header->ancount == htons(0) && header->nscount == htons(0)) {
        return 1;
    }
    return 0;
}

/**
 * Returns a pointer to the first data in a LLMNR packet.
 * @param header [in] LLMNR header.
 * @return pointer to the first data in the LLMNR packet.
 */
static inline const uint8_t *llmnr_data(const struct llmnr_header *header) {
    return (const uint8_t *) header + LLMNR_HEADER_SIZE;
}

#endif

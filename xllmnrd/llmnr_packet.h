// llmnr_packet.h -*- C++ -*-
// Copyright (C) 2013  Kaz Nishimura
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

#ifndef LLMNR_PACKET_H
#define LLMNR_PACKET_H 1

#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Size of a header in octets.
 */
#define LLMNR_HEADER_SIZE 12

/*
 * Maximum number of octets in a label excluding a length prefix.
 * This value is derived from RFC 1035.
 */
#define LLMNR_LABEL_MAX 63

#define LLMNR_HEADER_QR     0x8000
#define LLMNR_HEADER_OPCODE 0x7800
#define LLMNR_HEADER_C      0x0400
#define LLMNR_HEADER_TC     0x0200
#define LLMNR_HEADER_T      0x0100
#define LLMNR_HEADER_RCODE  0x000f

/*
 * TYPE constants.
 */
#define LLMNR_TYPE_A       1
#define LLMNR_TYPE_PTR    12
#define LLMNR_TYPE_AAAA   28

/*
 * QTYPE constants.
 */
#define LLMNR_QTYPE_A    LLMNR_TYPE_A
#define LLMNR_QTYPE_PTR  LLMNR_TYPE_PTR
#define LLMNR_QTYPE_AAAA LLMNR_TYPE_AAAA
#define LLMNR_QTYPE_ANY  255

/*
 * CLASS constant.
 */
#define LLMNR_CLASS_IN   1

/*
 * QCLASS constant.
 */
#define LLMNR_QCLASS_IN LLMNR_CLASS_IN

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

/**
 * Reads a 16-bit value in a LLMNR packet.
 * @param i [in] two octets to be read.
 * @return read value.
 */
static inline uint16_t llmnr_get_uint16(const uint8_t *restrict i) {
    return (i[0] << 8) | i[1];
}

/**
 * Writes a 16-bit value in a LLMNR packet.
 * @param x value to be written.
 * @param i [out] two octets where the value is written.
 */
static inline void llmnr_put_uint16(uint16_t x, uint8_t *restrict i) {
    i[0] = x >> 8;
    i[1] = x;
}

/**
 * Writes a 32-bit value in a LLMNR packet.
 * @param x value to be written.
 * @param i [out] four octets where the value is written.
 */
static inline void llmnr_put_uint32(uint32_t x, uint8_t *restrict i) {
    i[0] = x >> 24;
    i[1] = x >> 16;
    i[2] = x >>  8;
    i[3] = x;
}

/**
 * Skips a name in a LLMNR packet.
 * @param i [in] first octet of the name.
 * @param n [inout] number of unused octets.
 * @return pointer after the name, or null if an error is detected.
 */
static inline const uint8_t *llmnr_skip_name(const uint8_t *restrict i,
        size_t *restrict n) {
    bool done;
    do {
        if (*n < 1) {
            return NULL;
        }
        size_t length = *i++;
        --(*n);

        // Checks the most significant two bits.
        switch (length >> 6) {
        case 3:
            if (*n < 1) {
                return NULL;
            }
            ++i;
            --(*n);
            done = true;
            break;

        case 0:
            if (*n < length) {
                return NULL;
            }
            i += length;
            *n -= length;
            done = length == 0;
            break;

        default:
            // Handles exceptional cases.
            return NULL;
        }
    } while (!done);

    return i;
}

#endif

// ascii.h
// Copyright (C) 2013-2020 Kaz Nishimura
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

#ifndef ASCII_H
#define ASCII_H 1

#include <stdint.h>
#include <stdbool.h>

/*
 * NOTE: These functions MUST be locale-independent.
 */

/**
 * Returns true if a character is an uppercase letter in the US-ASCII
 * character set.
 * @param c character to be tested.
 * @return true if the argument is an uppercase letter; otherwise false.
 */
static inline int ascii_is_upper(uint_fast8_t c) {
    if (c >= 'A' && c <= 'Z') {
        return 1;
    }
    return 0;
}

/**
 * Returns true if a character is a lowercase letter in the US-ASCII
 * character set.
 * @param c character to be tested.
 * @return true if the argument is a lowercase letter; otherwise false.
 */
static inline int ascii_is_lower(uint_fast8_t c) {
    if (c >= 'a' && c <= 'z') {
        return true;
    }
    return false;
}

/**
 * Converts a lowercase letter in the US-ASCII character set to a
 * corresponding uppercase letter.
 * @param c character to be converted.
 * @return the corresponding uppercase letter if the argument is a lowercase
 * letter; otherwise the argument unchanged.
 */
static inline uint_fast8_t ascii_to_upper(uint_fast8_t c) {
    if (ascii_is_lower(c)) {
        c -= 'a' - 'A';
    }
    return c;
}

/**
 * Converts an uppercase letter in the US-ASCII character set to a
 * corresponding lowercase letter.
 * @param c character to be converted.
 * @return the corresponding lowercase letter if the argument is an uppercase
 * letter; otherwise the argument unchanged.
 */
static inline uint_fast8_t ascii_to_lower(uint_fast8_t c) {
    if (ascii_is_lower(c)) {
        c += 'a' - 'A';
    }
    return c;
}

#endif

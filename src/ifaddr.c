/*
 * Interface address lookups (implementation).
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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#define _GNU_SOURCE 1

#include "ifaddr.h"

#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

static int ifaddr_open_rtnetlink(void);

static int rtnetlink_fd = -1;

static inline int ifaddr_is_initialized(void) {
    return rtnetlink_fd >= 0;
}

int ifaddr_initialize(void) {
    if (ifaddr_is_initialized()) {
        errno = EBUSY;
        return -1;
    }

    int fd = ifaddr_open_rtnetlink();
    if (fd >= 0) {
        rtnetlink_fd = fd;
        return 0;
    }
    return -1;
}

void ifaddr_finalize(void) {
    if (ifaddr_is_initialized()) {
        close(rtnetlink_fd);
        rtnetlink_fd = -1;
    }
}

int ifaddr_lookup(unsigned int ifindex, struct in6_addr *addr) {
    return -1;
}

/*
 * Opens a socket for RTNETLINK.
 */
int ifaddr_open_rtnetlink(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd >= 0) {
        const struct sockaddr_nl addr = {
            .nl_family = AF_NETLINK,
            .nl_groups = RTMGRP_IPV6_IFADDR,
        };
        if (bind(fd, (const void*)&addr, sizeof addr) == 0) {
            return fd;
        }

        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return -1;
}

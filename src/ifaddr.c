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
#include <pthread.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

static int ifaddr_open_rtnetlink(void);

/**
 * Keeps how many times this module has been initialized recursively.
 * The value SHALL be incremented up to INT_MAX by each call to
 * ifaddr_initialize() and decremented by each call to ifaddr_finalize().
 */
static unsigned int initialize_count;

static int rtnetlink_fd = -1;

static volatile sig_atomic_t terminated;

/**
 * Identifier for the worker thread.
 */
static pthread_t worker_thread;

/**
 * Returns non-zero if this module has been initialized.
 */
static inline int ifaddr_initialized(void) {
    return initialize_count > 0;
}

static int ifaddr_start_worker(void);
static void *ifaddr_run(void *__data);

int ifaddr_initialize(void) {
    if (!ifaddr_initialized()) {
        int fd = ifaddr_open_rtnetlink();
        if (fd >= 0) {
            rtnetlink_fd = fd;

            int err = ifaddr_start_worker();
            if (err == 0) {
                return initialize_count++;
            }

            close(rtnetlink_fd);
            rtnetlink_fd = -1;
            errno = err;
        }
    } else {
        if (initialize_count < INT_MAX) {
            return initialize_count++;
        }
        errno = EOVERFLOW;
    }
    return -1;
}

void ifaddr_finalize(void) {
    if (ifaddr_initialized()) {
        if (--initialize_count == 0) {
            close(rtnetlink_fd);
            rtnetlink_fd = -1;
        }
    }
}

/**
 * Starts the worker thread.
 * @return 0 on success, non-zero error number on failure
 */
int ifaddr_start_worker(void) {
    // The worker thread should not catch signals except SIGUSR2.
    sigset_t set, oset;
    sigfillset(&set);
    sigdelset(&set, SIGUSR2);

    int err = pthread_sigmask(SIG_SETMASK, &set, &oset);
    if (err == 0) {
        err = pthread_create(&worker_thread, 0, &ifaddr_run, 0);
        // Restore the signal mask before proceeding.
        // Errors are not significant here.
        pthread_sigmask(SIG_SETMASK, &oset, 0);
    }
    return err;
}


/**
 * Runs the worker in a loop.
 * @param data
 * @return the value of data
 */
void *ifaddr_run(void *data) {
    if (ifaddr_initialized()) {
        terminated = 0;
        while (!terminated) {
            unsigned char buf[128];
            ssize_t recv_size = recv(rtnetlink_fd, buf, sizeof buf, 0);
            struct nlmsghdr *nlmsg = (void *)buf;
            if (recv_size >= 0 && (size_t)recv_size >= sizeof *nlmsg) {
                if (nlmsg->nlmsg_type == NLMSG_ERROR) {
                    struct nlmsgerr *err = NLMSG_DATA(nlmsg);
                    if (nlmsg->nlmsg_len >= NLMSG_LENGTH(sizeof *err)) {
                        syslog(LOG_ERR, "Got rtnetlink error: %s",
                                strerror(-(err->error)));
                    }
                }
            }
        }
    }
    return data;
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

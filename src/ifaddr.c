/*
 * Interface address lookups (implementation)
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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#define _GNU_SOURCE 1

#include "ifaddr.h"

#include <linux/rtnetlink.h>
#include <arpa/inet.h> /* inet_ntop */
#include <sys/socket.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>

static int open_rtnetlink(void);

/**
 * True if this module has been initialized.
 */
static bool initialized;

/**
 * File descriptor for the rtnetlink socket.
 */
static int rtnetlink_fd;

static volatile sig_atomic_t terminated;

/**
 * Identifier for the worker thread.
 */
static pthread_t worker_thread;

/**
 * Mutex for refresh_not_in_progress.
 */
static pthread_mutex_t refresh_mutex;

/**
 * Condition variable for refresh_not_in_progress.
 */
static pthread_cond_t refresh_cond;

/**
 * Indicates if a refresh operation is not in progress.
 */
static volatile bool refresh_not_in_progress;

/**
 * Returns non-zero if this module has been initialized.
 */
static inline int ifaddr_initialized(void) {
    return initialized;
}

static int ifaddr_start_worker(void);
static void *ifaddr_run(void *__data);

/**
 * Decodes netlink messages.
 * @param __nlmsg pointer to the first netlink message
 * @param __size total size of the netlink messages
 */
static void ifaddr_decode_nlmsg(struct nlmsghdr *__nlmsg, size_t __size);

/**
 * Handles a rtnetlink message of type 'struct ifaddrmsg'.
 * @param __nlmsg pointer to the netlink message
 */
static void ifaddr_handle_ifaddrmsg(const struct nlmsghdr *__nlmsg);


int ifaddr_initialize(void) {
    if (ifaddr_initialized()) {
        errno = EBUSY;
        return -1;
    }
    initialized = true;

    int fd = open_rtnetlink();
    if (fd >= 0) {
        rtnetlink_fd = fd;

        int err = ifaddr_start_worker();
        if (err == 0) {
            err = pthread_mutex_init(&refresh_mutex, 0);
            if (err == 0) {
                err = pthread_cond_init(&refresh_cond, 0);
                if (err == 0) {
                    refresh_not_in_progress = true;

                    err = ifaddr_refresh();
                    if (err == 0) {
                        return 0;
                    }
                }
                // Errors are not significant here.
                pthread_cond_destroy(&refresh_cond);
            }
            // Errors are not significant here.
            pthread_mutex_destroy(&refresh_mutex);
        }

        close(rtnetlink_fd);
        errno = err;
    }
    initialized = false;
    return -1;
}

void ifaddr_finalize(void) {
    if (ifaddr_initialized()) {
        initialized = false;

        pthread_cond_destroy(&refresh_cond);
        pthread_mutex_destroy(&refresh_mutex);

        close(rtnetlink_fd);
        rtnetlink_fd = -1;
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
    assert(ifaddr_initialized());
    terminated = 0;
    while (!terminated) {
        // Gets the required buffer size.
        ssize_t recv_size = recv(rtnetlink_fd, 0, 0, MSG_PEEK | MSG_TRUNC);

        unsigned char buf[recv_size];
        ssize_t recv_len = recv(rtnetlink_fd, buf, recv_size, 0);

        struct nlmsghdr *nlmsg = (void *) buf;
        if (recv_len >= 0) {
            ifaddr_decode_nlmsg(nlmsg, recv_len);
        } else if (errno != EINTR) {
            syslog(LOG_ERR, "Failed to recv from rtnetlink: %s",
                    strerror(errno));
        }
    }
    return data;
}

void ifaddr_decode_nlmsg(struct nlmsghdr *nlmsg, size_t len) {
    while (NLMSG_OK(nlmsg, len)) {
        bool done = false;

        switch (nlmsg->nlmsg_type) {
        case NLMSG_NOOP:
            syslog(LOG_INFO, "Got NLMSG_NOOP");
            break;
        case NLMSG_ERROR:
        {
            struct nlmsgerr *err = NLMSG_DATA(nlmsg);
            if (nlmsg->nlmsg_len >= NLMSG_LENGTH(sizeof *err)) {
                syslog(LOG_ERR, "Got rtnetlink error: %s",
                        strerror(-(err->error)));
            }
            break;
        }
        case NLMSG_DONE:
            pthread_mutex_lock(&refresh_mutex);
            refresh_not_in_progress = true;
            pthread_cond_broadcast(&refresh_cond);
            pthread_mutex_unlock(&refresh_mutex);
            done = true;
            break;
        case RTM_NEWADDR:
            syslog(LOG_DEBUG, "Got RTM_NEWADDR");
            ifaddr_handle_ifaddrmsg(nlmsg);
            break;
        case RTM_DELADDR:
            syslog(LOG_DEBUG, "Got RTM_DELADDR");
            ifaddr_handle_ifaddrmsg(nlmsg);
            break;
        default:
            syslog(LOG_INFO, "Unknown netlink message type: %u",
                    (unsigned int) nlmsg->nlmsg_type);
            break;
        }

        if ((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0 || done) {
            // There are no more messages.
            break;
        }
        nlmsg = NLMSG_NEXT(nlmsg, len);
    }
}

void ifaddr_handle_ifaddrmsg(const struct nlmsghdr *const nlmsg) {
    struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlmsg);
    // We use 'NLMSG_SPACE' instead of 'NLMSG_LENGTH' since the payload must
    // be aligned.
    if (nlmsg->nlmsg_len >= NLMSG_SPACE(sizeof *ifa)) {
        struct rtattr *rta = (struct rtattr *)
                ((char *) nlmsg + NLMSG_SPACE(sizeof *ifa));
        size_t rta_len = nlmsg->nlmsg_len - NLMSG_SPACE(sizeof *ifa);
        syslog(LOG_DEBUG, "  Interface %u",
                (unsigned int) ifa->ifa_index);
        while (RTA_OK(rta, rta_len)) {
            if (rta->rta_type == IFA_ADDRESS) {
                struct in6_addr *addr = RTA_DATA(rta);

                char addrstr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, addr, addrstr, INET6_ADDRSTRLEN);
                syslog(LOG_DEBUG, "  Address %s", addrstr);
            }
            rta = RTA_NEXT(rta, rta_len);
        }
    }
}

int ifaddr_refresh(void) {
    int result = -1;
    if (ifaddr_initialized()) {
        pthread_mutex_lock(&refresh_mutex);

        unsigned char buf[128];
        struct nlmsghdr *nlmsg = (void*) buf;
        struct ifaddrmsg *ifa = NLMSG_DATA(nlmsg);
        *nlmsg = (struct nlmsghdr) {
            .nlmsg_len = NLMSG_LENGTH(sizeof *ifa),
            .nlmsg_type = RTM_GETADDR,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,
        };
        *ifa = (struct ifaddrmsg) {
            .ifa_family = AF_INET6,
        };
        if (!refresh_not_in_progress ||
                send(rtnetlink_fd, buf, nlmsg->nlmsg_len, 0) >= 0) {
            refresh_not_in_progress = false;
            do {
                pthread_cond_wait(&refresh_cond, &refresh_mutex);
            } while (!refresh_not_in_progress);

            result = 0;
        }

        pthread_mutex_unlock(&refresh_mutex);
    } else {
        // TODO: Choose a better error number.
        errno = EBADF;
    }
    return result;
}

int ifaddr_lookup(unsigned int ifindex, struct in6_addr *addr) {
    return -1;
}

/*
 * Opens a socket for RTNETLINK.
 */
int open_rtnetlink(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd >= 0) {
        const struct sockaddr_nl addr = {
            .nl_family = AF_NETLINK,
            .nl_groups = RTMGRP_IPV6_IFADDR,
        };
        if (bind(fd, (const void *) &addr, sizeof addr) == 0) {
            return fd;
        }

        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return -1;
}

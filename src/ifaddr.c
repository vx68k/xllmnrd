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
#include <config.h>
#endif
#define _GNU_SOURCE 1

#include "ifaddr.h"

#if HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#endif
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h> /* abort */
#include <errno.h>
#include <stdbool.h>
#include <assert.h>

/**
 * Terminates the program abnormally if a error is detected.
 * @param e value to be checked for an error.
 * @param message error message.
 */
static inline void abort_if_error(int err, const char *restrict message) {
    if (err != 0) {
        syslog(LOG_CRIT, "%s: %s", message, strerror(err));
        abort();
    }
}

/**
 * Opens a RTNETLINK socket and binds to necessary groups.
 */
static inline int open_rtnetlink(int *restrict fd_out) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    int err = errno;
    if (fd >= 0) {
        struct sockaddr_nl addr = {
            .nl_family = AF_NETLINK,
            .nl_groups = RTMGRP_IPV6_IFADDR,
        };
        if (bind(fd, (struct sockaddr *) &addr, sizeof addr) == 0) {
            *fd_out = fd;
            return 0;
        }
        err = errno;
        close(fd);
    }
    return err;
}

struct ifaddr_if {
    unsigned int ifindex;
    struct in6_addr addr;
};

/**
 * True if this module has been initialized.
 */
static bool initialized;

/**
 * Signal number that will be used to interrupt the worker thread.
 * If this value is zero, no signal will be used.
 */
static int interrupt_signo;

/**
 * File descriptor for the rtnetlink socket.
 */
static int rtnetlink_fd;

/**
 * Mutex for the interface table.
 */
static pthread_mutex_t if_mutex;

/**
 * Pointer to the interface change handler.
 */
static ifaddr_change_handler if_change_handler;

static const size_t if_table_capacity = 32;
static size_t if_table_size;
static struct ifaddr_if if_table[32]; // TODO: Allocate dynamically.

/**
 * Mutex for refresh_not_in_progress.
 */
static pthread_mutex_t refresh_mutex;

/**
 * Condition variable for refresh_not_in_progress.
 */
static pthread_cond_t refresh_cond;

/**
 * True if a refresh operation is not in progress.
 * This flag is volatile as it is used from multiple threads.
 */
static volatile bool refresh_not_in_progress;

/**
 * True if the worker thread is started.
 */
static bool started;

/**
 * Identifier for the worker thread.
 */
static pthread_t worker_thread;

static volatile sig_atomic_t terminated;

/**
 * Returns non-zero if this module has been initialized.
 */
static inline int ifaddr_initialized(void) {
    return initialized;
}

/**
 * Returns true if the worker thread is started.
 * The return value is valid only if this module is initialized.
 * @return non-zero if the worker thread is started, or zero if not.
 */
static inline int ifaddr_started(void) {
    return started;
}

static inline void ifaddr_add_interface(unsigned int ifindex,
        const struct in6_addr *restrict addr) {
    abort_if_error(pthread_mutex_lock(&if_mutex),
            "ifaddr: Could not lock 'if_mutex'");

    unsigned int i = 0;
    while (i != if_table_size && if_table[i].ifindex != ifindex) {
        ++i;
    }
    if (i == if_table_size) {
        if (if_table_size == if_table_capacity) {
            abort(); // TODO: Think later.
        }
        ++if_table_size;

        if_table[i].ifindex = ifindex;
        if_table[i].addr = *addr;
        if (if_change_handler) {
            struct ifaddr_change change = {
                .type = IFADDR_ADDED,
                .ifindex = ifindex,
            };
            (*if_change_handler)(&change);
        }
    } else if (!IN6_ARE_ADDR_EQUAL(&if_table[i].addr, addr)) {
        // Handles an address-only change.
        if_table[i].addr = *addr;
        if (if_change_handler) {
            struct ifaddr_change change = {
                .type = IFADDR_ADDED,
                .ifindex = ifindex,
            };
            (*if_change_handler)(&change);
        }        
    }

    abort_if_error(pthread_mutex_unlock(&if_mutex),
            "ifaddr: Could not lock 'if_mutex'");
}

static inline void ifaddr_remove_interface(unsigned int ifindex,
        const struct in6_addr *restrict addr) {
    abort_if_error(pthread_mutex_lock(&if_mutex),
            "ifaddr: Could not lock 'if_mutex'");

    unsigned int i = 0;
    while (i != if_table_size && if_table[i].ifindex != ifindex) {
        ++i;
    }
    if (i != if_table_size && IN6_ARE_ADDR_EQUAL(&if_table[i].addr, addr)) {
        --if_table_size;
        while (i != if_table_size) {
            if_table[i] = if_table[i + 1];
            ++i;
        }

        if (if_change_handler) {
            struct ifaddr_change change = {
                .type = IFADDR_REMOVED,
                .ifindex = ifindex,
            };
            (*if_change_handler)(&change);
        }
    }

    abort_if_error(pthread_mutex_unlock(&if_mutex),
            "ifaddr: Could not unlock 'if_mutex'");
}

/**
 * Waits for the running refresh operation to complete.
 */
static inline void ifaddr_wait_for_refresh_completion(void) {
    abort_if_error(pthread_mutex_lock(&refresh_mutex),
            "ifaddr: Could not lock 'refresh_mutex'");

    while (!refresh_not_in_progress) {
        abort_if_error(pthread_cond_wait(&refresh_cond, &refresh_mutex),
                "ifaddr: Could not wait for 'refresh_cond'");
    }

    abort_if_error(pthread_mutex_unlock(&refresh_mutex),
            "ifaddr: Could not unlock 'refresh_mutex'");
}

static inline void ifaddr_complete_refresh(void) {
    abort_if_error(pthread_mutex_lock(&refresh_mutex),
            "ifaddr: Could not lock 'refresh_mutex'");

    refresh_not_in_progress = true;
    abort_if_error(pthread_cond_broadcast(&refresh_cond),
            "ifaddr: Could not broadcast 'refresh_cond'");

    abort_if_error(pthread_mutex_unlock(&refresh_mutex),
            "ifaddr: Could not unlock 'refresh_mutex'");
}

static void *ifaddr_run(void *__data);

/**
 * Decodes netlink messages.
 * @param __nlmsg pointer to the first netlink message
 * @param __size total size of the netlink messages
 */
static void ifaddr_decode_nlmsg(const struct nlmsghdr *__nlmsg, size_t __len);

/**
 * Handles a rtnetlink message of type 'struct ifaddrmsg'.
 * @param __nlmsg pointer to the netlink message
 */
static void ifaddr_handle_ifaddrmsg(const struct nlmsghdr *__nlmsg);


int ifaddr_initialize(int sig) {
    if (ifaddr_initialized()) {
        return EBUSY;
    }
    interrupt_signo = sig;
    if_change_handler = NULL;
    if_table_size = 0;
    started = false;
    refresh_not_in_progress = true;

    int err = open_rtnetlink(&rtnetlink_fd);
    if (err == 0) {
        err = pthread_mutex_init(&if_mutex, NULL);
        if (err == 0) {
            err = pthread_mutex_init(&refresh_mutex, 0);
            if (err == 0) {
                err = pthread_cond_init(&refresh_cond, 0);
                if (err == 0) {
                    initialized = true;
                    return 0;
                }
                pthread_cond_destroy(&refresh_cond);
            }
            pthread_mutex_destroy(&refresh_mutex);
        }
        pthread_mutex_destroy(&if_mutex);

        close(rtnetlink_fd);
    }
    return err;
}

void ifaddr_finalize(void) {
    if (ifaddr_initialized()) {
        initialized = false;

        if (ifaddr_started()) {
            terminated = true;

            if (interrupt_signo != 0) {
                pthread_kill(worker_thread, interrupt_signo); // TODO: Check for an error.
            }
            pthread_join(worker_thread, NULL); // TODO: Check for an error.
        }

        abort_if_error(pthread_cond_destroy(&refresh_cond),
                "ifaddr: Could not destroy 'refresh_cond'");
        abort_if_error(pthread_mutex_destroy(&refresh_mutex),
                "ifaddr: Could not destroy 'refresh_mutex'");
        abort_if_error(pthread_mutex_destroy(&if_mutex),
                "ifaddr: Could not destroy 'if_mutex'");
        if (close(rtnetlink_fd) != 0) {
            syslog(LOG_CRIT, "ifaddr: Could not close 'rtnetlink_fd': %s",
                    strerror(errno));
            abort();
        }
    }
}

int ifaddr_set_change_handler(ifaddr_change_handler handler,
        ifaddr_change_handler *old_handler_out) {
    if (!ifaddr_initialized()) {
        return ENXIO;
    }

    // This lock might be unnecessary, but it looks safer.
    abort_if_error(pthread_mutex_lock(&if_mutex),
            "ifaddr: Could not lock 'if_mutex'");

    if (old_handler_out) {
        *old_handler_out = if_change_handler;
    }
    if_change_handler = handler;

    abort_if_error(pthread_mutex_unlock(&if_mutex),
            "ifaddr: Could not lock 'if_mutex'");

    return 0;
}

int ifaddr_start(void) {
    if (!ifaddr_initialized()) {
        return ENXIO;
    }

    int err = 0;
    if (!ifaddr_started()) {
        terminated = false;

        sigset_t set, oset;
        sigfillset(&set);
        if (interrupt_signo != 0) {
            sigdelset(&set, interrupt_signo);
        }

        err = pthread_sigmask(SIG_SETMASK, &set, &oset);
        if (err == 0) {
            err = pthread_create(&worker_thread, 0, &ifaddr_run, 0);
            // Restores the signal mask before proceeding.
            abort_if_error(pthread_sigmask(SIG_SETMASK, &oset, 0),
                    "ifaddr: Could not restore the signal mask");

            if (err == 0) {
                started = true;
                return ifaddr_refresh();
            }
        }
    }
    return err;
}

/**
 * Runs the worker in a loop.
 * @param data
 * @return the value of data
 */
void *ifaddr_run(void *data) {
    while (!terminated) {
        // Gets the required buffer size.
        ssize_t recv_size = recv(rtnetlink_fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
        if (recv_size < 0) {
            if (errno != EINTR) {
                syslog(LOG_ERR, "Failed to recv from rtnetlink: %s",
                        strerror(errno));
                return data;
            }
        } else {
            unsigned char buf[recv_size];
            ssize_t recv_len = recv(rtnetlink_fd, buf, recv_size, 0);
            if (recv_len < 0) {
                if (errno != EINTR) {
                    syslog(LOG_ERR, "Failed to recv from rtnetlink: %s",
                            strerror(errno));
                    return data;
                }
            } else {
                const struct nlmsghdr *nlmsg = (struct nlmsghdr *) buf;
                assert(recv_len == recv_size);
                ifaddr_decode_nlmsg(nlmsg, recv_len);
            }
        }
    }
    return data;
}

void ifaddr_decode_nlmsg(const struct nlmsghdr *nlmsg, size_t len) {
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
            ifaddr_complete_refresh();
            done = true;
            break;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            ifaddr_handle_ifaddrmsg(nlmsg);
            break;
        default:
            syslog(LOG_DEBUG, "Unknown netlink message type: %u",
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
    // We use 'NLMSG_SPACE' instead of 'NLMSG_LENGTH' since the payload must
    // be aligned.
    const size_t rta_offset = NLMSG_SPACE(sizeof (struct ifaddrmsg));
    if (nlmsg->nlmsg_len >= rta_offset) {
        const struct ifaddrmsg *ifa = (const struct ifaddrmsg *)
                NLMSG_DATA(nlmsg);
        const struct rtattr *rta = (const struct rtattr *)
                ((const char *) nlmsg + rta_offset);
        size_t rta_len = nlmsg->nlmsg_len - rta_offset;

        while (RTA_OK(rta, rta_len)) {
            switch (ifa->ifa_family) {
            case AF_INET6:
                if (rta->rta_len >= RTA_LENGTH(sizeof (struct in6_addr)) &&
                        rta->rta_type == IFA_ADDRESS) {
                    const struct in6_addr *addr = (const struct in6_addr *)
                            RTA_DATA(rta);
                    if (IN6_IS_ADDR_LINKLOCAL(addr)) {
                        switch (nlmsg->nlmsg_type) {
                        case RTM_NEWADDR:
                            ifaddr_add_interface(ifa->ifa_index, addr);
                            break;

                        case RTM_DELADDR:
                            ifaddr_remove_interface(ifa->ifa_index, addr);
                            break;
                        }
                    }
                }
                break;

            case AF_INET:
                if (rta->rta_len >= RTA_LENGTH(sizeof (struct in_addr)) &&
                        rta->rta_type == IFA_ADDRESS) {
                    // TODO: Implement IPv4 handler.
                }
                break;
            }
            rta = RTA_NEXT(rta, rta_len);
        }
    }
}

int ifaddr_refresh(void) {
    if (!ifaddr_initialized() || !ifaddr_started()) {
        return ENXIO;
    }

    abort_if_error(pthread_mutex_lock(&refresh_mutex),
            "ifaddr: Could not lock 'refresh_mutex'");

    int err = 0;
    if (refresh_not_in_progress) {
        abort_if_error(pthread_mutex_lock(&if_mutex),
                "ifaddr: Could not lock 'if_mutex'");
        if_table_size = 0;
        abort_if_error(pthread_mutex_unlock(&if_mutex),
                "ifaddr: Could not unlock 'if_mutex'");

        unsigned char buf[128];
        struct nlmsghdr *nlmsg = (struct nlmsghdr *) buf;
        struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlmsg);
        *nlmsg = (struct nlmsghdr) {
            .nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg)),
            .nlmsg_type = RTM_GETADDR,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,
        };
        *ifa = (struct ifaddrmsg) {
            .ifa_family = AF_INET6,
        };

        ssize_t send_len = send(rtnetlink_fd, nlmsg, nlmsg->nlmsg_len, 0);
        if (send_len < 0) {
            err = errno;
        } else if ((size_t) send_len != nlmsg->nlmsg_len) {
            syslog(LOG_CRIT, "ifaddr: Truncated request");
            abort();
        }
    }

    if (err == 0) {
        refresh_not_in_progress = false;
    }

    abort_if_error(pthread_mutex_unlock(&refresh_mutex),
            "ifaddr: Could not unlock 'refresh_mutex'");

    return err;
}

int ifaddr_lookup(unsigned int ifindex, struct in6_addr *restrict addr_out) {
    if (!ifaddr_initialized() || !ifaddr_started()) {
        return ENXIO;
    }

    ifaddr_wait_for_refresh_completion();

    abort_if_error(pthread_mutex_lock(&if_mutex),
            "ifaddr: Could not lock 'ifable_mutex'");

    unsigned int i = 0;
    while (i != if_table_size && if_table[i].ifindex != ifindex) {
        ++i;
    }

    int err = 0;
    if (i != if_table_size) {
        if (addr_out) {
            *addr_out = if_table[i].addr;
        }
    } else {
        err = ENODEV;
    }

    abort_if_error(pthread_mutex_unlock(&if_mutex),
            "ifaddr: Could not unlock 'ifable_mutex'");

    return err;
}

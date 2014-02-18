/*
 * Interface address lookups (implementation)
 * Copyright (C) 2013 Kaz Nishimura
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
#undef _GNU_SOURCE
// Workaround for undefined s6_addr32 in IN6_IS_ADDR_UNSPECIFIED.
// TODO: Remove this workaround when we no longer need it.
#if __GNUC__
#define _GNU_SOURCE 1
#endif

#include "ifaddr.h"

#if HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#endif
#include <net/if.h> /* if_indextoname */
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
 * Terminates the program abnormally if an error is detected.
 * @param err value to be checked for an error.
 * @param name display name of the operation.
 */
static inline void assume_no_error(int err, const char *restrict name) {
    if (err != 0) {
        syslog(LOG_CRIT, "ifaddr: Failed to %s: %s", name, strerror(err));
        abort();
    }
}

/**
 * Destroys a mutex assuming no error is detected.
 * @param mutex [in] mutex to be destroyed.
 */
static inline void destroy_mutex(pthread_mutex_t *mutex) {
    assume_no_error(pthread_mutex_destroy(mutex), "destroy a mutex");
}

/**
 * Locks a mutex assuming no error is detected.
 * @param mutex [inout] mutex to be locked.
 */
static inline void lock_mutex(pthread_mutex_t *mutex) {
    assume_no_error(pthread_mutex_lock(mutex), "lock a mutex");
}

/**
 * Unlocks a mutex assuming no error is detected.
 * @param mutex [inout] mutex to be unlocked.
 */
static inline void unlock_mutex(pthread_mutex_t *mutex) {
    assume_no_error(pthread_mutex_unlock(mutex), "unlock a mutex");
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
            .nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
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

/**
 * Interface record.
 */
struct ifaddr_if {
    unsigned int ifindex;
    size_t addr_v4_size;
    struct in_addr *addr_v4;
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
 * Flag to indicates if a refresh operation is not in progress.
 * This flag MUST be accessed while 'refresh_mutex' is locked.
 */
static bool refresh_not_in_progress;

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
 * Adds an IPv4 address to an interface.
 * @param __index interface index.
 * @param __addr [in] IPv4 address to be added.
 */
static void ifaddr_add_addr_v4(unsigned int __index,
        const struct in_addr *__addr);

/**
 * Removes an IPv4 address from an interface.
 * @param __index interface index.
 * @param __addr [in] IPv4 address to be removed.
 */
static void ifaddr_remove_addr_v4(unsigned int __index,
        const struct in_addr *__addr);

/*
 * Declarations for static functions.
 */

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

/**
 * Handles a sequence of RTNETLINK attributes for an IPv4 ifaddrmsg.
 * @param __nlmsg_type message type, either RTM_NEWADDR or RTM_DELADDR.
 * @param __index interface index.
 * @param __rta [in] first RTNETLINK attribute.
 * @param __rta_size total size of all the RTNETLINK attributes.
 */
static void ifaddr_v4_handle_rtattrs(unsigned int __nlmsg_type,
        unsigned int __index, const struct rtattr *__rta, size_t __rta_size);

/**
 * Handles a sequence of RTNETLINK attributes for an IPv6 ifaddrmsg.
 * @param __nlmsg_type message type, either RTM_NEWADDR or RTM_DELADDR.
 * @param __index interface index.
 * @param __rta [in] first RTNETLINK attribute.
 * @param __rta_size total size of all the RTNETLINK attributes.
 */
static void ifaddr_v6_handle_rtattrs(unsigned int __nlmsg_type,
        unsigned int __index, const struct rtattr *__rta, size_t __rta_size);

/*
 * Definitions for in-line functions.
 */

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

/**
 * Tests if an interface has no address.
 * This function MUST be called while 'if_mutex' is locked.
 * @param i [in] interface record to be tested.
 * @return true if the interface has no address.
 */
static inline int ifaddr_interface_is_free(
        const struct ifaddr_if * restrict i) {
    return i->addr_v4_size == 0 && IN6_IS_ADDR_UNSPECIFIED(&i->addr);
}

/**
 * Erases an interface.
 * This function MUST be called while 'if_mutex' is locked.
 * @param i [in] interface record to be erased.
 */
static inline void ifaddr_erase_interface(struct ifaddr_if *restrict i) {
    free(i->addr_v4);

    struct ifaddr_if *j = i++;
    while (i != if_table + if_table_size) {
        *j++ = *i++;
    }
    --if_table_size;

    // Clears the pointer that is no longer used though it is unnecessary.
    if_table[if_table_size].addr_v4 = NULL;
}

/**
 * Adds an IPv6 address to an interface.
 * @param index interface index.
 * @param addr IPv6 address.
 */
static inline void ifaddr_add_addr_v6(unsigned int index,
        const struct in6_addr *restrict addr) {
    lock_mutex(&if_mutex);

    unsigned int i = 0;
    while (i != if_table_size && if_table[i].ifindex != index) {
        ++i;
    }
    if (i == if_table_size) {
        if (if_table_size == if_table_capacity) {
            abort(); // TODO: Think later.
        }
        ++if_table_size;

        if_table[i] = (struct ifaddr_if){
            .ifindex = index,
            .addr = *addr,
        };
        if (if_change_handler) {
            struct ifaddr_change change = {
                .type = IFADDR_ADDED,
                .ifindex = index,
            };
            (*if_change_handler)(&change);
        }
    } else if (!IN6_ARE_ADDR_EQUAL(&if_table[i].addr, addr)) {
        // Handles an address-only change.
        if_table[i].addr = *addr;
        if (if_change_handler) {
            struct ifaddr_change change = {
                .type = IFADDR_ADDED,
                .ifindex = index,
            };
            (*if_change_handler)(&change);
        }
    }

    unlock_mutex(&if_mutex);
}

/**
 * Removes an IPv6 address from an interface.
 * @param index interface index.
 * @param addr IPv6 address.
 */
static inline void ifaddr_remove_addr_v6(unsigned int index,
        const struct in6_addr *restrict addr) {
    lock_mutex(&if_mutex);

    unsigned int i = 0;
    while (i != if_table_size && if_table[i].ifindex != index) {
        ++i;
    }
    if (i != if_table_size && IN6_ARE_ADDR_EQUAL(&if_table[i].addr, addr)) {
        if_table[i].addr = in6addr_any;
        if (ifaddr_interface_is_free(&if_table[i])) {
            ifaddr_erase_interface(&if_table[i]);
        }

        if (if_change_handler) {
            struct ifaddr_change change = {
                .type = IFADDR_REMOVED,
                .ifindex = index,
            };
            (*if_change_handler)(&change);
        }
    }

    unlock_mutex(&if_mutex);
}

/**
 * Waits for the running refresh operation to complete.
 */
static inline void ifaddr_wait_for_refresh_completion(void) {
    lock_mutex(&refresh_mutex);

    while (!refresh_not_in_progress) {
        assume_no_error(pthread_cond_wait(&refresh_cond, &refresh_mutex),
                "wait for a condition");
    }

    unlock_mutex(&refresh_mutex);
}

static inline void ifaddr_complete_refresh(void) {
    lock_mutex(&refresh_mutex);

    refresh_not_in_progress = true;
    assume_no_error(pthread_cond_broadcast(&refresh_cond),
            "broadcast a condition");

    unlock_mutex(&refresh_mutex);
}

/*
 * Definitions for out-of-line functions.
 */

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
                assume_no_error(pthread_cond_destroy(&refresh_cond),
                        "destroy a conditon");
            }
            destroy_mutex(&refresh_mutex);
        }
        destroy_mutex(&if_mutex);

        if (close(rtnetlink_fd) != 0) {
            syslog(LOG_ERR, "ifaddr: Failed to close a socket: %s",
                    strerror(errno));
        }
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

        assume_no_error(pthread_cond_destroy(&refresh_cond),
                "destroy a condition");
        destroy_mutex(&refresh_mutex);
        destroy_mutex(&if_mutex);

        if (close(rtnetlink_fd) != 0) {
            syslog(LOG_ERR, "ifaddr: Failed to close a socket: %s",
                    strerror(errno));
        }
    }
}

int ifaddr_set_change_handler(ifaddr_change_handler handler,
        ifaddr_change_handler *old_handler_out) {
    if (!ifaddr_initialized()) {
        return ENXIO;
    }

    lock_mutex(&if_mutex);

    if (old_handler_out) {
        *old_handler_out = if_change_handler;
    }
    if_change_handler = handler;

    unlock_mutex(&if_mutex);

    return 0;
}

void ifaddr_add_addr_v4(unsigned int index,
        const struct in_addr *restrict addr) {
    lock_mutex(&if_mutex);

    struct ifaddr_if *i = if_table;
    while (i != if_table + if_table_size && i->ifindex != index) {
        ++i;
    }
    if (i == if_table + if_table_size) {
        if (if_table_size == if_table_capacity) {
            abort(); // TODO: Think later.
        }
        *i = (struct ifaddr_if){
            .ifindex = index,
            .addr_v4_size = 0,
        };
        ++if_table_size;
    }

    struct in_addr *j = i->addr_v4;
    while (j != i->addr_v4 + i->addr_v4_size && j->s_addr != addr->s_addr) {
        ++j;
    }
    // Appends an address if no matching one is found
    if (j == i->addr_v4 + i->addr_v4_size) {
        struct in_addr *addr_v4 = NULL;
        // Avoids potential overflow in size calculation.
        if (i->addr_v4_size + 1 <= SIZE_MAX / sizeof (struct in_addr)) {
            addr_v4 = (struct in_addr *) realloc(i->addr_v4,
                    (i->addr_v4_size + 1) * sizeof (struct in_addr));
        }
        if (addr_v4) {
            addr_v4[i->addr_v4_size] = *addr;
            i->addr_v4 = addr_v4;
            i->addr_v4_size += 1;

            char ifname[IF_NAMESIZE];
            if_indextoname(index, ifname);
            syslog(LOG_DEBUG, "ifaddr: Added an IPv4 address on %s [%zu]",
                    ifname, i->addr_v4_size);
        } else {
            syslog(LOG_ERR, "ifaddr: Failed to reallocate an array");
        }
    }

    unlock_mutex(&if_mutex);
}

void ifaddr_remove_addr_v4(unsigned int index,
        const struct in_addr *restrict addr) {
    lock_mutex(&if_mutex);

    struct ifaddr_if *i = if_table;
    while (i != if_table + if_table_size && i->ifindex != index) {
        ++i;
    }
    if (i != if_table + if_table_size) {
        struct in_addr *j = i->addr_v4;
        while (j != i->addr_v4 + i->addr_v4_size &&
                j->s_addr != addr->s_addr) {
            ++j;
        }
        // Erases a matching address if one is found.
        if (j != i->addr_v4 + i->addr_v4_size) {
            struct in_addr *k = j++;
            while (j != i->addr_v4 + i->addr_v4_size) {
                *k++ = *j++;
            }
            --(i->addr_v4_size);

            char ifname[IF_NAMESIZE];
            if_indextoname(index, ifname);
            syslog(LOG_DEBUG, "ifaddr: Removed an IPv4 address on %s [%zu]",
                    ifname, i->addr_v4_size);

            if (ifaddr_interface_is_free(i)) {
                ifaddr_erase_interface(i);
            }
        }
    }

    unlock_mutex(&if_mutex);
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
            assume_no_error(pthread_sigmask(SIG_SETMASK, &oset, 0),
                    "restore the signal mask");

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
            if (recv_len >= 0) {
                const struct nlmsghdr *nlmsg = (struct nlmsghdr *) buf;
                assert(recv_len == recv_size);
                ifaddr_decode_nlmsg(nlmsg, recv_len);
            } else if (errno != EINTR) {
                syslog(LOG_ERR, "Failed to recv from rtnetlink: %s",
                        strerror(errno));
                return data;
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
        // Handles link-local or wider interfaces only.
        if (ifa->ifa_scope <= RT_SCOPE_LINK) {
            const struct rtattr *rta = (const struct rtattr *)
                    ((const char *) nlmsg + rta_offset);
            size_t rta_len = nlmsg->nlmsg_len - rta_offset;

            switch (ifa->ifa_family) {
                char ifname[IF_NAMESIZE];

            case AF_INET:
                ifaddr_v4_handle_rtattrs(nlmsg->nlmsg_type, ifa->ifa_index,
                        rta, rta_len);
                break;

            case AF_INET6:
                ifaddr_v6_handle_rtattrs(nlmsg->nlmsg_type, ifa->ifa_index,
                        rta, rta_len);
                break;

            default:
                if_indextoname(ifa->ifa_index, ifname);
                syslog(LOG_INFO, "Ignored unknown address family %u on %s",
                        (unsigned int) ifa->ifa_family, ifname);
                break;
            }
        }
    }
}

void ifaddr_v4_handle_rtattrs(unsigned int nlmsg_type, unsigned int index,
        const struct rtattr *restrict rta, size_t rta_size) {
    assert(nlmsg_type == RTM_NEWADDR || nlmsg_type == RTM_DELADDR);

    while (RTA_OK(rta, rta_size)) {
        if (rta->rta_type == IFA_ADDRESS &&
                rta->rta_len >= RTA_LENGTH(sizeof (struct in_addr))) {
            const struct in_addr *addr = (const struct in_addr *)
                    RTA_DATA(rta);
            switch (nlmsg_type) {
            case RTM_NEWADDR:
                ifaddr_add_addr_v4(index, addr);
                break;

            case RTM_DELADDR:
                ifaddr_remove_addr_v4(index, addr);
                break;
            }
        }

        rta = RTA_NEXT(rta, rta_size);
    }
}

void ifaddr_v6_handle_rtattrs(unsigned int nlmsg_type, unsigned int index,
        const struct rtattr *restrict rta, size_t rta_size) {
    while (RTA_OK(rta, rta_size)) {
        if (rta->rta_type == IFA_ADDRESS &&
                rta->rta_len >= RTA_LENGTH(sizeof (struct in6_addr))) {
            const struct in6_addr *addr =
                    (const struct in6_addr *) RTA_DATA(rta);
            // TODO: Add support for global addresses.
            if (IN6_IS_ADDR_LINKLOCAL(addr)) {
                switch (nlmsg_type) {
                case RTM_NEWADDR:
                    ifaddr_add_addr_v6(index, addr);
                    break;

                case RTM_DELADDR:
                    ifaddr_remove_addr_v6(index, addr);
                    break;
                }
            }
        }

        rta = RTA_NEXT(rta, rta_size);
    }
}

int ifaddr_refresh(void) {
    if (!ifaddr_initialized() || !ifaddr_started()) {
        return ENXIO;
    }

    lock_mutex(&refresh_mutex);

    int err = 0;
    if (refresh_not_in_progress) {
        lock_mutex(&if_mutex);
        // TODO: Call the change handler for each interface.
        if_table_size = 0;
        unlock_mutex(&if_mutex);

        unsigned char buf[NLMSG_LENGTH(sizeof (struct ifaddrmsg))];
        struct nlmsghdr *nlmsg = (struct nlmsghdr *) buf;
        *nlmsg = (struct nlmsghdr) {
            .nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg)),
            .nlmsg_type = RTM_GETADDR,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,
        };

        struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlmsg);
        *ifa = (struct ifaddrmsg) {
            .ifa_family = AF_UNSPEC,
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

    unlock_mutex(&refresh_mutex);

    return err;
}

int ifaddr_lookup(unsigned int ifindex, struct in6_addr *restrict addr_out) {
    if (!ifaddr_initialized() || !ifaddr_started()) {
        return ENXIO;
    }

    ifaddr_wait_for_refresh_completion();

    lock_mutex(&if_mutex);

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

    unlock_mutex(&if_mutex);

    return err;
}

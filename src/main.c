/*
 * Experimental responder of the LLMNR protocol
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

#include "llmnr.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

static void run_service(void);

struct options {
    bool foreground;
};

int main(int argc, char **argv) {
    struct options options = {
        .foreground = true,
    };

    if (options.foreground || daemon(false, false) == 0) {
        run_service();
    }
    
    return 0;
}

void run_service(void) {
    int so = llmnr_new_udp_socket();
    if (so < 0) {
        syslog(LOG_DAEMON | LOG_ERR, "Error: %m");
        syslog(LOG_DAEMON | LOG_INFO, "Exiting");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        struct sockaddr_in6 from = {};
        char packet[512];
        char control[1024];
        struct iovec iov[1] = {
            {
                .iov_base = packet,
                .iov_len = 512,
            },
        };
        struct msghdr msg = {
            .msg_name = &from,
            .msg_namelen = sizeof from,
            .msg_iov = iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = 1024,
        };
        recvmsg(so, &msg, 0);
    }   
}

/*
 * Experimental LLMNR responder daemon
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

#include "llmnr.h"
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

struct options {
    bool foreground;
};

static llmnr_responder_t responder;

int main(int argc, char **argv) {
    struct options options = {
        .foreground = true,
    };

    openlog(basename(argv[0]), LOG_PERROR, LOG_DAEMON);
    
    if (llmnr_responder_create(&responder) < 0) {
        syslog(LOG_ERR, "Could not create a responder object: %m");
        syslog(LOG_INFO, "Exiting");
        exit(EXIT_FAILURE);
    }

    if (options.foreground || daemon(false, false) == 0) {
        llmnr_responder_run(responder);
    }

    llmnr_responder_delete(responder);    
    return 0;
}

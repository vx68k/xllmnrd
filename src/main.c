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
#include <getopt.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

struct program_options {
    bool foreground;
};

static llmnr_responder_t responder;

static int parse_options(int, char *[*], struct program_options *);

int main(int argc, char *argv[static argc + 1]) {
    struct program_options options = {
        .foreground = false,
    };
    if (parse_options(argc, argv, &options) >= 0) {
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
    }

    return 0;
}

int parse_options(int argc, char *argv[static argc + 1],
        struct program_options *restrict options) {
    enum opt {
        OPT_VERSION = UCHAR_MAX + 1,
        OPT_HELP,
    };
    static const struct option longopts[] = {
        {"foreground", no_argument, 0, 'f'},
        {"help", no_argument, 0, OPT_HELP},
        {"version", no_argument, 0, OPT_VERSION},
        {0, 0, 0, 0},
    };

    bool help = false;
    bool version = false;
    int opt;
    do {
        opt = getopt_long(argc, argv, "f", longopts, 0);
        switch (opt) {
        case 'f':
            options->foreground = true;
            break;
        case OPT_HELP:
            help = true;
            break;
        case OPT_VERSION:
            version = true;
            break;
        case '?':
            return -1;
        }
    } while (opt >= 0);

    if (version) {
        printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
        return -1;
    }
    if (help) {
        // TODO: Show help.
        fputs("No help yet.\n", stderr);
        return -1;
    }
    return 0;
}

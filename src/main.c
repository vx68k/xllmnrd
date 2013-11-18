/*
 * IPv6 LLMNR responder daemon (main)
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

#include "llmnr_responder.h"
#include "ifaddr.h"
#if HAVE_SYSEXITS_H
#include <sysexits.h>
#endif
#include <getopt.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

// We just ignore 'LOG_PERROR' if it is not defined.
#ifndef LOG_PERROR
#define LOG_PERROR 0
#endif

#ifndef EX_USAGE
#define EX_USAGE 64
#endif

#ifndef _
#define _(message) (message)
#endif

#ifndef COPYRIGHT_YEARS
#define COPYRIGHT_YEARS "2013"
#endif

struct program_options {
    bool foreground;
};

/**
 * Parses command-line arguments for options.
 * If an option that causes an immediate exit is used, this function does not
 * return but terminates this program with a zero exit status.
 * If an invalid option is used, this function does not return but prints a
 * diagnostic message and terminates this program with a non-zero exit status.
 * @param __argc number of command-line arguments.
 * @param __argv pointer array of command-line arguments.
 * @param __options [out] parsed options.
 */
static void parse_arguments(int __argc, char *__argv[__argc + 1],
        struct program_options *__options);

/**
 * Shows the command help.
 * @param __name command name.
 */
static void show_help(const char *__name);

/**
 * Shows the version information.
 */
static void show_version(void);

/**
 * Do nothing on a signal.
 * @param __sig signal number.
 */
static void discard_signal(int __sig);

static void handle_signal_to_terminate(int __sig);

static volatile sig_atomic_t caught_signal;

/*
 * Sets the handler for a signal and makes a log entry if it failed.
 */
static inline int set_signal_handler(int sig, void (*handler)(int __sig),
        const sigset_t *restrict mask) {
    struct sigaction action = {
        .sa_handler = handler,
    };
    if (mask) {
        action.sa_mask = *mask;
    } else {
        sigemptyset(&action.sa_mask);
    }

    int ret = sigaction(sig, &action, 0);
    if (ret != 0) {
        syslog(LOG_ERR, "Failed to set handler for %s", strsignal(sig));
    }
    return ret;
}

int main(int argc, char *argv[argc + 1]) {
    setlocale(LC_ALL, "");

    struct program_options options = {
        .foreground = false,
    };
    parse_arguments(argc, argv, &options);

    // Sets the locale back to the default to keep logs untranslated.
    setlocale(LC_ALL, "POSIX");

    const char *program_name = basename(argv[0]);
    if (options.foreground) {
        // In foreground mode, tries to use the standard error stream as well.
        openlog(program_name, LOG_PERROR, LOG_USER);
    } else {
        // In background mode, uses the daemon facility by default.
        openlog(program_name, 0, LOG_DAEMON);
    }

    // Sets the handler for SIGUSR2 to interrupt a blocking system call.
    set_signal_handler(SIGUSR2, &discard_signal, NULL);

    int err = ifaddr_initialize(SIGUSR2);
    if (err != 0) {
        syslog(LOG_CRIT, "Failed to initialize ifaddr: %s",
                strerror(err));
        exit(EXIT_FAILURE);
    }
    atexit(&ifaddr_finalize);

    if (llmnr_responder_initialize(0) < 0) {
        syslog(LOG_ERR, "Could not create a responder object: %m");
        syslog(LOG_INFO, "Exiting");
        exit(EXIT_FAILURE);
    }

    if (options.foreground || daemon(false, false) == 0) {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);

        set_signal_handler(SIGINT, handle_signal_to_terminate, &mask);
        set_signal_handler(SIGTERM, handle_signal_to_terminate, &mask);

        ifaddr_start();
        llmnr_responder_run();
    }

    llmnr_responder_finalize();

    if (caught_signal != 0) {
        // Resets the handler to default and reraise the same signal.

        ifaddr_finalize(); // The exit functions will not be called.

        const struct sigaction default_action = {
            .sa_handler = SIG_DFL,
        };
        if (sigaction(caught_signal, &default_action, 0) == 0) {
            raise(caught_signal);
        }
    }

    return EXIT_SUCCESS;
}

void parse_arguments(int argc, char *argv[argc + 1],
        struct program_options *restrict options) {
    enum opt_char {
        OPT_VERSION = UCHAR_MAX + 1,
        OPT_HELP,
    };
    static const struct option longopts[] = {
        {"foreground", no_argument, 0, 'f'},
        {"help", no_argument, 0, OPT_HELP},
        {"version", no_argument, 0, OPT_VERSION},
        {0, 0, 0, 0},
    };

    int opt;
    do {
        opt = getopt_long(argc, argv, "f", longopts, 0);
        switch (opt) {
        case 'f':
            options->foreground = true;
            break;
        case OPT_HELP:
            show_help(argv[0]);
            exit(EXIT_SUCCESS);
        case OPT_VERSION:
            show_version();
            exit(EXIT_SUCCESS);
        case '?':
            printf(_("Try '%s --help' for more information.\n"), argv[0]);
            exit(EX_USAGE);
        }
    } while (opt >= 0);
}

void show_help(const char *restrict name) {
    printf(_("Usage: %s [OPTIONS]...\n"), name);
    printf(_("Respond to IPv6 LLMNR queries.\n"));
    putchar('\n');
    printf(_("  -f, --foreground      run in foreground\n"));
    printf(_("      --help            display this help and exit\n"));
    printf(_("      --version         output version information and exit\n"));
    putchar('\n');
    printf(_("Report bugs to %s\n"), PACKAGE_BUGREPORT);
}

void show_version(void) {
    printf(_("%s %s\n"), PACKAGE_NAME, PACKAGE_VERSION);
    printf("Copyright %s %s Kaz Nishimura\n", _("(C)"), COPYRIGHT_YEARS);
    printf(_("This is free software: you are free to change and redistribute it.\n" \
            "There is NO WARRANTY, to the extent permitted by law.\n"));
}

// We expect a warning about unused parameter 'sig' in this function.
void discard_signal(int sig) {
    // Does nothing.
}

/*
 * Handles a signal by terminating the process.
 */
void handle_signal_to_terminate(int sig) {
    if (caught_signal == 0) {
        caught_signal = sig;

        llmnr_responder_terminate();
    }
}

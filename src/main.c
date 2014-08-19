/*
 * IPv6 LLMNR responder daemon (main)
 * Copyright (C) 2013-2014 Kaz Nishimura
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "responder.h"
#include "ifaddr.h"
#include "gettext.h"
#include <getopt.h>
#if HAVE_SYSEXITS_H
#include <sysexits.h>
#endif
#include <syslog.h>
#if HAVE_LIBGEN_H
#include <libgen.h>
#endif
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#ifndef EX_USAGE
#define EX_USAGE 64
#endif
#ifndef EX_OSERR
#define EX_OSERR 71
#endif
#ifndef EX_CANTCREAT
#define EX_CANTCREAT 73
#endif

// Copyright years for printing.
#ifndef COPYRIGHT_YEARS
#define COPYRIGHT_YEARS "2013-2014"
#endif

// Marks localization strings.
#define _(s) gettext(s)
#define N_(s) gettext_noop(s)


struct program_options {
    bool foreground;
    const char *pid_file;
    const char *host_name;
};

static volatile sig_atomic_t caught_signal;

/**
 * Sets the default host name of the responder object.
 * @return 0 if succeeded, or non-zero error number.
 */
static int set_default_host_name(void);

/**
 * Makes a pid file.
 * @param __name name of the pid file.
 * @return 0 if no error is detected, or non-zero error number.
 */
static int make_pid_file(const char *__name);

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
    bindtextdomain(PACKAGE_TARNAME, LOCALEDIR);
    textdomain(PACKAGE_TARNAME);

    struct program_options options = {
        .foreground = false,
    };
    parse_arguments(argc, argv, &options);

    // Sets the locale back to the default to keep logs untranslated.
    setlocale(LC_ALL, "POSIX");

    const char *program_name = basename(argv[0]);
    int facility = LOG_DAEMON;
    if (options.foreground) {
        // For foreground operation, the 'LOG_USER' facility is used instead.
        facility = LOG_USER;
    }
    openlog(program_name, 0, facility);

    // Sets the handler for SIGUSR2 to interrupt a blocking system call.
    set_signal_handler(SIGUSR2, &discard_signal, NULL);

    int err = ifaddr_initialize(SIGUSR2);
    if (err != 0) {
        syslog(LOG_CRIT, "Failed to initialize ifaddr: %s",
                strerror(err));
        exit(EXIT_FAILURE);
    }
    atexit(&ifaddr_finalize);

    err = responder_initialize(0);
    if (err != 0) {
        syslog(LOG_ERR, "Failed to initialize responder: %s", strerror(err));
        exit(EXIT_FAILURE);
    }

    if (options.host_name) {
        syslog(LOG_NOTICE, "Setting the host name of the responder to '%s'",
                options.host_name);
        responder_set_host_name(options.host_name);
    } else {
        int err = set_default_host_name();
        if (err != 0) {
            syslog(LOG_ERR, "Failed to get the default host name");
            exit(EX_OSERR);
        }
    }

    int exit_status = EXIT_SUCCESS;
    if (options.foreground || daemon(false, false) == 0) {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);

        set_signal_handler(SIGINT, handle_signal_to_terminate, &mask);
        set_signal_handler(SIGTERM, handle_signal_to_terminate, &mask);

        if (options.pid_file) {
            int err = make_pid_file(options.pid_file);
            if (err != 0) {
                syslog(LOG_ERR, "Failed to make pid file '%s': %s",
                        options.pid_file, strerror(err));
                exit_status = EX_CANTCREAT;
            }
        }

        if (exit_status == EXIT_SUCCESS) {
            ifaddr_start();
            responder_run();

            if (options.pid_file) {
                if (unlink(options.pid_file) != 0) {
                    syslog(LOG_WARNING, "Failed to unlink pid file '%s': %s",
                            options.pid_file, strerror(errno));
                }
            }
        }
    }

    responder_finalize();

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

    return exit_status;
}

int set_default_host_name(void) {
    // Gets the maximum length of the host name.
    long host_name_max = sysconf(_SC_HOST_NAME_MAX);
    if (host_name_max < 0) {
        host_name_max = HOST_NAME_MAX;
    } else if (host_name_max > 255) {
        // Avoids allocation overflow.
        host_name_max = 255;
    }

    char host_name[host_name_max + 1];
    if (gethostname(host_name, host_name_max + 1) == 0) {
        responder_set_host_name(host_name);
        return 0;
    }

    return errno;
}

int make_pid_file(const char *restrict name) {
    FILE *f = fopen(name, "w");
    if (!f) {
        return errno;
    }

    int written = fprintf(f, "%lu\n", (long) getpid());
    if (written >= 0) {
        fclose(f);
        return 0;
    }

    int err = errno; // Any of the following functions MAY fail.
    fclose(f);
    unlink(name);

    return err;
}

void parse_arguments(int argc, char *argv[argc + 1],
        struct program_options *restrict options) {
    enum opt_char {
        OPT_VERSION = UCHAR_MAX + 1,
        OPT_HELP,
    };
    static const struct option long_options[] = {
        {"foreground", no_argument, 0, 'f'},
        {"pid-file", required_argument, 0, 'p'},
        {"name", required_argument, 0, 'n'},
        {"help", no_argument, 0, OPT_HELP},
        {"version", no_argument, 0, OPT_VERSION},
        {NULL},
    };

    int opt;
    do {
        opt = getopt_long(argc, argv, "fp:n:", long_options, 0);
        switch (opt) {
        case 'f':
            options->foreground = true;
            break;
        case 'p':
            options->pid_file = optarg;
            break;
        case 'n':
            options->host_name = optarg;
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
    printf(_("Usage: %s [OPTION]...\n"), name);
    printf(_("Respond to IPv6 LLMNR queries.\n"));
    putchar('\n');
    printf(_("\
  -f, --foreground      run in foreground\n"));
    printf(_("\
  -p, --pid-file=FILE   record the process ID in FILE\n"));
    printf(_("\
  -n, --name=NAME       set the host name of the responder to NAME\n"));
    printf(_("\
      --help            display this help and exit\n"));
    printf(_("\
      --version         output version information and exit\n"));
    putchar('\n');
    printf(_("Report bugs to <%s>.\n"), PACKAGE_BUGREPORT);
}

void show_version(void) {
    printf(_("%s %s\n"), PACKAGE_NAME, PACKAGE_VERSION);
#ifdef PACKAGE_REVISION
    printf(_("Packaged from revision %s\n"), PACKAGE_REVISION);
#endif
    printf("Copyright %s %s Kaz Nishimura\n", _("(C)"), COPYRIGHT_YEARS);
    printf(_("\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n"));
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

        responder_terminate();
    }
}

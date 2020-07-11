/*
 * IPv6 LLMNR responder daemon (main)
 * Copyright (C) 2013-2020 Kaz Nishimura
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

#include "responder.h"
#include <gettext.h>
#include <getopt.h>
#include <sysexits.h>
// Uses POSIX signals instead of ones from <csignal>.
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <atomic>
#include <vector>
#include <locale>
#include <system_error>
#include <limits>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <cstdlib>

using std::atomic;
using std::exception;
using std::fclose;
using std::fopen;
using std::fprintf;
using std::generic_category;
using std::locale;
using std::putchar;
using std::printf;
using std::system_error;
using std::runtime_error;
using std::unique_ptr;

// We just ignore 'LOG_PERROR' if it is not defined.
#ifndef LOG_PERROR
#define LOG_PERROR 0
#endif

// Copyright years for printing.
#ifndef COPYRIGHT_YEARS
#define COPYRIGHT_YEARS "2013-2020"
#endif

// Marks localization strings.
#define _(s) gettext(s)
#define N_(s) gettext_noop(s)

/**
 * Makes a pid file.
 * @param __name name of the pid file.
 * @return 0 if no error is detected, or non-zero error number.
 */
static int make_pid_file(const char *__name);

struct responder_builder
{
    bool foreground = false;
    const char *pid_file = nullptr;

    void init()
    {
        if (not(foreground)) {
            foreground = true;

            if (daemon(false, false) == -1) {
                throw system_error(errno, generic_category(),
                    "could not become a daemon");
            }

            openlog(nullptr, 0, LOG_DAEMON);
        }

        if (pid_file) {
            int err = make_pid_file(pid_file);
            if (err != 0) {
                throw system_error(err, generic_category(),
                    "could not make a pid file");
            }
        }
    }

    /**
     * Builds a responder object.
     */
    auto build() -> unique_ptr<class responder>
    {
        unique_ptr<class responder> responder {new class responder()};
        return responder;
    }
};

static unique_ptr<class responder> responder;

static atomic<int> caught_signal;

/**
 * Parses command-line arguments for options.
 * If an option that causes an immediate exit is used, this function does not
 * return but terminates this program with a zero exit status.
 * If an invalid option is used, this function does not return but prints a
 * diagnostic message and terminates this program with a non-zero exit status.
 *
 * @param argc number of command-line arguments.
 * @param argv pointer array of command-line arguments.
 * @param builder parsed options.
 */
static int parse_options(int argc, char **argv, responder_builder &builder);

/**
 * Prints the command usage.
 *
 * @param arg0 the command name
 */
static void print_usage(const char *arg0);

/**
 * Prints the version information.
 */
static void print_version();


static void handle_signal_to_terminate(int __sig);

/*
 * Sets the handler for a signal and makes a log entry if it failed.
 */
static inline int set_signal_handler(int sig, void (*handler)(int __sig),
        const sigset_t *restrict mask) {
    struct sigaction action = {};
    action.sa_handler = handler;
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

/**
 * Runs the program.
 */
int main(const int argc, char **const argv)
{
    try {
        locale::global(locale(""));
    }
    catch (runtime_error &error) {
        fprintf(stderr, "error: failed to set locale: %s\n", error.what());
    }

#if defined LOCALEDIR
    bindtextdomain(PACKAGE_TARNAME, LOCALEDIR);
#endif
    textdomain(PACKAGE_TARNAME);

    // Tries to use the standard error stream as well.
    openlog(nullptr, LOG_PERROR, LOG_USER);

    try {
        responder_builder builder {};
        parse_options(argc, argv, builder);

        builder.init();
        syslog(LOG_INFO, "%s %s started", PACKAGE_NAME, PACKAGE_VERSION);

        responder = builder.build();

        int exit_status = EXIT_SUCCESS;

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);

        set_signal_handler(SIGINT, handle_signal_to_terminate, &mask);
        set_signal_handler(SIGTERM, handle_signal_to_terminate, &mask);

        if (exit_status == EXIT_SUCCESS) {
            responder->run();

            if (builder.pid_file) {
                if (unlink(builder.pid_file) != 0) {
                    syslog(LOG_WARNING, "Failed to unlink pid file '%s': %s",
                            builder.pid_file, strerror(errno));
                }
            }
        }

        responder.reset();

        if (caught_signal != 0) {
            // Resets the handler to default and reraise the same signal.

            struct sigaction default_action = {};
            default_action.sa_handler = SIG_DFL;
            if (sigaction(caught_signal, &default_action, 0) == 0) {
                raise(caught_signal);
            }
        }

        return exit_status;
    }
    catch (const exception &e) {
        fprintf(stderr, "%s\n", e.what());
        exit(1);
    }
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

int parse_options(const int argc, char **const argv,
    responder_builder &builder)
{
    enum
    {
        VERSION = -128,
        HELP,
    };
    static const option options[] = {
        {"foreground", no_argument, 0, 'f'},
        {"pid-file", required_argument, 0, 'p'},
        {"help", no_argument, 0, HELP},
        {"version", no_argument, 0, VERSION},
        {}
    };

    int opt = -1;
    do {
        opt = getopt_long(argc, argv, "fp:", options, nullptr);
        switch (opt) {
        case 'f':
            builder.foreground = true;
            break;
        case 'p':
            builder.pid_file = optarg;
            break;
        case HELP:
            print_usage(argv[0]);
            exit(0);
        case VERSION:
            print_version();
            exit(0);
        case '?':
            fprintf(stderr, _("Try '%s --help' for more information.\n"), argv[0]);
            exit(EX_USAGE);
        }
    }
    while (opt != -1);

    return optind;
}

void print_usage(const char *const arg0)
{
    printf(_("Usage: %s [OPTION]...\n"), arg0);
    printf(_("Respond to IPv6 LLMNR queries.\n"));
    putchar('\n');
    printf("  -f, --foreground      %s\n", _("run in foreground"));
    printf("  -p, --pid-file=FILE   %s\n", _("record the process ID in FILE"));
    printf("      --help            %s\n", _("display this help and exit"));
    printf("      --version         %s\n", _("output version information and exit"));
    putchar('\n');
    printf(_("Report bugs to <%s>.\n"), PACKAGE_BUGREPORT);
}

void print_version()
{
    printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
    printf("Copyright %s %s Kaz Nishimura\n", _("(C)"), COPYRIGHT_YEARS);
    printf(_("\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n"));
}

/*
 * Handles a signal by terminating the process.
 */
void handle_signal_to_terminate(int sig)
{
    int expected = 0;
    if (caught_signal.compare_exchange_weak(expected, sig)) {
        responder->terminate();
    }
}

/* SPDX-License-Identifier: MIT */

/* kbox entry point: parse CLI arguments and boot the rootfs image. */

#include <execinfo.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "daemon.h"
#include "kbox/cli.h"
#include "kbox/image.h"

/* A crash in the daemon takes every container with it, and the only evidence
 * left behind is "Exit Code: 139" plus whatever the container happened to
 * print last. Print where it died instead of guessing from a log tail.
 */
static void crash_handler(int sig)
{
    void *frames[64];
    int n = backtrace(frames, 64);

    const char *name = sig == SIGSEGV ? "SIGSEGV"
                       : sig == SIGBUS ? "SIGBUS"
                       : sig == SIGABRT ? "SIGABRT"
                                        : "signal";
    write(STDERR_FILENO, "kbox: fatal: ", 13);
    write(STDERR_FILENO, name, strlen(name));
    write(STDERR_FILENO, " backtrace:\n", 13);
    backtrace_symbols_fd(frames, n, STDERR_FILENO);
    _exit(139);
}

int main(int argc, char *argv[])
{
    struct sigaction sa;
    struct kbox_image_args args;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

    if (argc >= 2 && strcmp(argv[1], "daemon") == 0)
        return kbox_daemon_main(argc - 1, argv + 1);

    if (kbox_parse_args(argc, argv, &args) < 0)
        return 1;

    return kbox_run_image(&args) < 0 ? 1 : 0;
}

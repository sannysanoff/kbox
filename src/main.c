/* SPDX-License-Identifier: MIT */

/* kbox entry point: parse CLI arguments and boot the rootfs image. */

#include <string.h>

#include "daemon.h"
#include "kbox/cli.h"
#include "kbox/image.h"

int main(int argc, char *argv[])
{
    struct kbox_image_args args;

    if (argc >= 2 && strcmp(argv[1], "daemon") == 0)
        return kbox_daemon_main(argc - 1, argv + 1);

    if (kbox_parse_args(argc, argv, &args) < 0)
        return 1;

    return kbox_run_image(&args) < 0 ? 1 : 0;
}

/*
 * Copyright (C) 2016  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "auditd.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <getopt.h>
#include <poll.h>
#include <signal.h>

#include <mblog/logging.h>
#include <mbutil/finally.h>

#include "external/audit_log.h"
#include "external/libaudit.h"

#define DEFAULT_LOG_FILE    "/data/misc/audit/audit.log"

namespace mb
{

static volatile bool done = false;

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
    case SIGTERM:
        done = true;
        break;
    }
}

static void auditd_usage(FILE *stream)
{
    fprintf(stream,
            "Usage: auditd [-f <file>] [-k]\n\n"
            "Options:\n"
            "  -f, --file <file>\n"
            "                   Output file for audit log\n"
            "                   (Default: /data/misc/audit/audit.log)\n"
            "  -k, --dmesg      Search for audit events from dmesg on startup\n"
            "  -h, --help       Display this help message\n");
}

int auditd_main(int argc, char *argv[])
{
    int opt;

    static const char *short_options = "f:kh";
    static struct option long_options[] = {
        {"file",      required_argument, 0, 'f'},
        {"dmesg",     no_argument,       0, 'k'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int long_index = 0;

    const char *output_file = DEFAULT_LOG_FILE;
    bool check_kernel_log = false;

    while ((opt = getopt_long(argc, argv, short_options,
            long_options, &long_index)) != -1) {
        switch (opt) {
        case 'f':
            output_file = optarg;
            break;
        case 'k':
            check_kernel_log = true;
            break;
        case 'h':
            auditd_usage(stdout);
            return EXIT_SUCCESS;
        default:
            auditd_usage(stderr);
            return EXIT_FAILURE;
        }
    }

    // There should be no other arguments
    if (argc - optind != 0) {
        auditd_usage(stderr);
        return EXIT_FAILURE;
    }

    // Set up signal handler to properly close the socket
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, nullptr) < 0) {
        LOGE("Failed on set signal handler: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    int fd = audit_open();
    if (fd < 0) {
        LOGE("Failed to open audit socket: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    auto close_fd = util::finally([&]{
        audit_setup(fd, 0);
        audit_close(fd);
    });

    audit_log *al = audit_log_open(output_file);
    if (!al) {
        LOGE("%s: Failed to open log file", output_file);
        return EXIT_FAILURE;
    }

    auto close_log = util::finally([&]{
        audit_log_close(al);
    });

    if (audit_setup(fd, getpid()) < 0) {
        LOGD("Failed to register for audit events: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    if (check_kernel_log) {
        audit_log_put_kmsg(al);
    }

    struct pollfd pfds;
    pfds.fd = fd;
    pfds.events = POLLIN;

    while (!done) {
        int ret = poll(&pfds, 1, -1);
        if (ret == 0) {
            continue;
        } else if (ret < 0) {
            if (errno != EINTR) {
                LOGW("Failed to poll audit socket: %s", strerror(errno));
            }
            continue;
        }

        struct audit_message msg;

        if (audit_get_reply(fd, &msg, GET_REPLY_BLOCKING, 0) < 0) {
            LOGE("Failed to get audit reply: %s", strerror(errno));
            continue;
        }

        audit_log_write(al, "type=%d msg=%.*s\n",
                        msg.nlh.nlmsg_type, msg.nlh.nlmsg_len, msg.data);
    }

    return EXIT_SUCCESS;
}

}

/*
    SSSD

    Tests -- a simple test process that echoes input back

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <popt.h>

#include "util/util.h"
#include "util/child_common.h"

int main(int argc, const char *argv[])
{
    int opt;
    int debug_fd = -1;
    char *opt_logger = NULL;
    poptContext pc;
    ssize_t len;
    ssize_t written;
    errno_t ret;
    uint8_t buf[IN_BUF_SIZE];
    const char *action = NULL;
    const char *guitar;
    const char *drums;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0,
         _("Debug level"), NULL},
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0,
         _("Add debug timestamps"), NULL},
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0,
         _("Show timestamps with microseconds"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        {"debug-to-stderr", 0, POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN, &debug_to_stderr, 0, \
         _("Send the debug output to stderr directly."), NULL },
        SSSD_LOGGER_OPTS
        {"guitar", 0, POPT_ARG_STRING, &guitar, 0, _("Who plays guitar"), NULL },
        {"drums", 0, POPT_ARG_STRING, &drums, 0, _("Who plays drums"), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            poptFreeContext(pc);
            _exit(1);
        }
    }
    poptFreeContext(pc);

    sss_set_logger(opt_logger);

    action = getenv("TEST_CHILD_ACTION");
    if (action) {
        if (strcasecmp(action, "check_extra_args") == 0) {
            if (!(strcmp(guitar, "george") == 0 \
                        && strcmp(drums, "ringo") == 0)) {
                DEBUG(SSSDBG_CRIT_FAILURE, "This band sounds weird\n");
                _exit(1);
            }
        } else if (strcasecmp(action, "check_only_extra_args") == 0) {
            if (debug_timestamps == 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "debug_timestamp was passed when only extra args "
                      "should have been\n");
                _exit(1);
            }

            if (!(strcmp(guitar, "george") == 0 \
                        && strcmp(drums, "ringo") == 0)) {
                DEBUG(SSSDBG_CRIT_FAILURE, "This band sounds weird\n");
                _exit(1);
            }
        } else if (strcasecmp(action, "check_only_extra_args_neg") == 0) {
            if (debug_timestamps != 1) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "debug_timestamp was not passed as expected\n");
                _exit(1);
            }
        } else if (strcasecmp(action, "echo") == 0) {
            errno = 0;
            len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
            if (len == -1) {
                ret = errno;
                DEBUG(SSSDBG_CRIT_FAILURE, "read failed [%d][%s].\n", ret, strerror(ret));
                _exit(1);
            }
            close(STDIN_FILENO);

            errno = 0;
            written = sss_atomic_write_s(3, buf, len);
            if (written == -1) {
                ret = errno;
                DEBUG(SSSDBG_CRIT_FAILURE, "write failed [%d][%s].\n", ret,
                            strerror(ret));
                _exit(1);
            }
            close(STDOUT_FILENO);

            if (written != len) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Expected to write %zu bytes, wrote %zu\n",
                      len, written);
                _exit(1);
            }
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "test_child completed successfully\n");
    _exit(0);
}

/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Server instantiation

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
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <popt.h>
#include "util/util.h"
#include "util/strtonum.h"
#include "tests/cmocka/common_mock.h"

static void wait_for_fg_server(pid_t pid)
{
    pid_t wpid;
    int status;

    assert_int_not_equal(pid, -1);

    wpid = waitpid(pid, &status, 0);
    assert_int_equal(wpid, pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
}

static void wait_for_bg_server(const char *pidfile)
{
    int fd;
    uint32_t tmp;
    char buf[16];
    pid_t pid;
    int ret;
    int count;

    count = 0;
    do {
        struct stat sb;

        count++;
        if (count > 200) {
            fail();
            break;
        }

        ret = stat(pidfile, &sb);
        usleep(50000);
    } while (ret != 0);

    /* read the pidfile */
    fd = open(pidfile, O_RDONLY);
    assert_false(fd < 0);

    ret = read(fd, buf, sizeof(buf));
    close(fd);
    assert_false(ret <= 0);

    buf[sizeof(buf) - 1] = '\0';

    errno = 0;
    tmp = strtouint32(buf, NULL, 10);
    assert_int_not_equal(tmp, 0);
    assert_int_equal(errno, 0);

    pid = (pid_t) (tmp);

    /* Make sure the daemon goes away! */
    ret = kill(pid, SIGTERM);
    fprintf(stderr, "killing %u\n", pid);
    assert_true(ret == 0);

    unlink(pidfile);
}

void test_run_as_root_fg(void **state)
{
    int ret;
    struct main_context *main_ctx;
    pid_t pid;

    /* Must root as root, real or fake */
    assert_int_equal(geteuid(), 0);

    pid = fork();
    if (pid == 0) {
        ret = server_setup(__FUNCTION__, false, 0, CONFDB_FILE,
                           __FUNCTION__, &main_ctx, true);
        assert_int_equal(ret, 0);
        exit(0);
    }
    wait_for_fg_server(pid);
}

void test_run_as_root_daemon(void **state)
{
    int ret;
    struct main_context *main_ctx;
    pid_t pid;
    char *pidfile;

    /* Must root as root, real or fake */
    assert_int_equal(geteuid(), 0);

    pidfile = talloc_asprintf(NULL, "%s/%s.pid", TEST_PID_PATH, __FUNCTION__);

    /* Make sure there are no leftovers */
    unlink(pidfile);

    pid = fork();
    if (pid == 0) {
        ret = server_setup(__FUNCTION__, false, FLAGS_PID_FILE,
                           CONFDB_FILE, __FUNCTION__, &main_ctx, true);
        assert_int_equal(ret, 0);

        server_loop(main_ctx);
        exit(0);
    }

    wait_for_bg_server(pidfile);
    talloc_free(pidfile);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_run_as_root_fg),
        cmocka_unit_test(test_run_as_root_daemon),
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
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TEST_DB_PATH, CONFDB_FILE, NULL);
    test_dom_suite_setup(TEST_DB_PATH);

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0) {
        test_dom_suite_cleanup(TEST_DB_PATH, CONFDB_FILE, NULL);
    }

    return rv;
}

/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: User switching

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

/* Yes, a .c file. We need to call static functions during the test */
#include "../../../src/monitor/become_user.c"

#include <popt.h>
#include "util/util.h"
#include "tests/cmocka/common_mock.h"

void test_become_user(void **state)
{
    struct passwd *sssd;
    errno_t ret;
    pid_t pid, wpid;
    int status;

    /* Must root as root, real or fake */
    assert_int_equal(geteuid(), 0);

    sssd = getpwnam("sssd");
    assert_non_null(sssd);

    pid = fork();
    if (pid == 0) {
        /* Change the UID in a child */
        ret = become_user(sssd->pw_uid, sssd->pw_gid, false);
        assert_int_equal(ret, EOK);

        /* Make sure we have the requested UID and GID now and there
         * are no supplementary groups
         */
        assert_int_equal(geteuid(), sssd->pw_uid);
        assert_int_equal(getegid(), sssd->pw_gid);
        assert_int_equal(getuid(), sssd->pw_uid);
        assert_int_equal(getgid(), sssd->pw_gid);

        /* Another become_user is a no-op */
        ret = become_user(sssd->pw_uid, sssd->pw_gid, false);
        assert_int_equal(ret, EOK);

        assert_int_equal(getgroups(0, NULL), 0);
        exit(0);
    }

    assert_int_not_equal(pid, -1);

    wpid = waitpid(pid, &status, 0);
    assert_int_equal(wpid, pid);
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), 0);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_become_user),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}

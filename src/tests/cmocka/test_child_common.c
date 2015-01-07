/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Child handlers

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include "util/child_common.h"
#include "tests/cmocka/common_mock.h"

#define TEST_BIN    "dummy-child"
#define ECHO_STR    "Hello child"

struct child_test_ctx {
    int pipefd_to_child[2];
    int pipefd_from_child[2];

    struct sss_test_ctx *test_ctx;
};

void child_test_setup(void **state)
{
    struct child_test_ctx *child_tctx;
    errno_t ret;

    check_leaks_push(global_talloc_context);
    child_tctx = talloc(global_talloc_context, struct child_test_ctx);
    assert_non_null(child_tctx);

    child_tctx->test_ctx = create_ev_test_ctx(child_tctx);
    assert_non_null(child_tctx->test_ctx);

    ret = pipe(child_tctx->pipefd_from_child);
    assert_int_not_equal(ret, -1);
    DEBUG(SSSDBG_TRACE_LIBS, "from_child: %d:%d\n",
                             child_tctx->pipefd_from_child[0],
                             child_tctx->pipefd_from_child[1]);

    ret = pipe(child_tctx->pipefd_to_child);
    assert_int_not_equal(ret, -1);
    DEBUG(SSSDBG_TRACE_LIBS, "to_child: %d:%d\n",
                             child_tctx->pipefd_to_child[0],
                             child_tctx->pipefd_to_child[1]);

    *state = child_tctx;
}

void child_test_teardown(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);

    talloc_free(child_tctx);
    check_leaks_pop(global_talloc_context);
}

/* Just make sure the exec works. The child does nothing but exits */
void test_exec_child(void **state)
{
    errno_t ret;
    pid_t child_pid;
    int status;
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);

    child_pid = fork();
    assert_int_not_equal(child_pid, -1);
    if (child_pid == 0) {
        ret = exec_child(child_tctx,
                         child_tctx->pipefd_to_child,
                         child_tctx->pipefd_from_child,
                         CHILD_DIR"/"TEST_BIN, 2);
        assert_int_equal(ret, EOK);
    } else {
            do {
                errno = 0;
                ret = waitpid(child_pid, &status, 0);
            } while (ret == -1 && errno == EINTR);

            if (ret > 0) {
                ret = EIO;
                if (WIFEXITED(status)) {
                    ret = WEXITSTATUS(status);
                    assert_int_equal(ret, 0);
                }
            } else {
                DEBUG(SSSDBG_FUNC_DATA,
                    "Failed to wait for children %d\n", child_pid);
                ret = EIO;
            }
    }
}

/* Just make sure the exec works. The child does nothing but exits */
void test_exec_child_extra_args(void **state)
{
    errno_t ret;
    pid_t child_pid;
    int status;
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    const char *extra_args[] = { "--guitar=george",
                                 "--drums=ringo",
                                 NULL };

    setenv("TEST_CHILD_ACTION", "check_extra_args", 1);

    child_pid = fork();
    assert_int_not_equal(child_pid, -1);
    if (child_pid == 0) {
        ret = exec_child_ex(child_tctx,
                            child_tctx->pipefd_to_child,
                            child_tctx->pipefd_from_child,
                            CHILD_DIR"/"TEST_BIN, 2, extra_args,
                            STDIN_FILENO, STDOUT_FILENO);
        assert_int_equal(ret, EOK);
    } else {
            do {
                errno = 0;
                ret = waitpid(child_pid, &status, 0);
            } while (ret == -1 && errno == EINTR);

            if (ret > 0) {
                ret = EIO;
                if (WIFEXITED(status)) {
                    ret = WEXITSTATUS(status);
                    assert_int_equal(ret, 0);
                }
            } else {
                DEBUG(SSSDBG_FUNC_DATA,
                    "Failed to wait for children %d\n", child_pid);
                ret = EIO;
            }
    }
}

int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_exec_child,
                                 child_test_setup,
                                 child_test_teardown),
        unit_test_setup_teardown(test_exec_child_extra_args,
                                 child_test_setup,
                                 child_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    rv = run_tests(tests);
    return rv;
}

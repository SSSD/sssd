/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: User utilities

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
#include <fcntl.h>
#include <talloc.h>

#include <popt.h>
#include "util/util.h"
#include "responder/common/responder.h"
#include "tests/cmocka/common_mock.h"

/* Just to satisfy dependencies */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return responder_test_cli_protocol_version;
}

void test_uid_csv_to_uid_list(void **state)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    size_t count;
    uid_t *list;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);

    check_leaks_push(tmp_ctx);

    ret = csv_string_to_uid_array(tmp_ctx, "1, 2, 3", &count, &list);
    assert_int_equal(ret, EOK);
    assert_int_equal(count, 3);
    assert_int_equal(list[0], 1);
    assert_int_equal(list[1], 2);
    assert_int_equal(list[2], 3);

    talloc_free(list);
    assert_true(check_leaks_pop(tmp_ctx));
    talloc_free(tmp_ctx);
}

void test_name_csv_to_uid_list(void **state)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    size_t count;
    uid_t *list;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);

    check_leaks_push(tmp_ctx);

    ret = csv_string_to_uid_array(tmp_ctx, "sssd, foobar", &count, &list);
    assert_int_equal(ret, EOK);
    assert_int_equal(count, 2);
    assert_int_equal(list[0], 123);
    assert_int_equal(list[1], 10001);

    talloc_free(list);
    assert_true(check_leaks_pop(tmp_ctx));
    talloc_free(tmp_ctx);
}

void test_csv_to_uid_list_neg(void **state)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    size_t count;
    uid_t *list = NULL;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);

    check_leaks_push(tmp_ctx);

    ret = csv_string_to_uid_array(tmp_ctx, "nosuchuser", &count, &list);
    assert_int_not_equal(ret, EOK);

    assert_true(check_leaks_pop(tmp_ctx));
    talloc_free(tmp_ctx);
}

struct create_pipe_ctx {
    int fd;
    const char *sock_name;
};

static int test_create_pipe_fd_setup(void **state)
{
    struct create_pipe_ctx *ctx;

    ctx = talloc(global_talloc_context, struct create_pipe_ctx);
    assert_non_null(ctx);
    ctx->fd = -1;

    *state = ctx;
    return 0;
}

void check_sock_properties(struct create_pipe_ctx *ctx, mode_t mode)
{
    int ret;
    int optval;
    socklen_t optlen;
    struct stat sbuf;

    /* Check existence of the file and the permissions */
    ret = stat(ctx->sock_name, &sbuf);
    assert_int_equal(ret, 0);
    assert_true(S_ISSOCK(sbuf.st_mode));
    assert_true((sbuf.st_mode & ~S_IFMT) == mode);

    /* Check it's a UNIX socket */
    optlen = sizeof(optval);
    ret = getsockopt(ctx->fd, SOL_SOCKET, SO_DOMAIN, &optval, &optlen);
    assert_int_equal(ret, 0);
    assert_int_equal(optval, AF_UNIX);

    optlen = sizeof(optval);
    ret = getsockopt(ctx->fd, SOL_SOCKET, SO_TYPE, &optval, &optlen);
    assert_int_equal(ret, 0);
    assert_int_equal(optval, SOCK_STREAM);

    /* Make sure this is a listening socket */
    optlen = sizeof(optval);
    ret = getsockopt(ctx->fd, SOL_SOCKET, SO_ACCEPTCONN, &optval, &optlen);
    assert_int_equal(ret, 0);
    /* getsockopt(SO_ACCEPTCONN) returns 1 on Linux,
     * but SO_ACCEPTCONN on FreeBSD
     */
    assert_int_not_equal(optval, 0);

    /* Check the right protocol */
    optlen = sizeof(optval);
    ret = getsockopt(ctx->fd, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen);
    assert_int_equal(ret, 0);
    assert_int_equal(optval, 0);

}

void test_create_pipe_fd(void **state)
{
    int ret;
    struct create_pipe_ctx *ctx;

    ctx = talloc_get_type(*state, struct create_pipe_ctx);

    ctx->sock_name = __FUNCTION__;

    ret = create_pipe_fd(ctx->sock_name, &ctx->fd, 0111);
    assert_int_equal(ret, EOK);
    assert_int_not_equal(ctx->fd, -1);
    check_sock_properties(ctx, 0666);

    /* Make sure we can overwrite an existing socket */
    ret = create_pipe_fd(ctx->sock_name, &ctx->fd, 0000);
    assert_int_equal(ret, EOK);
    assert_int_not_equal(ctx->fd, -1);
    check_sock_properties(ctx, 0777);
}

static int test_create_pipe_fd_teardown(void **state)
{
    struct create_pipe_ctx *ctx;

    ctx = talloc_get_type(*state, struct create_pipe_ctx);

    if (ctx->fd != -1) {
        unlink(ctx->sock_name);
        close(ctx->fd);
    }
    return 0;
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
        cmocka_unit_test(test_uid_csv_to_uid_list),
        cmocka_unit_test(test_name_csv_to_uid_list),
        cmocka_unit_test(test_csv_to_uid_list_neg),
        cmocka_unit_test_setup_teardown(test_create_pipe_fd,
                                        test_create_pipe_fd_setup,
                                        test_create_pipe_fd_teardown)
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

    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}

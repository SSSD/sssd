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
#define ECHO_LARGE_STR      "Lorem ipsum dolor sit amet consectetur adipiscing elit, urna consequat felis vehicula class ultricies mollis dictumst, aenean non a in donec nulla. Phasellus ante pellentesque erat cum risus consequat imperdiet aliquam, integer placerat et turpis mi eros nec lobortis taciti, vehicula nisl litora tellus ligula porttitor metus. Vivamus integer non suscipit taciti mus etiam at primis tempor sagittis sit, euismod libero facilisi aptent elementum felis blandit cursus gravida sociis erat ante, eleifend lectus nullam dapibus netus feugiat curae curabitur est ad. Massa curae fringilla porttitor quam sollicitudin iaculis aptent leo ligula euismod dictumst, orci penatibus mauris eros etiam praesent erat volutpat posuere hac. Metus fringilla nec ullamcorper odio aliquam lacinia conubia mauris tempor, etiam ultricies proin quisque lectus sociis id tristique, integer phasellus taciti pretium adipiscing tortor sagittis ligula. Mollis pretium lorem primis senectus habitasse lectus scelerisque donec, ultricies tortor suspendisse adipiscing fusce morbi volutpat pellentesque, consectetur mi risus molestie curae malesuada cum. Dignissim lacus convallis massa mauris enim ad mattis magnis senectus montes, mollis taciti phasellus accumsan bibendum semper blandit suspendisse faucibus nibh est, metus lobortis morbi cras magna vivamus per risus fermentum. Dapibus imperdiet praesent magnis ridiculus congue gravida curabitur dictum sagittis, enim et magna sit inceptos sodales parturient pharetra mollis, aenean vel nostra tellus commodo pretium sapien sociosqu."


static int destructor_called;

struct child_test_ctx {
    int pipefd_to_child[2];
    int pipefd_from_child[2];

    struct sss_test_ctx *test_ctx;

    int save_debug_timestamps;
};

static int child_test_setup(void **state)
{
    struct child_test_ctx *child_tctx;
    errno_t ret;

    assert_true(leak_check_setup());

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
    return 0;
}

static int child_test_teardown(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);

    talloc_free(child_tctx);

    assert_true(leak_check_teardown());
    return 0;
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
        exec_child(child_tctx,
                   child_tctx->pipefd_to_child,
                   child_tctx->pipefd_from_child,
                   CHILD_DIR"/"TEST_BIN, NULL);
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

static int only_extra_args_setup(void **state)
{
    struct child_test_ctx *child_tctx;
    errno_t ret;

    ret = child_test_setup((void **) &child_tctx);
    if (ret != 0) {
        return ret;
    }

    child_tctx->save_debug_timestamps = debug_timestamps;
    *state = child_tctx;

    return 0;
}

static int only_extra_args_teardown(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    errno_t ret;

    debug_timestamps = child_tctx->save_debug_timestamps;
    ret = child_test_teardown((void **) &child_tctx);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static void extra_args_test(struct child_test_ctx *child_tctx,
                            bool extra_args_only)
{
    pid_t child_pid;
    errno_t ret;
    int status;

    const char *extra_args[] = { "--guitar=george",
                                 "--drums=ringo",
                                 NULL };

    child_pid = fork();
    assert_int_not_equal(child_pid, -1);
    if (child_pid == 0) {
        debug_timestamps = SSSDBG_TIMESTAMP_ENABLED;

        exec_child_ex(child_tctx,
                      child_tctx->pipefd_to_child,
                      child_tctx->pipefd_from_child,
                      CHILD_DIR"/"TEST_BIN, NULL, extra_args,
                      extra_args_only,
                      STDIN_FILENO, STDOUT_FILENO);
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

/* Make sure extra arguments are passed correctly */
void test_exec_child_extra_args(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    setenv("TEST_CHILD_ACTION", "check_extra_args", 1);
    extra_args_test(child_tctx, false);
}

/* Make sure extra arguments are passed correctly */
void test_exec_child_only_extra_args(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    setenv("TEST_CHILD_ACTION", "check_only_extra_args", 1);
    extra_args_test(child_tctx, true);
}

void test_exec_child_only_extra_args_neg(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    setenv("TEST_CHILD_ACTION", "check_only_extra_args_neg", 1);
    extra_args_test(child_tctx, false);
}

struct tevent_req *echo_child_write_send(TALLOC_CTX *mem_ctx,
                                         struct child_test_ctx *child_tctx,
                                         struct child_io_fds *io_fds,
                                         const char *input,
                                         bool safe);
static void echo_child_write_done(struct tevent_req *subreq);
static void echo_child_read_done(struct tevent_req *subreq);

int __real_child_io_destructor(void *ptr);

int __wrap_child_io_destructor(void *ptr)
{
    destructor_called = 1;
    return __real_child_io_destructor(ptr);
}

/* Test that writing to the pipes works as expected */
void test_exec_child_io_destruct(void **state)
{
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    struct child_io_fds *io_fds;

    io_fds = talloc(child_tctx, struct child_io_fds);
    io_fds->read_from_child_fd = -1;
    io_fds->write_to_child_fd = -1;
    assert_non_null(io_fds);
    talloc_set_destructor((void *) io_fds, child_io_destructor);

    io_fds->read_from_child_fd = child_tctx->pipefd_from_child[0];
    io_fds->write_to_child_fd = child_tctx->pipefd_to_child[1];

    destructor_called = 0;
    talloc_free(io_fds);
    assert_int_equal(destructor_called, 1);

    errno = 0;
    close(child_tctx->pipefd_from_child[0]);
    assert_int_equal(errno, EBADF);

    errno = 0;
    close(child_tctx->pipefd_from_child[1]);
    assert_int_equal(errno, 0);

    errno = 0;
    close(child_tctx->pipefd_to_child[0]);
    assert_int_equal(errno, 0);

    errno = 0;
    close(child_tctx->pipefd_to_child[1]);
    assert_int_equal(errno, EBADF);
}

void test_child_cb(int child_status,
                   struct tevent_signal *sige,
                   void *pvt);

/* Test that writing to the pipes works as expected */
void test_exec_child_handler(void **state)
{
    errno_t ret;
    pid_t child_pid;
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    struct sss_child_ctx_old *child_old_ctx;

    ret = unsetenv("TEST_CHILD_ACTION");
    assert_int_equal(ret, 0);

    child_pid = fork();
    assert_int_not_equal(child_pid, -1);
    if (child_pid == 0) {
        exec_child(child_tctx,
                   child_tctx->pipefd_to_child,
                   child_tctx->pipefd_from_child,
                   CHILD_DIR"/"TEST_BIN, NULL);
    }

    ret = child_handler_setup(child_tctx->test_ctx->ev, child_pid,
                              test_child_cb, child_tctx, &child_old_ctx);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(child_tctx->test_ctx);
    assert_int_equal(ret, EOK);
    assert_int_equal(child_tctx->test_ctx->error, 0);
}

void test_child_cb(int child_status,
                   struct tevent_signal *sige,
                   void *pvt)
{
    struct child_test_ctx *child_ctx = talloc_get_type(pvt, struct child_test_ctx);

    child_ctx->test_ctx->error = EIO;
    if (WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0) {
        child_ctx->test_ctx->error = 0;
    }

    child_ctx->test_ctx->done = true;
}

void test_exec_child_echo(void **state,
                          const char *msg,
                          bool safe)
{

    errno_t ret;
    pid_t child_pid;
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    struct tevent_req *req;
    struct child_io_fds *io_fds;

    setenv("TEST_CHILD_ACTION", "echo", 1);

    io_fds = talloc(child_tctx, struct child_io_fds);
    assert_non_null(io_fds);
    io_fds->read_from_child_fd = -1;
    io_fds->write_to_child_fd = -1;
    talloc_set_destructor((void *) io_fds, child_io_destructor);

    child_pid = fork();
    assert_int_not_equal(child_pid, -1);
    if (child_pid == 0) {
        exec_child_ex(child_tctx,
                      child_tctx->pipefd_to_child,
                      child_tctx->pipefd_from_child,
                      CHILD_DIR"/"TEST_BIN, NULL, NULL, false,
                      STDIN_FILENO, 3);
    }

    DEBUG(SSSDBG_FUNC_DATA, "Forked into %d\n", child_pid);

    io_fds->read_from_child_fd = child_tctx->pipefd_from_child[0];
    close(child_tctx->pipefd_from_child[1]);
    io_fds->write_to_child_fd = child_tctx->pipefd_to_child[1];
    close(child_tctx->pipefd_to_child[0]);

    sss_fd_nonblocking(io_fds->write_to_child_fd);
    sss_fd_nonblocking(io_fds->read_from_child_fd);

    ret = child_handler_setup(child_tctx->test_ctx->ev, child_pid,
                              NULL, NULL, NULL);
    assert_int_equal(ret, EOK);

    req = echo_child_write_send(child_tctx, child_tctx, io_fds, msg, safe);
    assert_non_null(req);

    ret = test_ev_loop(child_tctx->test_ctx);
    talloc_free(io_fds);
    assert_int_equal(ret, EOK);
}

/* Test that writing a small message to the pipes works as expected */
void test_exec_child_echo_small(void **state)
{
    test_exec_child_echo(state, ECHO_STR, false);
}

void test_exec_child_echo_small_safe(void **state)
{
    test_exec_child_echo(state, ECHO_STR, true);
}

/* Test that writing a large message to the pipes works as expected,
 * test will still fail if message exceeds IN_BUF_SIZE */
void test_exec_child_echo_large(void **state)
{
    test_exec_child_echo(state, ECHO_LARGE_STR, false);
}

void test_exec_child_echo_large_safe(void **state)
{
    test_exec_child_echo(state, ECHO_LARGE_STR, true);
}

struct test_exec_echo_state {
    struct child_io_fds *io_fds;
    struct io_buffer buf;
    struct child_test_ctx *child_test_ctx;
    bool safe;
};

struct tevent_req *echo_child_write_send(TALLOC_CTX *mem_ctx,
                                         struct child_test_ctx *child_tctx,
                                         struct child_io_fds *io_fds,
                                         const char *input,
                                         bool safe)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct test_exec_echo_state *echo_state;

    req = tevent_req_create(mem_ctx, &echo_state, struct test_exec_echo_state);
    assert_non_null(req);

    echo_state->child_test_ctx = child_tctx;

    echo_state->buf.data = (unsigned char *) talloc_strdup(echo_state, input);
    assert_non_null(echo_state->buf.data);
    echo_state->buf.size = strlen(input) + 1;
    echo_state->io_fds = io_fds;
    echo_state->safe = safe;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Writing..\n");
    if (echo_state->safe) {
        subreq = write_pipe_safe_send(child_tctx, child_tctx->test_ctx->ev,
                                      echo_state->buf.data, echo_state->buf.size,
                                      echo_state->io_fds->write_to_child_fd);
    } else {
        subreq = write_pipe_send(child_tctx, child_tctx->test_ctx->ev,
                                 echo_state->buf.data, echo_state->buf.size,
                                 echo_state->io_fds->write_to_child_fd);
    }
    assert_non_null(subreq);
    tevent_req_set_callback(subreq, echo_child_write_done, req);

    return req;
}

static void echo_child_write_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct test_exec_echo_state *echo_state;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    echo_state = tevent_req_data(req, struct test_exec_echo_state);

    if (echo_state->safe) {
        ret = write_pipe_safe_recv(subreq);
    } else {
        ret = write_pipe_recv(subreq);
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Writing OK\n");
    talloc_zfree(subreq);
    assert_int_equal(ret, EOK);

    close(echo_state->io_fds->write_to_child_fd);
    echo_state->io_fds->write_to_child_fd = -1;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Reading..\n");
    if (echo_state->safe) {
        subreq = read_pipe_safe_send(echo_state,
                                echo_state->child_test_ctx->test_ctx->ev,
                                echo_state->io_fds->read_from_child_fd);
    } else {
        subreq = read_pipe_send(echo_state,
                                echo_state->child_test_ctx->test_ctx->ev,
                                echo_state->io_fds->read_from_child_fd);
    }

    assert_non_null(subreq);
    tevent_req_set_callback(subreq, echo_child_read_done, req);
}

static void echo_child_read_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct test_exec_echo_state *echo_state;
    errno_t ret;
    ssize_t len;
    uint8_t *buf;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    echo_state = tevent_req_data(req, struct test_exec_echo_state);

    if (echo_state->safe) {
        ret = read_pipe_safe_recv(subreq, echo_state, &buf, &len);
    } else {
        ret = read_pipe_recv(subreq, echo_state, &buf, &len);
    }

    talloc_zfree(subreq);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Reading OK\n");
    assert_int_equal(ret, EOK);

    close(echo_state->io_fds->read_from_child_fd);
    echo_state->io_fds->read_from_child_fd = -1;

    assert_string_equal((char *)buf, (char *)echo_state->buf.data);
    echo_state->child_test_ctx->test_ctx->done = true;
}

void sss_child_cb(int pid, int wait_status, void *pvt);

/* Just make sure the exec works. The child does nothing but exits */
void test_sss_child(void **state)
{
    errno_t ret;
    pid_t child_pid;
    struct child_test_ctx *child_tctx = talloc_get_type(*state,
                                                        struct child_test_ctx);
    struct sss_sigchild_ctx *sc_ctx;
    struct sss_child_ctx *sss_child;

    ret = unsetenv("TEST_CHILD_ACTION");
    assert_int_equal(ret, 0);

    ret = sss_sigchld_init(child_tctx, child_tctx->test_ctx->ev, &sc_ctx);
    assert_int_equal(ret, EOK);

    child_pid = fork();
    assert_int_not_equal(child_pid, -1);
    if (child_pid == 0) {
        exec_child(child_tctx,
                   child_tctx->pipefd_to_child,
                   child_tctx->pipefd_from_child,
                   CHILD_DIR"/"TEST_BIN, NULL);
    }

    ret = sss_child_register(child_tctx, sc_ctx,
                             child_pid,
                             sss_child_cb,
                             child_tctx, &sss_child);
    assert_int_equal(ret, EOK);

    ret = test_ev_loop(child_tctx->test_ctx);
    assert_int_equal(ret, EOK);
    assert_int_equal(child_tctx->test_ctx->error, 0);
}

void sss_child_cb(int pid, int wait_status, void *pvt)
{
    struct child_test_ctx *child_ctx = talloc_get_type(pvt, struct child_test_ctx);

    child_ctx->test_ctx->error = EIO;
    if (WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 0) {
        child_ctx->test_ctx->error = 0;
    }

    child_ctx->test_ctx->done = true;
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

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_exec_child,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_extra_args,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_io_destruct,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_handler,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_echo_small,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_echo_large,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_echo_small_safe,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_echo_large_safe,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_sss_child,
                                        child_test_setup,
                                        child_test_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_only_extra_args,
                                        only_extra_args_setup,
                                        only_extra_args_teardown),
        cmocka_unit_test_setup_teardown(test_exec_child_only_extra_args_neg,
                                        only_extra_args_setup,
                                        only_extra_args_teardown),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    return rv;
}

/*
    Copyright (C) 2016 Red Hat

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

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <talloc.h>
#include <popt.h>

#include "limits.h"
#include "shared/io.h"
#include "util/inotify.h"
#include "util/util.h"
#include "tests/common.h"

struct inotify_test_ctx {
    char *filename;
    char *dirname;

    int ncb;
    int threshold;
    /* if the cb receives flags not in this set, test fails */
    uint32_t exp_flags;

    struct sss_test_ctx *tctx;
    struct tevent_timer *fail_te;
};

static void test_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t,
                         void *ptr)
{
    DEBUG(SSSDBG_FATAL_FAILURE, "The test timed out!\n");
    talloc_free(te);
    fail();
}

static struct inotify_test_ctx *common_setup(TALLOC_CTX *mem_ctx)
{
    struct inotify_test_ctx *ctx;
    struct timeval tv;

    ctx = talloc_zero(mem_ctx, struct inotify_test_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->tctx = create_ev_test_ctx(ctx);
    if (ctx->tctx == NULL) {
        talloc_free(ctx);
        return NULL;
    }

    gettimeofday(&tv, NULL);
    tv.tv_sec += 5;
    ctx->fail_te = tevent_add_timer(ctx->tctx->ev, ctx,
                                    tv, test_timeout, ctx);
    if (ctx->fail_te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue fallback timer!\n");
        talloc_free(ctx);
        return NULL;
    }

    return ctx;
}

static int inotify_test_setup(void **state)
{
    struct inotify_test_ctx *ctx;
    int fd;

    ctx = common_setup(NULL);
    if (ctx == NULL) {
        return 1;
    }

    ctx->filename = talloc_strdup(ctx, "test_inotify.XXXXXX");
    if (ctx->filename == NULL) {
        talloc_free(ctx);
        return 1;
    }

    fd = mkstemp(ctx->filename);
    if (fd == -1) {
        talloc_free(ctx);
        return 1;
    }
    close(fd);

    *state = ctx;
    return 0;
}

static int inotify_test_dir_setup(void **state)
{
    struct inotify_test_ctx *ctx;

    ctx = common_setup(NULL);
    if (ctx == NULL) {
        return 1;
    }

    ctx->dirname = talloc_strdup(ctx, "test_inotify_dir.XXXXXX");
    if (ctx->dirname == NULL) {
        talloc_free(ctx);
        return 1;
    }

    ctx->dirname = mkdtemp(ctx->dirname);
    if (ctx->dirname == NULL) {
        talloc_free(ctx);
        return 1;
    }

    ctx->filename = talloc_asprintf(ctx, "%s/testfile", ctx->dirname);
    if (ctx->filename == NULL) {
        talloc_free(ctx);
        return 1;
    }

    *state = ctx;
    return 0;
}

static int inotify_test_teardown(void **state)
{
    struct inotify_test_ctx *ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    int ret;

    ret = unlink(ctx->filename);
    if (ret == -1 && errno != ENOENT) {
        return 1;
    }

    talloc_free(ctx);
    return 0;
}

static int inotify_test_dir_teardown(void **state)
{
    struct inotify_test_ctx *ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    int ret;

    ret = unlink(ctx->filename);
    if (ret == -1 && errno != ENOENT) {
        return 1;
    }

    ret = rmdir(ctx->dirname);
    if (ret == -1 && errno != ENOENT) {
        return 1;
    }

    talloc_free(ctx);
    return 0;
}

static void file_mod_op(struct tevent_context *ev,
                        struct tevent_timer *te,
                        struct timeval t,
                        void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);
    FILE *f;

    talloc_free(te);

    f = fopen(test_ctx->filename, "w");
    if (f == NULL) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    fprintf(f, "%s\n", test_ctx->filename);
    fflush(f);
    fclose(f);
}

static void check_and_set_threshold(struct inotify_test_ctx *test_ctx,
                                    uint32_t flags)
{
    if (test_ctx->exp_flags != 0 && !(test_ctx->exp_flags & flags)) {
        fail();
    }

    test_ctx->ncb++;
}

static int inotify_set_threshold_cb(const char *filename,
                                    uint32_t flags,
                                    void *pvt)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(pvt,
                                                struct inotify_test_ctx);

    check_and_set_threshold(test_ctx, flags);
    return EOK;
}

static int inotify_threshold_cb(const char *filename,
                                uint32_t flags,
                                void *pvt)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(pvt,
                                                struct inotify_test_ctx);

    check_and_set_threshold(test_ctx, flags);
    if (test_ctx->ncb == test_ctx->threshold) {
        test_ctx->tctx->done = true;
        return EOK;
    }

    return EOK;
}

/* Test that running two modifications fires the callback twice */
static void test_inotify_mod(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev, SNOTIFY_WATCH_DIR,
                         test_ctx->filename, NULL, IN_MODIFY,
                         inotify_threshold_cb, test_ctx);
    assert_non_null(ctx);

    test_ctx->threshold = 2;
    test_ctx->exp_flags = IN_MODIFY;

    gettimeofday(&tv, NULL);
    tv.tv_usec += 500;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mod_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    gettimeofday(&tv, NULL);
    tv.tv_sec += 1;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mod_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);

    talloc_free(ctx);
}

static void file_mv_op(struct tevent_context *ev,
                       struct tevent_timer *te,
                       struct timeval t,
                       void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);
    FILE *f;
    int fd;
    char src_tmp_file[] = "test_inotify_src.XXXXXX";
    int ret;

    talloc_free(te);

    fd = mkstemp(src_tmp_file);
    if (fd == -1) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    f = fdopen(fd, "w");
    if (f == NULL) {
        close(fd);
        unlink(src_tmp_file);
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    fprintf(f, "%s\n", test_ctx->filename);
    fflush(f);
    fclose(f);

    ret = rename(src_tmp_file, test_ctx->filename);
    if (ret == -1) {
        unlink(src_tmp_file);
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }
}

static void test_inotify_mv(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev, SNOTIFY_WATCH_DIR,
                         test_ctx->filename, NULL, IN_MOVED_TO,
                         inotify_threshold_cb, test_ctx);
    assert_non_null(ctx);

    test_ctx->threshold = 1;
    test_ctx->exp_flags = IN_MOVED_TO;

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mv_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void file_del_add_op(struct tevent_context *ev,
                            struct tevent_timer *te,
                            struct timeval t,
                            void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);
    FILE *f;
    int ret;

    talloc_free(te);

    ret = unlink(test_ctx->filename);
    if (ret == -1) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    f = fopen(test_ctx->filename, "w");
    if (f == NULL) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }

    fprintf(f, "%s\n", test_ctx->filename);
    fflush(f);
    fclose(f);
}

static void test_inotify_del_add(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;

    test_ctx->threshold = 1;
    test_ctx->exp_flags = IN_CREATE;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev, SNOTIFY_WATCH_DIR,
                         test_ctx->filename, NULL,
                         IN_CREATE,
                         inotify_threshold_cb, test_ctx);
    assert_non_null(ctx);

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_del_add_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void test_inotify_file_moved_in(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;

    test_ctx->threshold = 1;
    test_ctx->exp_flags = IN_CREATE;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev, SNOTIFY_WATCH_DIR,
                         test_ctx->filename, NULL,
                         IN_CREATE | IN_CLOSE_WRITE,
                         inotify_threshold_cb, test_ctx);
    assert_non_null(ctx);

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;

    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mod_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void file_del_op(struct tevent_context *ev,
                        struct tevent_timer *te,
                        struct timeval t,
                        void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);
    int ret;

    talloc_free(te);

    ret = unlink(test_ctx->filename);
    if (ret == -1) {
        test_ctx->tctx->error = errno;
        test_ctx->tctx->done = true;
        return;
    }
}

static void check_threshold_cb(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval t,
                               void *ptr)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(ptr,
                                                struct inotify_test_ctx);

    /* tests that no more callbacks were issued and exactly one
     * was caught for both requests
     */
    if (test_ctx->ncb == test_ctx->threshold) {
        test_ctx->tctx->done = true;
        return;
    }

    fail();
}

static void test_inotify_delay(void **state)
{
    struct inotify_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                     struct inotify_test_ctx);
    struct snotify_ctx *ctx;
    struct timeval tv;
    struct tevent_timer *te;
    errno_t ret;
    struct timeval delay = { .tv_sec = 1, .tv_usec = 0 };

    test_ctx->threshold = 1;
    test_ctx->exp_flags = IN_CREATE | IN_DELETE;

    ctx = snotify_create(test_ctx, test_ctx->tctx->ev, SNOTIFY_WATCH_DIR,
                         test_ctx->filename, &delay,
                         IN_CREATE | IN_DELETE,
                         inotify_set_threshold_cb, test_ctx);
    assert_non_null(ctx);

    gettimeofday(&tv, NULL);
    tv.tv_usec += 100;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_mod_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    gettimeofday(&tv, NULL);
    tv.tv_usec += 200;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, file_del_op, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    gettimeofday(&tv, NULL);
    tv.tv_sec += 2;
    te = tevent_add_timer(test_ctx->tctx->ev, test_ctx,
                          tv, check_threshold_cb, test_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to queue file update!\n");
        return;
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
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
        cmocka_unit_test_setup_teardown(test_inotify_mv,
                                        inotify_test_setup,
                                        inotify_test_teardown),
        cmocka_unit_test_setup_teardown(test_inotify_mod,
                                        inotify_test_setup,
                                        inotify_test_teardown),
        cmocka_unit_test_setup_teardown(test_inotify_del_add,
                                        inotify_test_setup,
                                        inotify_test_teardown),
        cmocka_unit_test_setup_teardown(test_inotify_file_moved_in,
                                        inotify_test_dir_setup,
                                        inotify_test_dir_teardown),
        cmocka_unit_test_setup_teardown(test_inotify_delay,
                                        inotify_test_dir_setup,
                                        inotify_test_dir_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}

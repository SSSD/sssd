/*
    SSSD

    file watch - Utilities tests

    Authors:
        Alejandro López <allopez@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <tevent.h>
#include <fcntl.h>

#include <check.h>
#include <popt.h>

#include "util/file_watch.h"
#include "tests/common.h"

#define FW_NAME                           "/file-watch-test-dir"
#define FILE_INOTIFY_NAME                 "watched_file_inotify"
#define FILE_POLL_NAME                    "watched_file_poll"
#define FW_DIR                            TEST_DIR FW_NAME
#define EXISTING_FILE_INOTIFY_NAME        FILE_INOTIFY_NAME ".exists"
#define EXISTING_FILE_POLL_NAME           FILE_POLL_NAME ".exists"
#define WATCHED_FILE_INOTIFY              FW_DIR "/.." FW_NAME "/" FILE_INOTIFY_NAME
#define WATCHED_FILE_POLL                 FW_DIR "/.." FW_NAME "/" FILE_POLL_NAME
#define WATCHED_EXISTING_FILE_INOTIFY     FW_DIR "/.." FW_NAME "/" EXISTING_FILE_INOTIFY_NAME
#define WATCHED_EXISTING_FILE_POLL        FW_DIR "/.." FW_NAME "/" EXISTING_FILE_POLL_NAME
#define WATCHED_EXISTING_LINK_INOTIFY     FW_DIR "/" EXISTING_FILE_INOTIFY_NAME ".link"
#define WATCHED_EXISTING_LINK_POLL        FW_DIR "/" EXISTING_FILE_POLL_NAME ".link"
#define UNWATCHED_FILE                    FW_DIR "/unwatched_file"


static TALLOC_CTX *test_mem_ctx;

struct fn_arg {
    const char *filename;
    int counter;
};

static void remove_files(void)
{
    unlink(WATCHED_FILE_INOTIFY);
    unlink(WATCHED_FILE_POLL);
    unlink(WATCHED_EXISTING_LINK_INOTIFY);
    unlink(WATCHED_EXISTING_LINK_POLL);
    unlink(WATCHED_EXISTING_FILE_INOTIFY);
    unlink(WATCHED_EXISTING_FILE_POLL);
    unlink(UNWATCHED_FILE);
}

static void setup_file_watch(void)
{
    DEBUG(SSSDBG_TRACE_ALL, "==========================================\n");
    test_mem_ctx = talloc_new(NULL);
    mkdir(FW_DIR, 0700);
    remove_files();
}

static void teardown_file_watch(void)
{
    talloc_free(test_mem_ctx);
    remove_files();
    rmdir(FW_DIR);
}


static void callback(const char *filename, void *arg)
{
    static char received[PATH_MAX + 1];
    static char expected[PATH_MAX + 1];
    char *res;
    struct fn_arg *data = (struct fn_arg *) arg;

    DEBUG(SSSDBG_TRACE_FUNC, "Callback invoked\n");

    ck_assert_msg(data != NULL, "Callback received NULL argument");

    res = realpath(data->filename, expected);
    ck_assert_msg(res != NULL, "Failed to normalize the expected filename");

    res = realpath(filename, received);
    ck_assert_msg(res != NULL, "Failed to normalize the received filename");

    ck_assert_msg(strcmp(expected, received) == 0,
                  "Wrong filename in the callback.");
    data->counter++;
}


static void modify_file(const char *filename)
{
    int fd;
    int res;

    DEBUG(SSSDBG_TRACE_FUNC, "Modifying file %s\n", filename);
    fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    ck_assert_msg(fd != -1, "Failed to open the file.");

    res = write(fd, "=", 1);
    ck_assert_msg(res == 1, "Failed to write to the file.");

    res = close(fd);
    ck_assert_msg(res == 0, "Failed to close the file.");
}

static void test_file_watch_no_file(bool use_inotify)
{
    struct file_watch_ctx *ctx;
    struct tevent_context *ev;
    const char *filename;
    struct fn_arg arg;
    int res;

    if (use_inotify) {
        filename = WATCHED_FILE_INOTIFY;
    } else {
        filename = WATCHED_FILE_POLL;
    }

    ev = tevent_context_init(test_mem_ctx);
    ck_assert_msg(ev != NULL, "Failed to create the tevent context.");

    arg.filename = filename;
    arg.counter = 0;

    DEBUG(SSSDBG_TRACE_ALL, "Watching file %s\n", filename);
    ctx = fw_watch_file(test_mem_ctx, ev, filename, use_inotify, callback, &arg);
    ck_assert_msg(ctx != NULL, "Failed to watch a file.");
    ck_assert_msg(arg.counter == 0, "Unexpected callback invocation.");

    /* At this point the file doesn't exist. We create the watched and an
       unwatched file */
    modify_file(UNWATCHED_FILE);
    modify_file(filename);
    if (use_inotify) {
        res = tevent_loop_once(ev);
        ck_assert_msg(res == 0, "tevent_loop_once() failed.");
    }
    res = tevent_loop_once(ev);
    ck_assert_msg(res == 0, "tevent_loop_once() failed.");
    ck_assert_msg(arg.counter >= 1, "Callback not invoked on creation.");
    ck_assert_msg(arg.counter <= 1, "Callback invoked too many times on creation.");

    /* Now just modify the file */
    modify_file(filename);
    if (use_inotify) {
        res = tevent_loop_once(ev);
        ck_assert_msg(res == 0, "tevent_loop_once() failed.");
    }
    res = tevent_loop_once(ev);
    ck_assert_msg(res == 0, "tevent_loop_once() failed.");
    ck_assert_msg(arg.counter >= 2, "Callback not invoked on modification.");
    ck_assert_msg(arg.counter <= 2, "Callback invoked too many times on modification.");

}


static void test_file_watch_with_file(bool use_inotify)
{
    struct file_watch_ctx *ctx;
    struct tevent_context *ev;
    const char *filepath;
    const char *filename;
    const char *linkpath;
    struct fn_arg arg;
    int res;

    if (use_inotify) {
        filename = EXISTING_FILE_INOTIFY_NAME;
        filepath = WATCHED_EXISTING_FILE_INOTIFY;
        linkpath = WATCHED_EXISTING_LINK_INOTIFY;
    } else {
        filename = EXISTING_FILE_POLL_NAME;
        filepath = WATCHED_EXISTING_FILE_POLL;
        linkpath = WATCHED_EXISTING_LINK_POLL;
    }
    modify_file(filepath);
    res = symlink(filename, linkpath);
    ck_assert_msg(res == 0, "Failed create the symbolic link");

    ev = tevent_context_init(test_mem_ctx);
    ck_assert_msg(ev != NULL, "Failed to create the tevent context.");

    arg.filename = linkpath;
    arg.counter = 0;

    /* File already exists */
    DEBUG(SSSDBG_TRACE_ALL, "Watching link %s\n", linkpath);
    ctx = fw_watch_file(test_mem_ctx, ev, linkpath, use_inotify, callback, &arg);
    ck_assert_msg(ctx != NULL, "Failed to watch a link.");
    ck_assert_msg(arg.counter >= 1, "Callback not invoked at start up.");
    ck_assert_msg(arg.counter <= 1, "Callback invoked too many times at start up.");

    /* Now just modify the file */
    if (!use_inotify) {
        sleep(2); /* Detection by polling is based on the file's modification time. */
    }
    modify_file(filepath);
    if (use_inotify) {
        res = tevent_loop_once(ev);
        ck_assert_msg(res == 0, "tevent_loop_once() failed.");
    }
    res = tevent_loop_once(ev);
    ck_assert_msg(res == 0, "tevent_loop_once() failed.");
    ck_assert_msg(arg.counter >= 2, "Callback not invoked on modification.");
    ck_assert_msg(arg.counter <= 2, "Callback invoked too many times on modification.");
}


START_TEST(test_inotify_no_file)
{
    test_file_watch_no_file(true);
}
END_TEST


START_TEST(test_poll_no_file)
{
    test_file_watch_no_file(false);
}
END_TEST


START_TEST(test_inotify_with_file)
{
    test_file_watch_with_file(true);
}
END_TEST


START_TEST(test_poll_with_file)
{
    test_file_watch_with_file(false);
}
END_TEST


Suite *file_watch_suite(void)
{
    Suite *s = suite_create("file_watch");

    TCase *tc_file_watch = tcase_create("file_watch");
    tcase_add_checked_fixture(tc_file_watch, setup_file_watch, teardown_file_watch);

    tcase_add_test(tc_file_watch, test_inotify_no_file);
    tcase_add_test(tc_file_watch, test_inotify_with_file);
    tcase_add_test(tc_file_watch, test_poll_no_file);
    tcase_add_test(tc_file_watch, test_poll_with_file);
    tcase_set_timeout(tc_file_watch, 60);

    suite_add_tcase(s, tc_file_watch);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;
    int opt;
    poptContext pc;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
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
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    tests_set_cwd();

    Suite *s = file_watch_suite();
    SRunner *sr = srunner_create(s);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

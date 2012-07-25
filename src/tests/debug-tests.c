/*
    SSSD

    debug-tests.c

    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include <check.h>
#include <stdio.h>
#include <talloc.h>
#include <errno.h>
#include <string.h>
#include "util/util.h"
#include "tests/common.h"

#define DEBUG_TEST_ERROR    -1
#define DEBUG_TEST_NOK      1
#define DEBUG_TEST_NOK_TS   2

START_TEST(test_debug_convert_old_level_old_format)
{
    int expected_level = 0x0000;
    int old_level;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };

    for (old_level = 0; old_level <= 9; old_level++) {
        expected_level |= levels[old_level];

        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Invalid conversion of %d", old_level);
        fail_unless(debug_convert_old_level(old_level) == expected_level, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_convert_old_level_new_format)
{
    fail_unless(
        debug_convert_old_level(SSSDBG_UNRESOLVED) == SSSDBG_FATAL_FAILURE,
        "Invalid conversion of SSSDBG_UNRESOLVED"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_FATAL_FAILURE) == SSSDBG_FATAL_FAILURE,
        "Invalid conversion of SSSDBG_FATAL_FAILURE"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_CRIT_FAILURE) == SSSDBG_CRIT_FAILURE,
        "Invalid conversion of SSSDBG_CRIT_FAILURE"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_OP_FAILURE) == SSSDBG_OP_FAILURE,
        "Invalid conversion of SSSDBG_OP_FAILURE"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_MINOR_FAILURE) == SSSDBG_MINOR_FAILURE,
        "Invalid conversion of SSSDBG_MINOR_FAILURE"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_CONF_SETTINGS) == SSSDBG_CONF_SETTINGS,
        "Invalid conversion of SSSDBG_CONF_SETTINGS"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_FUNC_DATA) == SSSDBG_FUNC_DATA,
        "Invalid conversion of SSSDBG_FUNC_DATA"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_TRACE_FUNC) == SSSDBG_TRACE_FUNC,
        "Invalid conversion of SSSDBG_TRACE_FUNC"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_TRACE_LIBS) == SSSDBG_TRACE_LIBS,
        "Invalid conversion of SSSDBG_TRACE_LIBS"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_TRACE_INTERNAL) == SSSDBG_TRACE_INTERNAL,
        "Invalid conversion of SSSDBG_TRACE_INTERNAL"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_TRACE_ALL) == SSSDBG_TRACE_ALL,
        "Invalid conversion of SSSDBG_TRACE_ALL"
    );
    fail_unless(
        debug_convert_old_level(SSSDBG_MASK_ALL) == SSSDBG_MASK_ALL,
        "Invalid conversion of SSSDBG_MASK_ALL"
    );
}
END_TEST

START_TEST(test_debug_get_level_old_format)
{
    fail_unless(debug_get_level(0) == SSSDBG_FATAL_FAILURE, "Invalid conversion of 0");
    fail_unless(debug_get_level(1) == SSSDBG_CRIT_FAILURE, "Invalid conversion of 1");
    fail_unless(debug_get_level(2) == SSSDBG_OP_FAILURE, "Invalid conversion of 2");
    fail_unless(debug_get_level(3) == SSSDBG_MINOR_FAILURE, "Invalid conversion of 3");
    fail_unless(debug_get_level(4) == SSSDBG_CONF_SETTINGS, "Invalid conversion of 4");
    fail_unless(debug_get_level(5) == SSSDBG_FUNC_DATA, "Invalid conversion of 5");
    fail_unless(debug_get_level(6) == SSSDBG_TRACE_FUNC, "Invalid conversion of 6");
    fail_unless(debug_get_level(7) == SSSDBG_TRACE_LIBS, "Invalid conversion of 7");
    fail_unless(debug_get_level(8) == SSSDBG_TRACE_INTERNAL, "Invalid conversion of 8");
    fail_unless(debug_get_level(9) == SSSDBG_TRACE_ALL, "Invalid conversion of 9");
}
END_TEST

START_TEST(test_debug_get_level_new_format)
{
    fail_unless(
        debug_get_level(SSSDBG_UNRESOLVED) == SSSDBG_FATAL_FAILURE,
        "Invalid conversion of SSSDBG_UNRESOLVED"
    );
    fail_unless(
        debug_get_level(SSSDBG_FATAL_FAILURE) == SSSDBG_FATAL_FAILURE,
        "Invalid conversion of SSSDBG_FATAL_FAILURE"
    );
    fail_unless(
        debug_get_level(SSSDBG_CRIT_FAILURE) == SSSDBG_CRIT_FAILURE,
        "Invalid conversion of SSSDBG_CRIT_FAILURE"
    );
    fail_unless(
        debug_get_level(SSSDBG_OP_FAILURE) == SSSDBG_OP_FAILURE,
        "Invalid conversion of SSSDBG_OP_FAILURE"
    );
    fail_unless(
        debug_get_level(SSSDBG_MINOR_FAILURE) == SSSDBG_MINOR_FAILURE,
        "Invalid conversion of SSSDBG_MINOR_FAILURE"
    );
    fail_unless(
        debug_get_level(SSSDBG_CONF_SETTINGS) == SSSDBG_CONF_SETTINGS,
        "Invalid conversion of SSSDBG_CONF_SETTINGS"
    );
    fail_unless(
        debug_get_level(SSSDBG_FUNC_DATA) == SSSDBG_FUNC_DATA,
        "Invalid conversion of SSSDBG_FUNC_DATA"
    );
    fail_unless(
        debug_get_level(SSSDBG_TRACE_FUNC) == SSSDBG_TRACE_FUNC,
        "Invalid conversion of SSSDBG_TRACE_FUNC"
    );
    fail_unless(
        debug_get_level(SSSDBG_TRACE_LIBS) == SSSDBG_TRACE_LIBS,
        "Invalid conversion of SSSDBG_TRACE_LIBS"
    );
    fail_unless(
        debug_get_level(SSSDBG_TRACE_INTERNAL) == SSSDBG_TRACE_INTERNAL,
        "Invalid conversion of SSSDBG_TRACE_INTERNAL"
    );
    fail_unless(
        debug_get_level(SSSDBG_TRACE_ALL) == SSSDBG_TRACE_ALL,
        "Invalid conversion of SSSDBG_TRACE_ALL"
    );
}
END_TEST

int test_helper_debug_check_message(int level, int msgmode)
{
    TALLOC_CTX *ctx = talloc_new(NULL);
    char filename[24] = {'\0'};
    char *msg = NULL;
    char *compare_to = NULL;
    const char *function = __FUNCTION__;
    const char *body = "some error\n";
    int filesize;
    int fsize;
    int fd;
    int ret;
    int _errno = 0;
    mode_t old_umask;
    FILE *file = NULL;

    strncpy(filename, "sssd_debug_tests.XXXXXX", 24);

    old_umask = umask(077);
    fd = mkstemp(filename);
    umask(old_umask);
    if (fd == -1) {
        _errno = errno;
        talloc_free(ctx);
        errno = _errno;
        return DEBUG_TEST_ERROR;
    }

    file = fdopen(fd, "r");
    if (file == NULL) {
        _errno = errno;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    ret = set_debug_file_from_fd(fd);
    if (ret != EOK) {
        _errno = ret;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    if (msgmode == 0) {
        DEBUG(level, (body));
    } else {
        DEBUG_MSG(level, __FUNCTION__, "some error");
    }

    ret = fseek(file, 0, SEEK_END);
    if (ret == -1) {
        _errno = errno;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    filesize = ftell(file);
    if (filesize == -1) {
        _errno = errno;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    rewind(file);

    msg = talloc_array(ctx, char, filesize+1);
    if (msg == NULL) {
        _errno = ENOMEM;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }
    fsize = fread(msg, sizeof(char), filesize, file);
    if (fsize != filesize) {
        _errno = EIO;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }
    msg[fsize] = '\0';

    if (debug_timestamps == 1) {
        char time_day[4] = {'\0', '\0', '\0', '\0'};
        char time_month[4] = {'\0', '\0', '\0', '\0'};
        int time_day_num = 0;
        int time_hour = 0;
        int time_min = 0;
        int time_sec = 0;
        int time_usec = 0;
        int time_year = 0;
        int scan_return = 0;

        if (debug_microseconds == 0) {
            scan_return = sscanf(msg, "(%s %s %d %d:%d:%d %d)", time_day, time_month,
                                 &time_day_num, &time_hour, &time_min, &time_sec, &time_year);

            if (scan_return != 7) {
                ret = DEBUG_TEST_NOK_TS;
                goto done;
            }
            compare_to = talloc_asprintf(ctx,
                                         "(%s %s %2d %.2d:%.2d:%.2d %.4d) "
                                         "[%s] [%s] (%#.4x): %s",
                                         time_day, time_month, time_day_num,
                                         time_hour, time_min, time_sec, time_year,
                                         debug_prg_name, function, level, body);
            if (compare_to == NULL) {
                _errno = ENOMEM;
                ret = DEBUG_TEST_ERROR;
                goto done;
            }
        } else {
            scan_return = sscanf(msg, "(%s %s %d %d:%d:%d:%d %d)", time_day, time_month,
                                 &time_day_num, &time_hour, &time_min, &time_sec,
                                 &time_usec, &time_year);

            if (scan_return != 8) {
                ret = DEBUG_TEST_NOK_TS;
                goto done;
            }
            compare_to = talloc_asprintf(ctx,
                                         "(%s %s %2d %.2d:%.2d:%.2d:%.6d %.4d) "
                                         "[%s] [%s] (%#.4x): %s",
                                         time_day, time_month, time_day_num,
                                         time_hour, time_min, time_sec, time_usec,
                                         time_year, debug_prg_name, function, level, body);
            if (compare_to == NULL) {
                _errno = ENOMEM;
                ret = DEBUG_TEST_ERROR;
                goto done;
            }
        }
    } else {
        compare_to = talloc_asprintf(ctx, "[%s] [%s] (%#.4x): %s",
                                     debug_prg_name, function, level, body);
        if (compare_to == NULL) {
            _errno = ENOMEM;
            ret = DEBUG_TEST_ERROR;
            goto done;
        }
    }
    ret = strncmp(msg, compare_to, filesize) == 0 ? EOK : DEBUG_TEST_NOK;

done:
    talloc_free(ctx);
    if (file != NULL) {
        fclose(file);
    }
    remove(filename);
    errno = _errno;
    return ret;
}

int test_helper_debug_is_empty_message(int level, int msgmode)
{
    char filename[24] = {'\0'};
    int fd;
    int filesize;
    int ret;
    int _errno = 0;
    mode_t old_umask;
    FILE *file;

    strncpy(filename, "sssd_debug_tests.XXXXXX", 24);

    old_umask = umask(077);
    fd = mkstemp(filename);
    umask(old_umask);
    if (fd == -1) {
        return DEBUG_TEST_ERROR;
    }

    file = fdopen(fd, "r");
    if (file == NULL) {
        _errno = errno;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    ret = set_debug_file_from_fd(fd);
    if (ret != EOK) {
        _errno = ret;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    if (msgmode == 0) {
        DEBUG(level, ("some error\n"));
    } else {
        DEBUG_MSG(level, __FUNCTION__, "some error");
    }

    ret = fseek(file, 0, SEEK_END);
    if (ret == -1) {
        _errno = errno;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    filesize = ftell(file);
    if (filesize == -1) {
        _errno = errno;
        ret = DEBUG_TEST_ERROR;
        goto done;
    }

    ret = filesize == 0 ? EOK : DEBUG_TEST_NOK;

done:
    if (file != NULL) {
        fclose(file);
    }
    remove(filename);
    errno = _errno;
    return ret;
}

START_TEST(test_debug_is_set_single_no_timestamp)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = levels[i];

        errno = 0;
        result = test_helper_debug_check_message(levels[i], 0);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message don't match", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_set_single_timestamp)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 1;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = levels[i];

        errno = 0;
        result = test_helper_debug_check_message(levels[i], 0);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - invalid timestamp", levels[i]);
        fail_if(result == DEBUG_TEST_NOK_TS, msg);
        talloc_free(msg);

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message don't match", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_set_single_timestamp_microseconds)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 1;
    debug_microseconds = 1;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = levels[i];

        errno = 0;
        result = test_helper_debug_check_message(levels[i], 0);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - invalid timestamp", levels[i]);
        fail_if(result == DEBUG_TEST_NOK_TS, msg);
        talloc_free(msg);

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message don't match", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_notset_no_timestamp)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        errno = 0;
        result = test_helper_debug_is_empty_message(levels[i], 0);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL,
                              "Test of level %#.4x failed - message has been written",
                              levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_notset_timestamp)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        errno = 0;
        result = test_helper_debug_is_empty_message(levels[i], 0);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL,
                        "Test of level %#.4x failed - message has been written",
                        levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_notset_timestamp_microseconds)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 1;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        errno = 0;
        result = test_helper_debug_is_empty_message(levels[i], 0);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL,
                        "Test of level %#.4x failed - message has been written",
                        levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_msg_is_set_single_no_timestamp)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = levels[i];

        errno = 0;
        result = test_helper_debug_check_message(levels[i], 1);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message don't match", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_msg_is_set_single_timestamp)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 1;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = levels[i];

        errno = 0;
        result = test_helper_debug_check_message(levels[i], 1);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - invalid timestamp", levels[i]);
        fail_if(result == DEBUG_TEST_NOK_TS, msg);
        talloc_free(msg);

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message don't match", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_msg_is_set_single_timestamp_microseconds)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 1;
    debug_microseconds = 1;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = levels[i];

        errno = 0;
        result = test_helper_debug_check_message(levels[i], 1);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - invalid timestamp", levels[i]);
        fail_if(result == DEBUG_TEST_NOK_TS, msg);
        talloc_free(msg);

        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message don't match", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_msg_is_notset_no_timestamp)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        errno = 0;
        result = test_helper_debug_is_empty_message(levels[i], 1);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message has been written", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_msg_is_notset_timestamp)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 0;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        errno = 0;
        result = test_helper_debug_is_empty_message(levels[i], 1);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message has been written", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_msg_is_notset_timestamp_microseconds)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };
    char *error_msg;

    debug_timestamps = 0;
    debug_microseconds = 1;
    debug_to_file = 1;
    debug_prg_name = "sssd";

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        errno = 0;
        result = test_helper_debug_is_empty_message(levels[i], 1);

        if (result == DEBUG_TEST_ERROR) {
            error_msg = strerror(errno);
            fail(error_msg);
        }

        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - message has been written", levels[i]);
        fail_unless(result == EOK, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_set_true)
{
    int i;
    int result;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };

    debug_level = SSSDBG_MASK_ALL;

    for (i = 0; i <= 9; i++) {
        result = DEBUG_IS_SET(levels[i]);
        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - result is 0x%.4x", levels[i], result);
        fail_unless(result > 0, msg);
        talloc_free(msg);
    }
}
END_TEST

START_TEST(test_debug_is_set_false)
{
    int i;
    int result;
    int all_set = SSSDBG_MASK_ALL;
    int levels[] = {
        SSSDBG_FATAL_FAILURE,
        SSSDBG_CRIT_FAILURE,
        SSSDBG_OP_FAILURE,
        SSSDBG_MINOR_FAILURE,
        SSSDBG_CONF_SETTINGS,
        SSSDBG_FUNC_DATA,
        SSSDBG_TRACE_FUNC,
        SSSDBG_TRACE_LIBS,
        SSSDBG_TRACE_INTERNAL,
        SSSDBG_TRACE_ALL
    };

    for (i = 0; i <= 9; i++) {
        debug_level = all_set & ~levels[i];

        result = DEBUG_IS_SET(levels[i]);
        char *msg = NULL;
        msg = talloc_asprintf(NULL, "Test of level %#.4x failed - result is 0x%.4x", levels[i], result);
        fail_unless(result == 0, msg);
        talloc_free(msg);
    }
}
END_TEST

Suite *debug_suite(void)
{
    Suite *s = suite_create("debug");

    TCase *tc_debug = tcase_create("debug");

    tcase_add_test(tc_debug, test_debug_convert_old_level_old_format);
    tcase_add_test(tc_debug, test_debug_convert_old_level_new_format);
    tcase_add_test(tc_debug, test_debug_get_level_old_format);
    tcase_add_test(tc_debug, test_debug_get_level_new_format);
    tcase_add_test(tc_debug, test_debug_is_set_single_no_timestamp);
    tcase_add_test(tc_debug, test_debug_is_set_single_timestamp);
    tcase_add_test(tc_debug, test_debug_is_set_single_timestamp_microseconds);
    tcase_add_test(tc_debug, test_debug_is_notset_no_timestamp);
    tcase_add_test(tc_debug, test_debug_is_notset_timestamp);
    tcase_add_test(tc_debug, test_debug_is_notset_timestamp_microseconds);
    tcase_add_test(tc_debug, test_debug_msg_is_set_single_no_timestamp);
    tcase_add_test(tc_debug, test_debug_msg_is_set_single_timestamp);
    tcase_add_test(tc_debug, test_debug_msg_is_set_single_timestamp_microseconds);
    tcase_add_test(tc_debug, test_debug_msg_is_notset_no_timestamp);
    tcase_add_test(tc_debug, test_debug_msg_is_notset_timestamp);
    tcase_add_test(tc_debug, test_debug_msg_is_notset_timestamp_microseconds);
    tcase_add_test(tc_debug, test_debug_is_set_true);
    tcase_add_test(tc_debug, test_debug_is_set_false);
    tcase_set_timeout(tc_debug, 60);

    suite_add_tcase(s, tc_debug);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    tests_set_cwd();

    Suite *s = debug_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (number_failed == 0)
        return EXIT_SUCCESS;

    return EXIT_FAILURE;
}

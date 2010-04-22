/*
    INI LIBRARY

    Unit test for the comment object.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2010

    INI Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    INI Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with INI Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <errno.h>
#define TRACE_HOME
#include "trace.h"
#include "ini_comment.h"

int verbose = 0;

#define INIOUT(foo) \
    do { \
        if (verbose) foo; \
    } while(0)


int file_test(void)
{
    int error = EOK;
    struct ini_comment *ic = NULL;

    if ((error = ini_comment_create(&ic)) ||
        (error = ini_comment_build(ic, ";Line 0")) ||
        (error = ini_comment_build(ic, ";Line 1")) ||
        (error = ini_comment_build(ic, ";Line 2"))) {
        printf("Failed to create comment object %d\n",
               error);
        ini_comment_destroy(ic);
        return -1;
    }

    INIOUT(printf("<==== Comment ====>\n"));
    INIOUT(ini_comment_print(ic, stdout));
    INIOUT(printf("<=================>\n"));
    ini_comment_destroy(ic);

    return error;
}


int alter_test(void)
{
    int error = EOK;
    struct ini_comment *ic = NULL;
    uint32_t i, num = 0;
    char *line = NULL;
    const char *expected[] = { ";Line 0 inserted",
                               ";Line 1 inserted",
                               "",
                               "",
                               ";Line 3 replaced",
                               "",
                               ";Line 4" };


    if ((error = ini_comment_create(&ic)) ||
        (error = ini_comment_build(ic, ";Line 0")) ||
        (error = ini_comment_build(ic, NULL)) ||
        (error = ini_comment_build(ic, ";Line 2")) ||
        (error = ini_comment_build(ic, ";Line 3")) ||
        (error = ini_comment_build(ic, ""))) {
        printf("Failed to create comment object\n");
        ini_comment_destroy(ic);
        return -1;
    }

    INIOUT(printf("<==== Comment ====>\n"));
    INIOUT(ini_comment_print(ic, stdout));
    INIOUT(printf("<=================>\n"));

    if ((error = ini_comment_append(ic, ";Line 4")) ||
        (error = ini_comment_clear(ic, 2)) ||
        (error = ini_comment_replace(ic, 3, ";Line 3 replaced")) ||
        (error = ini_comment_remove(ic, 0)) ||
        (error = ini_comment_insert(ic, 0, ";Line 0 inserted")) ||
        (error = ini_comment_insert(ic, 1, ";Line 1 inserted"))) {
        printf("Failed to create comment object\n");
        ini_comment_destroy(ic);
        return -1;
    }

    INIOUT(printf("<==== Comment ====>\n"));
    INIOUT(ini_comment_print(ic, stdout));
    INIOUT(printf("<=================>\n"));

    error = ini_comment_get_numlines(ic, &num);
    if (error) {
        printf("Failed to get number of lines.\n");
        ini_comment_destroy(ic);
        return -1;
    }

    for (i = 0; i < num; i++) {
        error = ini_comment_get_line(ic, i, &line);
        if (error) {
            printf("Failed to get line.\n");
            ini_comment_destroy(ic);
            return -1;
        }
        if (strcmp(line, expected[i]) != 0) {
            printf("Lines do not match.\n");
            printf("GOT: %s\n", line);
            printf("EXP: %s\n", expected[i]);
            ini_comment_destroy(ic);
            return -1;
        }
    }

    INIOUT(printf("\n\nSwap test\n\n"));

    if ((error = ini_comment_swap(ic, 0 , 6)) ||
        (error = ini_comment_swap(ic, 1 , 5)) ||
        (error = ini_comment_swap(ic, 2 , 4))) {
        printf("Failed to swap lines.\n");
        ini_comment_destroy(ic);
        return -1;
    }

    for (i = 0; i < num; i++) {
        error = ini_comment_get_line(ic, i, &line);
        if (error) {
            printf("Failed to get line.\n");
            ini_comment_destroy(ic);
            return -1;
        }
        if (strcmp(line, expected[6 - i]) != 0) {
            printf("Lines do not match.\n");
            printf("GOT: %s\n", line);
            printf("EXP: %s\n", expected[6 - i]);
            ini_comment_destroy(ic);
            return -1;
        }
    }

    ini_comment_destroy(ic);
    return error;
}


int main(int argc, char *argv[])
{
    int error = EOK;

    if ((argc > 1) && (strcmp(argv[1], "-v") == 0)) verbose = 1;

    INIOUT(printf("Start\n"));

    if ((error = file_test()) ||
        (error = alter_test())) {
        printf("Test failed! Error %d.\n", error);
        return -1;
    }

    INIOUT(printf("Success!\n"));
    return 0;
}

/*
    REF ARRAY

    Implementation of the dynamic array with reference count.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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

#define _GNU_SOURCE
#include <errno.h>  /* for errors */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ref_array.h"
#include "config.h"
#define TRACE_HOME
#include "trace.h"

int verbose = 0;

#define RAOUT(foo) \
    do { \
        if (verbose) foo; \
    } while(0)

extern void ref_array_debug(struct ref_array *ra);

typedef int (*test_fn)(void);

/* Basic test */
int ref_array_basic_test(void)
{
    const char *line1 = "line1";
    const char *line2 = "line2";
    const char *line3 = "line3";
    const char *line4 = "line4";
    const char *line5 = "line5";
    const char *line6 = "line6";
    uint32_t i;
    struct ref_array *ra;
    struct ref_array *ra2;
    int error = EOK;
    uint32_t len = 0;
    uint32_t other_len = 0;
    char *ret;
    char *elem;
    void *ptr;

    error = ref_array_create(&ra, sizeof(char *), 1, NULL, NULL);
    if (error) {
        printf("Failed to create array %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    error = ref_array_append(ra, &line1);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 1 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    error = ref_array_append(ra, &line2);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 2 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    error = ref_array_append(ra, &line3);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 3 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    error = ref_array_append(ra, &line4);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 4 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    error = ref_array_append(ra, &line5);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 5 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    error = ref_array_append(ra, &line6);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 6 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    RAOUT(printf("\n\nTest 1 - Printing lines.\n\n"));

    error = ref_array_getlen(ra, &other_len);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to get length %d\n", error);
        return error;
    }

    len = ref_array_len(ra);

    if (len != other_len) {
        ref_array_destroy(ra);
        printf("Lengths do not match:\n");
        printf("Len    : %d\n", len);
        printf("Get Len: %d\n", other_len);
        return EFAULT;
    }

    for (i = 0; i < len; i++) {
        ref_array_get(ra, i, &ret);
        RAOUT(printf("%s\n", ret));
    }

    RAOUT(printf("\n\nTest 2 - Creating reference and then printing lines.\n\n"));

    ra2 = ref_array_getref(ra);
    ref_array_destroy(ra);

    for (i = 0; i < len; i++) {
        ret = *((char **)ref_array_get(ra2, i, NULL));
        RAOUT(printf("%s\n", ret));
    }

    RAOUT(printf("\n\nTest 3 - Get elements with copying.\n\n"));

    for (i = 0; i < len; i++) {
        ref_array_get(ra2, i, &ret);
        RAOUT(printf("%s\n", ret));
    }

    RAOUT(printf("\n\nTest 4a - Get elements with copying and assignment.\n\n"));

    /* This is a bad practice to use one variable
     * as a parameter and as an acceptor for the return value.
     * See next example for a better way to do it.
     */
    for (i = 0; i < len; i++) {
        ret = *((char **)ref_array_get(ra2, i, &ret));
        RAOUT(printf("%s\n", ret));
    }

    RAOUT(printf("\n\nTest 4b - Get elements with copying and assignment.\n\n"));

    for (i = 0; i < len; i++) {
        ret = *((char **)ref_array_get(ra2, i, &elem));
        RAOUT(printf("%s\n", ret));
        RAOUT(printf("%s\n", elem));
        if (strcmp(ret, elem) != 0) {
            ref_array_destroy(ra2);
            printf("\nRetrieved strings were expected to be same,\n");
            printf("but they are not:\n");
            printf("By pointer:[%s]\nAs element:[%s]\n", ret, elem);
            return EFAULT;
        }
    }

    RAOUT(printf("\n\nTest 5 - While loop up.\n\n"));

    i = 0;
    for (;;) {
        ptr = ref_array_get(ra2, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    RAOUT(printf("\n\nTest 6 - While loop down.\n\n"));

    i = len - 1;
    for (;;) {
        ptr = ref_array_get(ra2, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i--;
        }
        else break;
    }

    RAOUT(printf("\n\nDone!!!\n\n"));

    ref_array_destroy(ra2);
    return EOK;
}

void array_cleanup(void *elem,
                   ref_array_del_enum type,
                   void *data)
{
    RAOUT(printf("%s%s\n", (char *)data, *((char **)elem)));
    free(*((char **)elem));
}

/* Free test */
int ref_array_free_test(void)
{
    const char *line1 = "line1";
    const char *line2 = "line2";
    const char *line3 = "line3";
    const char *line4 = "line4";
    char text[] = "Deleting: ";
    char *str;
    uint32_t i;
    struct ref_array *ra;
    int error = EOK;
    char *ret;
    void *ptr;

    error = ref_array_create(&ra, sizeof(char *), 1, array_cleanup, (char *)text);
    if (error) {
        printf("Failed to create array %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    str = strdup(line1);

    error = ref_array_append(ra, &str);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 1 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    str = strdup(line2);

    error = ref_array_append(ra, &str);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 2 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    str = strdup(line3);

    error = ref_array_append(ra, &str);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 3 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    str = strdup(line4);

    error = ref_array_append(ra, &str);
    if (error) {
        ref_array_destroy(ra);
        printf("Failed to append to array line 4 %d\n", error);
        return error;
    }

    RAOUT(ref_array_debug(ra));

    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    RAOUT(printf("\n\nDone!!!\n\n"));

    ref_array_destroy(ra);
    return EOK;
}



/* Main function of the unit test */
int main(int argc, char *argv[])
{
    int error = 0;
    test_fn tests[] = { ref_array_basic_test,
                        ref_array_free_test,
                        NULL };
    test_fn t;
    int i = 0;
    char *var;

    if ((argc > 1) && (strcmp(argv[1], "-v") == 0)) verbose = 1;
    else {
        var = getenv("COMMON_TEST_VERBOSE");
        if (var) verbose = 1;
    }

    RAOUT(printf("Start\n"));

    while ((t = tests[i++])) {
        error = t();
        if (error) {
            RAOUT(printf("Failed with error %d!\n", error));
            return error;
        }
    }

    RAOUT(printf("Success!\n"));
    return 0;
}

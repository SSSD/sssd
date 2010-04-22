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

int ref_array_adv_test(void)
{
    int error = EOK;
    const char *lines[] = { "line0",
                            "line1",
                            "line2",
                            "line3",
                            "line4",
                            "line5",
                            "line6",
                            "line7",
                            "line8",
                            "line9" };
    char text[] = "Deleting: ";
    char *str;
    uint32_t i;
    struct ref_array *ra;
    char *ret;
    void *ptr;
    int expected[] = { 0, 1, 7, 8, 9 };
    int expected2[] = { 1, 7, 8, 9, 0 };

    error = ref_array_create(&ra,
                             sizeof(char *),
                             1,
                             array_cleanup,
                             (char *)text);
    if (error) {
        printf("Failed to create array %d\n", error);
        return error;
    }

    for (i = 0; i < 5;i++) {

        str = strdup(lines[i]);

        error = ref_array_append(ra, &str);
        if (error) {
            ref_array_destroy(ra);
            printf("Failed to append line %d, error %d\n",
                    i, error);
            return error;
        }
    }

    RAOUT(printf("\nInitial array.\n"));

    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }


    /* Try to remove invalid entry */
    error = ref_array_remove(ra, 1000);
    if (error != ERANGE) {
        ref_array_destroy(ra);
        printf("Removing entry expected error got success.\n");
        return -1;
    }

    /* Try to insert invalid entry */
    error = ref_array_insert(ra, 1000, &text);
    if (error != ERANGE) {
        ref_array_destroy(ra);
        printf("Inserting entry expected error got success.\n");
        return -1;
    }

    /* Try to replace invalid entry */
    error = ref_array_replace(ra, 1000, &text);
    if (error != ERANGE) {
        ref_array_destroy(ra);
        printf("Replacing entry expected error got success.\n");
        return -1;
    }

    /* Insert several entries */
    for (i = 9; i > 4; i--) {

        str = strdup(lines[i]);

        error = ref_array_insert(ra, 9 - i, &str);
        if (error) {
            ref_array_destroy(ra);
            free(str);
            printf("Failed to insert line %d, error %d\n",
                    i, error);
            return error;
        }
    }

    /* Displpay array contents */
    RAOUT(printf("\nArray with inserted values.\n"));
    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    /* Replace everything */
    for (i = 0; i < 10;i++) {

        str = strdup(lines[i]);

        error = ref_array_replace(ra, i, &str);
        if (error) {
            ref_array_destroy(ra);
            free(str);
            printf("Failed to replace line %d, error %d\n",
                    i, error);
            return error;
        }
    }

    /* Displpay array contents */
    RAOUT(printf("\nArray with replaced values.\n"));
    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    /* Reset */
    ref_array_reset(ra);

    /* Displpay array contents */
    RAOUT(printf("\nEmpty array.\n"));
    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    /* Add everything */
    for (i = 0; i < 10;i++) {

        str = strdup(lines[i]);

        error = ref_array_insert(ra, i, &str);
        if (error) {
            ref_array_destroy(ra);
            free(str);
            printf("Failed to insert into array %d\n", error);
            return error;
        }
    }

    /* Displpay array contents */
    RAOUT(printf("\nAll added back.\n"));
    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    /* Remove part */
    for (i = 0; i < 5;i++) {

        error = ref_array_remove(ra, 2);
        if (error) {
            ref_array_destroy(ra);
            printf("Failed to remive item from array %d\n", error);
            return error;
        }
    }

    /* Displpay array contents */
    RAOUT(printf("\nCleaned array.\n"));
    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("%s\n", ret));
            i++;
        }
        else break;
    }

    RAOUT(printf("\n\nChecking for expected contents\n\n"));

    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("Comparing:\n[%s]\n[%s]\n\n",
                  ret, lines[expected[i]]));
            if (strcmp(ret, lines[expected[i]]) != 0) {
                printf("Unexpected contents of the array.\n");
                ref_array_destroy(ra);
                return -1;
            }
            i++;
        }
        else break;
    }

    RAOUT(printf("\n\nSwap test\n\n"));

    if ((error = ref_array_swap(ra, 0, 1)) ||
        (error = ref_array_swap(ra, 1, 2)) ||
        (error = ref_array_swap(ra, 2, 3)) ||
        (error = ref_array_swap(ra, 3, 4))) {
        ref_array_destroy(ra);
        printf("Failed to to swap %d\n", error);
        return error;
    }

    i = 0;
    for (;;) {
        ptr = ref_array_get(ra, i, &ret);
        if (ptr) {
            RAOUT(printf("Comparing:\n[%s]\n[%s]\n\n",
                  ret, lines[expected2[i]]));
            if (strcmp(ret, lines[expected2[i]]) != 0) {
                printf("Unexpected contents of the array.\n");
                ref_array_destroy(ra);
                return -1;
            }
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
                        ref_array_adv_test,
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

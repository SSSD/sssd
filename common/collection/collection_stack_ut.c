/*
    STACK INTERFACE

    Stack unit test.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    Collection Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Collection Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Collection Library.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdio.h>
#include <string.h>
#include <errno.h>
#define TRACE_HOME
#include "trace.h"
#include "collection_stack.h"
#include "collection_tools.h"

typedef int (*test_fn)(void);

int verbose = 0;

#define COLOUT(foo) \
    do { \
        if (verbose) foo; \
    } while(0)



int stack_test(void)
{
    struct collection_item *stack = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    struct collection_item *item1 = NULL;
    struct collection_item *item2 = NULL;

    int error = EOK;

    TRACE_FLOW_STRING("stack_test", "Entry.");

    COLOUT(printf("\n\nSTACK TEST!!!.\n\n\n"));

    if ((error = col_create_stack(&stack)) ||
        (error = col_push_str_property(stack, "item1", "value 1", 0)) ||
        (error = col_push_int_property(stack, "item2", -1)) ||
        (error = col_push_unsigned_property(stack, "item3", 1)) ||
        (error = col_push_long_property(stack, "item4", 100)) ||
        (error = col_push_ulong_property(stack, "item5", 1000)) ||
        (error = col_push_double_property(stack, "item6", 1.1)) ||
        (error = col_push_bool_property(stack, "item7", 1)) ||
        (error = col_push_binary_property(stack, "item8", binary_dump, sizeof(binary_dump)))) {
        printf("Failed to push property. Error %d\n", error);
        col_destroy_collection(stack);
        return error;
    }

    COLOUT(col_debug_collection(stack, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Swapping last two items by popping and pushing them back.\n"));

    if ((error = col_pop_item(stack, &item1)) ||
        (error = col_pop_item(stack, &item2))) {
        printf("Failed to pop items. Error %d\n", error);
        col_destroy_collection(stack);
        return error;
    }

    COLOUT(printf("\nPopped two last items.\n"));
    COLOUT(col_debug_collection(stack, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("\nLast item.\n"));
    COLOUT(col_debug_item(item1));

    COLOUT(printf("\nPrevious item.\n"));
    COLOUT(col_debug_item(item2));

    if ((error = col_push_item(stack, item1)) ||
        (error = col_push_item(stack, item2))) {
        printf("Failed to pop or push items. Error %d\n", error);
        col_destroy_collection(stack);
        return error;
    }

    COLOUT(printf("\n\nPushed two items again in reverse order.\n\n"));

    COLOUT(col_debug_collection(stack, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(stack);
    TRACE_FLOW_NUMBER("stack_test. Returning", error);

    COLOUT(printf("\n\nEND OF STACK TEST!!!.\n\n"));

    return error;
}

/* Main function of the unit test */

int main(int argc, char *argv[])
{
    int error = 0;
    test_fn tests[] = { stack_test,
                        NULL };
    test_fn t;
    int i = 0;

    if ((argc > 1) && (strcmp(argv[1], "-v") == 0)) verbose = 1;

    printf("Start\n");

    while ((t = tests[i++])) {
        error = t();
        if (error) {
            printf("Failed!\n");
            return error;
        }
    }

    printf("Success!\n");
    return 0;
}

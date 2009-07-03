/*
    QUEUE INTERFACE

    Queue unit test.

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
#include "collection_queue.h"
#include "collection_tools.h"


int queue_test(void)
{
    struct collection_item *queue = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    struct collection_item *item = NULL;
    int i;
    unsigned count;
    int error = EOK;

    TRACE_FLOW_STRING("queue_test","Entry.");

    printf("\n\nQUEUE TEST!!!.\n\n\n");

    if((error = col_create_queue(&queue)) ||
       (error = col_enqueue_str_property(queue, "item1","value 1" ,0)) ||
       (error = col_enqueue_int_property(queue, "item2", -1)) ||
       (error = col_enqueue_unsigned_property(queue, "item3", 1)) ||
       (error = col_enqueue_long_property(queue, "item4", 100)) ||
       (error = col_enqueue_ulong_property(queue, "item5", 1000)) ||
       (error = col_enqueue_double_property(queue, "item6", 1.1)) ||
       (error = col_enqueue_bool_property(queue, "item7", 1)) ||
       (error = col_enqueue_binary_property(queue, "item8", binary_dump, sizeof(binary_dump)))) {
        printf("Failed to enqueue property. Error %d\n", error);
        col_destroy_collection(queue);
        return error;
    }

    col_debug_collection(queue,COL_TRAVERSE_DEFAULT);

    error = col_get_collection_count(queue, &count);
    if (error) {
        printf("Failed to get count. Error %d\n", error);
        col_destroy_collection(queue);
        return error;
    }

    count--;

    printf("Rotate the queue.\n");

    for (i = 0; i < count; i++) {
        if ((error = col_dequeue_item(queue, &item)) ||
            (error = col_enqueue_item(queue, item))) {
            printf("Failed to dequeue or enqueue items. Error %d\n", error);
            col_destroy_collection(queue);
            return error;
        }
        col_debug_collection(queue,COL_TRAVERSE_DEFAULT);
    }

    col_destroy_collection(queue);
    TRACE_FLOW_NUMBER("queue_test. Returning", error);

    printf("\n\nEND OF QUEUE TEST!!!.\n\n\n");

    return error;
}

/* Main function of the unit test */

int main(int argc, char *argv[])
{
    int error = EOK;

    printf("Start\n");
    if ((error = queue_test())) printf("Failed!\n");
    else printf("Success!\n");

    return error;
}

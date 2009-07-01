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


int queue_test()
{
    struct collection_item *queue = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    struct collection_item *item = NULL;
    int i;
    unsigned count;
    int error = EOK;

    TRACE_FLOW_STRING("queue_test","Entry.");

    printf("\n\nQUEUE TEST!!!.\n\n\n");

    if((error = create_queue(&queue)) ||
       (error = enqueue_str_property(queue, "item1","value 1" ,0)) ||
       (error = enqueue_int_property(queue, "item2", -1)) ||
       (error = enqueue_unsigned_property(queue, "item3", 1)) ||
       (error = enqueue_long_property(queue, "item4", 100)) ||
       (error = enqueue_ulong_property(queue, "item5", 1000)) ||
       (error = enqueue_double_property(queue, "item6", 1.1)) ||
       (error = enqueue_bool_property(queue, "item7", 1)) ||
       (error = enqueue_binary_property(queue, "item8", binary_dump, sizeof(binary_dump)))) {
        printf("Failed to enqueue property. Error %d\n", error);
        destroy_collection(queue);
        return error;
    }

    debug_collection(queue,COL_TRAVERSE_DEFAULT);

    error = get_collection_count(queue, &count);
    if (error) {
        printf("Failed to get count. Error %d\n", error);
        destroy_collection(queue);
        return error;
    }

    count--;

    printf("Rotate the queue.\n");

    for (i = 0; i < count; i++) {
        if ((error = dequeue_item(queue, &item)) ||
            (error = enqueue_item(queue, item))) {
            printf("Failed to dequeue or enqueue items. Error %d\n", error);
            destroy_collection(queue);
            return error;
        }
        debug_collection(queue,COL_TRAVERSE_DEFAULT);
    }

    destroy_collection(queue);
    TRACE_FLOW_NUMBER("queue_test. Returning", error);

    printf("\n\nEND OF QUEUE TEST!!!.\n\n\n");

    return error;
}

/* Main function of the unit test */

int main()
{
    int error = EOK;

    printf("Start\n");
    if ((error = queue_test())) printf("Failed!\n");
    else printf("Success!\n");

    return error;
}

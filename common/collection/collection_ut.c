/*
    COLLECTION LIBRARY

    Collection unit test.

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
#include "collection.h"
#include "collection_tools.h"

typedef int (*test_fn)(void);

int verbose = 0;

#define COLOUT(foo) \
    do { \
        if (verbose) foo; \
    } while(0)



int ref_collection_test(void)
{
    struct collection_item *peer = NULL;
    struct collection_item *socket = NULL;
    struct collection_item *socket2 = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };

    int error = EOK;

    TRACE_FLOW_STRING("ref_collection_test", "Entry.");

    COLOUT(printf("\n\nREF TEST!!!.\n\n\n"));
    COLOUT(printf("Creating PEER collection.\n"));

    if ((error = col_create_collection(&peer, "peer", 0)) ||
        (error = col_add_str_property(peer, NULL, "hostname", "peerhost.mytest.com", 0)) ||
        /* Expect trailing zero to be truncated */
        (error = col_add_str_property(peer, NULL, "IPv4", "10.10.10.10", 12)) ||
        (error = col_add_str_property(peer, NULL, "IPv6", "bla:bla:bla:bla:bla:bla", 0))) {
        printf("Failed to add property. Error %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("Creating SOCKET collection.\n"));

    if ((error = col_create_collection(&socket, "socket", 0)) ||
        (error = col_add_int_property(socket, NULL, "id", 1)) ||
        (error = col_add_long_property(socket, NULL, "packets", 100000000L)) ||
        (error = col_add_binary_property(socket, NULL, "stack", binary_dump, sizeof(binary_dump)))) {
        col_destroy_collection(peer);
        col_destroy_collection(socket);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Adding PEER collection to SOCKET collection as a reference named PEER\n"));

    /* Embed peer host into the socket2 as reference */
    error = col_add_collection_to_collection(socket, NULL, "peer", peer, COL_ADD_MODE_REFERENCE);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket);
        printf("Failed to add collection to collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("About to destroy PEER\n"));
    col_destroy_collection(peer);
    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("About to extract PEER\n"));
    error = col_get_collection_reference(socket, &peer, "peer");
    if (error) {
        col_destroy_collection(socket);
        printf("Failed to extract collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(peer);

    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));

    error = col_get_collection_reference(socket, &socket2, NULL);
    if (error) {
        col_destroy_collection(socket);
        printf("Failed to extract collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket2, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(socket);
    COLOUT(col_debug_collection(socket2, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(socket2);

    TRACE_FLOW_NUMBER("ref_collection_test. Returning", error);

    COLOUT(printf("\n\nEND OF REF TEST!!!.\n\n\n"));

    return error;

}


int single_collection_test(void)
{
    struct collection_item *handle = NULL;
    int error = EOK;

    TRACE_FLOW_STRING("single_collection_test", "Entry.");

    if ((error = col_create_collection(&handle, "string_test", 0)) ||
        (error = col_add_str_property(handle, NULL, "property_1", "some data", 0)) ||
        (error = col_add_str_property(handle, NULL, "property_2", "some other data", 2)) ||
        (error = col_add_str_property(handle, NULL, "property_3", "more data", 7))) {
        printf("Failed to add property. Error %d\n", error);
        col_destroy_collection(handle);
        return error;
    }

    error = col_add_str_property(handle, NULL, "property 1!", "some data", 0);
    if (error) {
        COLOUT(printf("Expected error adding bad property to collection %d\n", error));
    }
    else {
        printf("Expected error but got success\n");
        return -1;
    }

    error = col_add_double_property(handle, NULL, "double", 0.253545);
    if (error) {
        printf("Failed to add double property. Error %d\n", error);
        col_destroy_collection(handle);
        return error;
    }

    error = col_update_double_property(handle, "double", COL_TRAVERSE_DEFAULT, 1.999999);
    if (error) {
        printf("Failed to update double property. Error %d\n", error);
        col_destroy_collection(handle);
        return error;
    }

    COLOUT(printf("Created collection\n"));

    /* Traverse collection */
    if (verbose) {
        error = col_debug_collection(handle, COL_TRAVERSE_DEFAULT);
        if (error) {
            printf("Error debugging collection %d\n", error);
            return error;
        }
        error = col_print_collection(handle);
        if (error) {
            printf("Error printing collection %d\n", error);
            return error;
        }
    }

    col_destroy_collection(handle);

    TRACE_FLOW_NUMBER("single_collection_test. Error: ", error);
    return error;
}

int add_collection_test(void)
{
    struct collection_item *peer = NULL;
    struct collection_item *socket = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };

    int error = EOK;

    TRACE_FLOW_STRING("add_collection_test", "Entry.");

    COLOUT(printf("\n\nADD TEST!!!.\n\n\n"));
    COLOUT(printf("Creating PEER collection.\n"));

    if ((error = col_create_collection(&peer, "peer", 0)) ||
        (error = col_add_str_property(peer, NULL, "hostname", "peerhost.mytest.com", 0)) ||
        /* Expect trailing zero to be truncated */
        (error = col_add_str_property(peer, NULL, "IPv4", "10.10.10.10", 12)) ||
        (error = col_add_str_property(peer, NULL, "IPv6", "bla:bla:bla:bla:bla:bla", 0))) {
        printf("Failed to add property. Error %d", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("Creating SOCKET collection.\n"));

    if ((error = col_create_collection(&socket, "socket", 0)) ||
        (error = col_add_int_property(socket, NULL, "id", 1)) ||
        (error = col_add_long_property(socket, NULL, "packets", 100000000L)) ||
        (error = col_add_binary_property(socket, NULL, "stack", binary_dump, sizeof(binary_dump)))) {
        col_destroy_collection(peer);
        col_destroy_collection(socket);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Adding PEER collection to SOCKET collection as a reference named PEER\n"));

    /* Embed peer host into the socket2 as reference */
    error = col_add_collection_to_collection(socket, NULL, "peer", peer, COL_ADD_MODE_REFERENCE);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket);
        printf("Failed to create collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(peer);
    COLOUT(col_debug_collection(socket, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(socket);
    TRACE_FLOW_NUMBER("add_collection_test. Returning", error);
    return error;
}

int copy_cb(struct collection_item *item,
            void *ext_data,
            int *skip)
{
    COLOUT(printf("INSIDE Copy Callback\n"));
    COLOUT(col_debug_item(item));
    COLOUT(printf("Passed in data: %s\n", (char *) ext_data));
    if (strcmp(col_get_item_property(item, NULL), "id") == 0) *skip = 1;
    return EOK;
}


int mixed_collection_test(void)
{
    struct collection_item *peer;
    struct collection_item *socket1;
    struct collection_item *socket2;
    struct collection_item *socket3;
    struct collection_item *event;
    struct collection_item *host;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    int found = 0;
    unsigned int class = 0;
    char foo[] = "foo";

    int error = EOK;

    TRACE_FLOW_STRING("mixed_collection_test", "Entry.");

    COLOUT(printf("\n\nMIXED TEST!!!.\n\n\n"));
    COLOUT(printf("Creating PEER collection.\n"));

    if ((error = col_create_collection(&peer, "peer", 0)) ||
        (error = col_add_str_property(peer, NULL, "hostname", "peerhost.mytest.com", 0)) ||
        /* Expect trailing zero to be truncated */
        (error = col_add_str_property(peer, NULL, "IPv4", "10.10.10.10", 12)) ||
        (error = col_add_str_property(peer, NULL, "IPv6", "bla:bla:bla:bla:bla:bla", 0))) {
        printf("Failed to add property. Error %d", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Creating HOST collection.\n"));

    if ((error = col_create_collection(&host, "host", 0)) ||
        (error = col_add_str_property(host, NULL, "hostname", "myhost.mytest.com", 0)) ||
        (error = col_add_str_property(host, NULL, "IPv4", "20.20.20.20", 13)) ||
        (error = col_add_str_property(host, NULL, "IPv6", "bla:bla:bla:bla:bla:bla", 0)) ||
        (error = col_add_double_property(host, NULL, "double", 0.253545))) {
        printf("Failed to add property. Error %d", error);
        col_destroy_collection(peer);
        col_destroy_collection(host);
        return error;
    }

    COLOUT(col_debug_collection(host, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Creating SOCKET1 collection.\n"));

    if ((error = col_create_collection(&socket1, "socket1", 0)) ||
        (error = col_add_int_property(socket1, NULL, "id", 1)) ||
        (error = col_add_long_property(socket1, NULL, "packets", 100000000L)) ||
        (error = col_add_binary_property(socket1, NULL, "stack", binary_dump, sizeof(binary_dump)))) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket1, COL_TRAVERSE_DEFAULT));
    COLOUT(printf("Creating a copy of SOCKET1 collection named SOCKET2.\n"));

    error = col_copy_collection(&socket2, socket1, "socket2", COL_COPY_NORMAL);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        printf("Failed to copy collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket2, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    error = col_copy_collection_with_cb(&socket3, socket1, "socket3",
                                        COL_COPY_FLATDOT, copy_cb, (void *)foo);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to copy collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket3, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(socket3);

    COLOUT(printf("Adding PEER collection to SOCKET2 collection as a reference named PEER2\n"));

    /* Embed peer host into the socket2 as reference */
    error = col_add_collection_to_collection(socket2, NULL, "peer2", peer, COL_ADD_MODE_REFERENCE);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to create collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket2, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Creating an EVENT collection.\n"));

    /* Construct event */
    error = col_create_collection(&event, "event", 0);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to create collection. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(event, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Adding HOST to EVENT.\n"));

    /* Add host to event */
    error = col_add_collection_to_collection(event, NULL, NULL, host, COL_ADD_MODE_REFERENCE);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to add collections. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(event, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Embed SOCKET1 into EVENT.\n"));
    /* Donate socket1 to event */
    /* Socket1 should not be used after this */
    error = col_add_collection_to_collection(event, NULL, NULL, socket1, COL_ADD_MODE_EMBED);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to add collections. Error %d\n", error);
        return error;
    }

    COLOUT(printf("Traverse one level:\n"));
    COLOUT(col_debug_collection(event, COL_TRAVERSE_ONELEVEL));
    COLOUT(printf("Traverse ignore subcollections:\n"));
    COLOUT(col_debug_collection(event, COL_TRAVERSE_IGNORE));
    COLOUT(printf("Traverse normal:\n"));
    COLOUT(col_debug_collection(event, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(socket1, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("SOCKET1 MUST NO BE USED AFTER THIS POINT!!!\n"));
    socket1 = NULL;

    COLOUT(printf("Add collection PEER as PEER1 to subcollection SOCKET1 of the EVENT.\n"));

    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    error = col_add_collection_to_collection(event, "socket1", "peer1", peer, COL_ADD_MODE_CLONE);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        /* No socket1 any more :) */
        col_destroy_collection(socket2);
        printf("Failed to add collections. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(event, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Add property named TIMEOUT to PEER collection.\n"));

    /* Add new property to the peer collection */
    error = col_add_int_property(peer, NULL, "timeout", 5);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        /* No socket1 any more :) */
        col_destroy_collection(socket2);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(socket2, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Add property named DELAY to PEER1 collection.\n"));

    error = col_add_int_property(event, "peer1", "delay", 10);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        /* No socket1 any more :) */
        col_destroy_collection(socket2);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(event, COL_TRAVERSE_DEFAULT));
    COLOUT(col_debug_collection(host, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("Check if property PEER1.DELAY is in the EVENT collection.\n"));

    /* Check if the property in the collection */
    found = 0;
    error = col_is_item_in_collection(event, "peer1!delay", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        /* No socket1 any more :) */
        col_destroy_collection(socket2);
        printf("Failed to check property. Error %d\n", error);
        return error;
    }

    if (found == 1) {
        COLOUT(printf("Property is found!\n"));
    }
    else {
        COLOUT(printf("Error property is not found!\n"));
    }


    COLOUT(col_print_item(event, "peer1!IPv6"));
    COLOUT(col_print_item(event, "event!socket1!peer1!IPv6"));
    COLOUT(col_print_item(event, "event!peer1!IPv6"));
    COLOUT(col_print_item(event, "speer1!IPv6"));
    COLOUT(col_print_item(event, "eer1!IPv6"));
    COLOUT(col_print_item(event, "!peer1!IPv6"));
    COLOUT(col_print_item(event, "t!peer1!IPv6"));

    /* Traverse collection */
    if (verbose) {
        error = col_print_collection2(event);
        if (error) {
            printf("Error printing collection %d\n", error);
            return error;
        }
    }

    COLOUT(printf("Delete property PEER1!DELAY from the EVENT collection.\n"));

    error = col_delete_property(event, "peer1!delay", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(host);
        /* No socket1 any more :) */
        col_destroy_collection(socket2);
        printf("Failed to delete property. Error %d\n", error);
        return error;
    }

    COLOUT(printf("Printing EVENT.\n"));

    /* Traverse collection */
    if (verbose) {
        error = col_print_collection2(event);
        if (error) {
            printf("Error printing collection %d\n", error);
            return error;
        }
    }

    COLOUT(printf("Debugging EVENT.\n"));
    if (verbose) {
        error = col_debug_collection(event, COL_TRAVERSE_DEFAULT);
        if (error) {
            printf("Error printing collection %d\n", error);
            return error;
        }
    }
    COLOUT(printf("Cleanup of the collections PEER, HOST and SOCKET2.\n"));

    /* Destroy a referenced collection */
    col_destroy_collection(peer);
    col_destroy_collection(host);
    col_destroy_collection(socket2);

    COLOUT(printf("Printing EVENT again.\n"));

    /* Traverse collection again - peer should still be there */
    if (verbose) {
        error = col_print_collection(event);
        if (error) {
            col_destroy_collection(event);
            printf("Error printing collection %d\n", error);
            return error;
        }
    }

    COLOUT(printf("Debugging EVENT again.\n"));

    if (verbose) {
        error = col_debug_collection(event, COL_TRAVERSE_DEFAULT);
        if (error) {
            col_destroy_collection(event);
            printf("Error printing collection %d\n", error);
            return error;
        }
    }

    COLOUT(printf("Attempt to add property to a referenced collection.\n"));

    error = col_add_int_property(event, "host", "session", 500);
    if (error) {
        col_destroy_collection(event);
        printf("Error was NOT able to add property to a referenced collection %d.\n", error);
        return error;
    }

    COLOUT(printf("Attempt to delete non-existent property.\n"));

    /* Can't delete non exitent property */
    error = col_delete_property(event, "host.host", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT);
    if (error == 0) {
        col_destroy_collection(event);
        printf("Error was able to delete property that does not exist.\n");
        return -1;
    }
    else COLOUT(printf("Expected error %d\n", error));

    /* Set collection class */
    error = col_set_collection_class(event, 2);
    if (error != 0) {
        col_destroy_collection(event);
        printf("Error was NOT able to set class.\n");
        return error;
    }

    error = col_get_collection_class(event, &class);
    if (error != 0) {
        col_destroy_collection(event);
        printf("Error was NOT able to get class.\n");
        return error;
    }
    else COLOUT(printf("Class = %d\n", class));

    if (col_is_of_class(event, 2)) {
        COLOUT(printf("Class mathced!\n"));
    }
    else {
        col_destroy_collection(event);
        printf("Error - bad class.\n");
        return -1;
    }

    COLOUT(printf("Done. Cleaning...\n"));

    col_destroy_collection(event);

    COLOUT(printf("Exit.\n"));
    TRACE_FLOW_NUMBER("add_collection_test. Returning", EOK);
    return EOK;
}


int iterator_test(void)
{
    struct collection_item *peer;
    struct collection_item *initial;

    struct collection_item *socket1;
    struct collection_item *socket2;
    struct collection_item *socket3;
    struct collection_iterator *iterator = NULL;
    int error = EOK;
    struct collection_item *item = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    int depth = 0;
    int idepth = 0;
    int len = 0;
    int i;
    uint64_t hash1, hash2;
    int rwnd = 0;

    COLOUT(printf("\n\n==== ITERATOR TEST ====\n\n"));

    if ((error = col_create_collection(&initial, "strater", 0)) ||
        (error = col_create_collection(&peer, "peer", 0)) ||
        (error = col_add_str_property(initial, NULL, "hostname", "peerhost.mytest.com", 0)) ||
        /* Expect trailing zero to be truncated */
        (error = col_add_str_property(initial, NULL, "IPv4", "10.10.10.10", 12)) ||
        (error = col_add_str_property(initial, NULL, "IPv6", "bla:bla:bla:bla:bla:bla", 0)) ||
        (error = col_add_collection_to_collection(peer, NULL, NULL, initial, COL_ADD_MODE_FLAT))) {
        printf("Failed to add property. Error %d", error);
        col_destroy_collection(peer);
        col_destroy_collection(initial);
        return error;
    }

    col_destroy_collection(initial);

    if ((error = col_create_collection(&socket1, "socket", 0)) ||
        (error = col_add_int_property(socket1, NULL, "id", 1)) ||
        (error = col_add_long_property(socket1, NULL, "packets", 100000000L)) ||
        (error = col_add_binary_property(socket1, NULL, "stack", binary_dump, sizeof(binary_dump)))) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    if ((error = col_create_collection(&socket2, "socket", 0)) ||
        (error = col_add_int_property(socket2, NULL, "id", 2)) ||
        (error = col_add_long_property(socket2, NULL, "packets", 200000000L)) ||
        (error = col_add_binary_property(socket2, NULL, "queue", binary_dump, sizeof(binary_dump)))) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    if ((error = col_create_collection(&socket3, "socket", 0))) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        printf("Failed to add property. Error %d\n", error);
        return error;
    }

    error = col_add_collection_to_collection(peer, NULL, "first", socket1, COL_ADD_MODE_REFERENCE);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        col_destroy_collection(socket3);
        printf("Failed to add collection to collection. Error %d\n", error);
        return error;
    }

    error = col_add_collection_to_collection(peer, NULL, "second", socket2, COL_ADD_MODE_EMBED);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        col_destroy_collection(socket2);
        col_destroy_collection(socket3);
        printf("Failed to add collection to collection. Error %d\n", error);
        return error;
    }

    error = col_add_collection_to_collection(peer, NULL, "third", socket3, COL_ADD_MODE_EMBED);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        col_destroy_collection(socket3);
        printf("Failed to add collection to collection. Error %d\n", error);
        return error;
    }

    error = col_add_collection_to_collection(peer, NULL, "forth", socket1, COL_ADD_MODE_FLATDOT);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        printf("Failed to add collection to collection. Error %d\n", error);
        return error;
    }

    error = col_add_collection_to_collection(peer, NULL, NULL, socket1, COL_ADD_MODE_FLATDOT);
    if (error) {
        col_destroy_collection(peer);
        col_destroy_collection(socket1);
        printf("Failed to add collection to collection. Error %d\n", error);
        return error;
    }

    col_destroy_collection(socket1);

    /* Bind iterator */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_DEFAULT);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nCollection (traverse default):\n\n"));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("\n\nCollection (traverse flat):\n\n"));
    COLOUT(col_debug_collection(peer, COL_TRAVERSE_FLAT | COL_TRAVERSE_END));

    COLOUT(printf("\n\nIteration (1):\n\n"));

    do {


        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_unbind_iterator(iterator);
            col_destroy_collection(peer);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        idepth = 0;
        col_get_iterator_depth(iterator, &idepth);


        COLOUT(printf("%*sProperty (%s), type = %d, data size = %d depth = %d idepth = %d\n",
                depth * 4,  "",
                col_get_item_property(item, NULL),
                col_get_item_type(item),
                col_get_item_length(item),
                depth,
                idepth));

        if ((strcmp(col_get_item_property(item, NULL), "id")==0) &&
           (*((int *)(col_get_item_data(item))) == 1)) {
            COLOUT(printf("\n\nFound property we need - go up!!!\n\n\n"));

            /* This should work! */
            error = col_iterate_up(iterator, 1);
            if (error) {
                printf("We expected success but got error %d\n", error);
                col_unbind_iterator(iterator);
                col_destroy_collection(peer);
                return error;
            }

            if ((error = col_modify_str_item(item, "id2", "test", 0)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_str_item(item, NULL, "test", 2)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_binary_item(item, NULL, binary_dump, sizeof(binary_dump))) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_bool_item(item, NULL, 1)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_int_item(item, "int", 1)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_long_item(item, "long", 1000000000L)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_ulong_item(item, "ulong", 4000000000UL)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_unsigned_item(item, "unsigned", 4000000000U)) ||
                ((verbose) && (error = col_debug_item(item))) ||
                (error = col_modify_double_item(item, "double", -1.1)) ||
                ((verbose) && (error = col_debug_item(item)))) {
                printf("Failed to change property.\n");
                col_unbind_iterator(iterator);
                col_destroy_collection(peer);
                return error;
            }

            COLOUT(printf("Item name: %s\n", col_get_item_property(item, NULL)));
            COLOUT(printf("Item hash: %lu\n", (unsigned long int)col_get_item_hash(item)));
            error = col_modify_item_property(item, "new_name");
            if (error) {
                printf("We expected success but got error %d\n", error);
                col_unbind_iterator(iterator);
                col_destroy_collection(peer);
                return error;
            }
            len = 0;
            COLOUT(printf("Item name: %s\n", col_get_item_property(item, &len)));
            COLOUT(printf("Item hash: %lu\n", (unsigned long int)col_get_item_hash(item)));
            COLOUT(printf("Item length: %d\n", len));

            len = 0;
            hash1 = col_make_hash("new_name", 0, &len);
            COLOUT(printf("String name: %s\n", "new_name"));
            COLOUT(printf("String hash: %lu\n", (unsigned long int)hash1));
            COLOUT(printf("String length: %d\n", len));

            len = 0;
            hash2 = col_make_hash("new_name_suffix", 8, &len);
            COLOUT(printf("String name: %.*s\n", len, "new_name_suffix"));
            COLOUT(printf("String hash: %lu\n", (unsigned long int)hash2));
            COLOUT(printf("String length: %d\n", len));
            if (hash1 != hash2) {
                printf("Hash calculation failed\n");
                col_unbind_iterator(iterator);
                col_destroy_collection(peer);
                return EINVAL;
            }

            hash2 = col_make_hash("new_name", 8, &len);
            COLOUT(printf("String name: %.*s\n", len, "new_name"));
            COLOUT(printf("String hash: %lu\n", (unsigned long int)hash2));
            COLOUT(printf("String length: %d\n", len));
            if (hash1 != hash2) {
                printf("Hash calculation failed\n");
                col_unbind_iterator(iterator);
                col_destroy_collection(peer);
                return EINVAL;
            }

        }
    }
    while(1);

    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_FLAT);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nIteration (2 - flat):\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        COLOUT(printf("%*s", depth * 4, ""));
        COLOUT(col_debug_item(item));

        if ((strcmp(col_get_item_property(item, NULL), "queue") == 0) &&
            (rwnd == 0)) {
            COLOUT(printf("Rewinding iterator...\n"));
            col_rewind_iterator(iterator);
            rwnd++;
        }

    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_FLAT | COL_TRAVERSE_END);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nIteration (3 flat with end):\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        COLOUT(printf("%*s", depth * 4, ""));
        COLOUT(col_debug_item(item));

    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_DEFAULT | COL_TRAVERSE_END);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nIteration (4 default with end):\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        COLOUT(printf("%*s", depth * 4, ""));
        COLOUT(col_debug_item(item));

    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_SHOWSUB | COL_TRAVERSE_END);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }


    COLOUT(printf("\n\nIteration (5 show headers and references with end):\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        COLOUT(printf("%*s", depth * 4, ""));
        COLOUT(col_debug_item(item));

    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_SHOWSUB);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }


    COLOUT(printf("\n\nIteration (6 show headers and references no END):\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        COLOUT(printf("%*s", depth * 4, ""));
        COLOUT(col_debug_item(item));

    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_ONLYSUB);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nIteration (7 show headers only no END):\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        COLOUT(printf("%*s", depth * 4, ""));
        COLOUT(col_debug_item(item));

    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);


    /* Bind iterator */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_DEFAULT);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nIterate up test:\n\n"));

    do {

        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_unbind_iterator(iterator);
            col_destroy_collection(peer);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        depth = 0;
        col_get_item_depth(iterator, &depth);
        idepth = 0;
        col_get_iterator_depth(iterator, &idepth);


        COLOUT(printf("%*sProperty (%s), type = %d, data size = %d depth = %d idepth = %d\n",
                depth * 4,  "",
                col_get_item_property(item, NULL),
                col_get_item_type(item),
                col_get_item_length(item),
                depth,
                idepth));

        if (strcmp(col_get_item_property(item, NULL), "queue") == 0)  {

            COLOUT(printf("\n\nFound property we need - go up!!!\n"));
            COLOUT(printf("Expect bail out of collection processing.\n\n"));

            /* This should work! */
            error = col_iterate_up(iterator, 10);
            if (error) {
                printf("We expected success but got error %d\n", error);
                col_unbind_iterator(iterator);
                col_destroy_collection(peer);
                return error;
            }

        }
    }
    while(1);

    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_FLAT | COL_TRAVERSE_END);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nCircled looping:\n\n"));

    for (i = 0; i < 200; i++) {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) {
            COLOUT(printf("Reached end.\n\n"));
        }
        else {
            depth = 0;
            col_get_item_depth(iterator, &depth);
            COLOUT(printf("%*s", depth * 4, ""));
            COLOUT(col_debug_item(item));
        }
    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);

    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_FLAT | COL_TRAVERSE_END);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nCircled looping with pin:\n\n"));

    do {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        if (strcmp(col_get_item_property(item, NULL), "queue") == 0) {
            /* Make it a new looping point */
            col_pin_iterator(iterator);
            COLOUT(printf("Found pin point.\n\n"));
            break;
        }
        /* Are we done ? */
        if (item == NULL) {
            printf("Unexpected end.\n\n");
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return EINVAL;
        }
        else {
            depth = 0;
            col_get_item_depth(iterator, &depth);
            COLOUT(printf("%*s", depth * 4, ""));
            COLOUT(col_debug_item(item));
        }
    }
    while(1);

    /* Second loop around the pin point */
    for (i = 0; i < 200; i++) {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) {
            COLOUT(printf("Reached end.\n\n"));
        }
        else {
            depth = 0;
            col_get_item_depth(iterator, &depth);
            COLOUT(printf("%*s", depth * 4, ""));
            COLOUT(col_debug_item(item));
        }
    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);


    /* Bind iterator again in flat mode */
    error =  col_bind_iterator(&iterator, peer, COL_TRAVERSE_DEFAULT | COL_TRAVERSE_END);
    if (error) {
        printf("Error (bind): %d\n", error);
        col_destroy_collection(peer);
        return error;
    }

    COLOUT(printf("\n\nCircled looping with pin (default):\n\n"));

    do {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        if (strcmp(col_get_item_property(item, NULL), "queue") == 0) {
            /* Make it a new looping point */
            col_pin_iterator(iterator);
            COLOUT(printf("Found pin point.\n\n"));
            break;
        }
        /* Are we done ? */
        if (item == NULL) {
            printf("Unexpected end.\n\n");
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return EINVAL;
        }
        else {
            depth = 0;
            col_get_item_depth(iterator, &depth);
            COLOUT(printf("%*s", depth * 4, ""));
            COLOUT(col_debug_item(item));
        }
    }
    while(1);

    /* Second loop around the pin point */
    for (i = 0; i < 200; i++) {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error (iterate): %d\n", error);
            col_destroy_collection(peer);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) {
            COLOUT(printf("Reached end.\n\n"));
        }
        else {
            depth = 0;
            col_get_item_depth(iterator, &depth);
            COLOUT(printf("%*s", depth * 4, ""));
            COLOUT(col_debug_item(item));
        }
    }

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    col_unbind_iterator(iterator);
    col_destroy_collection(peer);

    return EOK;
}


int insert_extract_test(void)
{
    struct collection_item *col;
    struct collection_item *col2;
    int error = EOK;
    struct collection_item *item = NULL;

    COLOUT(printf("\n\n==== INSERTION TEST ====\n\n"));

    if ((error = col_create_collection(&col, "insertion", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_END,
                                         NULL, 0, COL_INSERT_NOCHECK,
                                         "property1", "value1", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_END,
                                         NULL, 0, COL_INSERT_NOCHECK,
                                         "property2", "value2", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_FRONT,
                                         NULL, 0, COL_INSERT_NOCHECK,
                                         "property0", "value0", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_BEFORE,
                                         "property0", 0, COL_INSERT_NOCHECK,
                                         "property_-1", "value_-1", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_BEFORE,
                                         "property1", 0, COL_INSERT_NOCHECK,
                                         "property0_5", "value0_5", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_BEFORE,
                                         "property2", 0, COL_INSERT_NOCHECK,
                                         "property1_5", "value1_5", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_AFTER,
                                         "property_-1", 0, COL_INSERT_NOCHECK,
                                         "property_-0_5", "value_-0_5", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_AFTER,
                                         "property1_5", 0, COL_INSERT_NOCHECK,
                                         "property1_6", "value1_6", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_INDEX,
                                         NULL, 10, COL_INSERT_NOCHECK,
                                         "property10", "value10", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_INDEX,
                                         NULL, 0, COL_INSERT_NOCHECK,
                                         "property_-2", "value_-2", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_INDEX,
                                         NULL, 1, COL_INSERT_NOCHECK,
                                         "property_-1_5", "value_-1_5", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_FIRSTDUP,
                                         NULL, 0, COL_INSERT_NOCHECK,
                                         "property0", "value0firstdup", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_LASTDUP,
                                         NULL, 0, COL_INSERT_NOCHECK,
                                         "property0", "value0lastdup", 0)) ||
        (error = col_insert_str_property(col, NULL, COL_DSP_NDUP,
                                         NULL, 1, COL_INSERT_NOCHECK,
                                         "property0", "value0middledup", 0)) ||
        (error = col_insert_str_property(col, NULL, 0,
                                         NULL, 0, COL_INSERT_DUPOVER ,
                                         "property0", "value0firstdupupdate", 0)) ||
        (error = col_insert_str_property(col, NULL, 0,
                                         NULL, 0, COL_INSERT_DUPOVERT,
                                         "property1", "value1update", 0)) ||
        ((error = col_insert_str_property(col, NULL, 0,
                                          NULL, 0, COL_INSERT_DUPERROR,
                                          "property0", "does not matter", 0)) != EEXIST) ||
         (error = col_insert_str_property(col, NULL, COL_DSP_NDUP,
                                          NULL, 5, COL_INSERT_NOCHECK,
                                          "property10", "value10dup", 0)) ||
         (error = col_insert_str_property(col, NULL, COL_DSP_LASTDUP,
                                          NULL, 0, COL_INSERT_NOCHECK,
                                          "property10", "value10lastdup", 0)) ||
         (error = col_insert_str_property(col, NULL, COL_DSP_END,
                                          NULL, 0, COL_INSERT_DUPMOVET,
                                          "property_-2", "value-2moved_to_bottom", 0)) ||
         (error = col_insert_str_property(col, NULL, COL_DSP_FRONT,
                                          NULL, 0, COL_INSERT_DUPMOVE,
                                          "property1_6", "value_1_6_moved_moved_to_front", 0))) {

        printf("ERROR in the ITERATION TEST\n");
        col_debug_collection(col, COL_TRAVERSE_DEFAULT);
        col_destroy_collection(col);
        return error;
    }

    COLOUT(printf("\n\nCollection:\n\n"));
    COLOUT(col_debug_collection(col, COL_TRAVERSE_DEFAULT));


    COLOUT(printf("\n\n==== EXTRACTION TEST ====\n\n"));

    if ((error = col_create_collection(&col2, "extraction", 0)) ||

        (error = col_extract_item(col, NULL, COL_DSP_FRONT,
                                  NULL, 0, 0, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_FRONT,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_extract_item(col, NULL, COL_DSP_END,
                                  NULL, 0, 0, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_insert_str_property(col, NULL, COL_DSP_INDEX,
                                         NULL, 100, COL_INSERT_NOCHECK,
                                         "property100", "value100", 0)) ||

        (error = col_extract_item(col, NULL, COL_DSP_AFTER,
                                  "property10", 0, COL_TYPE_STRING, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_extract_item(col, NULL, COL_DSP_BEFORE,
                                  "property0", 0, COL_TYPE_STRING, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_extract_item(col, NULL, COL_DSP_INDEX,
                                  NULL, 1, 0, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_extract_item(col, NULL, COL_DSP_NDUP,
                                  "property0", 1, 0, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_extract_item(col, NULL, COL_DSP_LASTDUP,
                                  "property0", 0, 0, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT))) ||

        (error = col_extract_item(col, NULL, COL_DSP_FIRSTDUP,
                                  "property0", 0, 0, &item)) ||

        (error = col_insert_item(col2, NULL, item, COL_DSP_END,
                                 NULL, 0, COL_INSERT_NOCHECK)) ||

        ((verbose) && (error = col_debug_collection(col2, COL_TRAVERSE_DEFAULT)))) {

        COLOUT(printf("ERROR in the EXTRACTION TEST\n"));
        COLOUT(printf("Collection 1\n"));
        COLOUT(col_debug_collection(col, COL_TRAVERSE_DEFAULT));
        COLOUT(printf("Collection 2\n"));
        COLOUT(col_debug_collection(col2, COL_TRAVERSE_DEFAULT));
        col_destroy_collection(col);
        col_destroy_collection(col2);
        return error;
    }

    COLOUT(printf("Collection 1\n"));
    COLOUT(col_debug_collection(col, COL_TRAVERSE_DEFAULT));
    COLOUT(printf("Collection 2\n"));
    COLOUT(col_debug_collection(col2, COL_TRAVERSE_DEFAULT));

    col_destroy_collection(col2);
    col_destroy_collection(col);


    return EOK;
}

int delete_test(void)
{

    struct collection_item *col;
    int error = EOK;

    COLOUT(printf("\n\n==== DELETION TEST 1====\n\n"));

    if ((error = col_create_collection(&col, "test", 0)) ||
        (error = col_add_int_property(col, NULL, "tt", 1)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_add_int_property(col, NULL, "test", 1)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_delete_property(col, "test", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_add_int_property(col, NULL, "test", 1)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_delete_property(col, "test", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_add_int_property(col, NULL, "test", 1))) {
        printf("Error in delete test %d\n", error);
        col_destroy_collection(col);
        return error;
    }

    COLOUT(col_debug_collection(col, COL_TRAVERSE_DEFAULT));
    col_destroy_collection(col);

    COLOUT(printf("\n\n==== DELETION TEST 1 END ====\n\n"));
    COLOUT(printf("\n\n==== DELETION TEST 2====\n\n"));

    if ((error = col_create_collection(&col, "test2", 0)) ||
        (error = col_add_int_property(col, NULL, "tt", 1)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_add_int_property(col, NULL, "test", 1)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_remove_item(col, NULL, COL_DSP_END, NULL, 0, COL_TYPE_ANY)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_add_int_property(col, NULL, "test", 1)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_remove_item_from_current(col, COL_DSP_AFTER, "tt", 0, COL_TYPE_ANY)) ||
        ((verbose) && (error = col_debug_collection(col, COL_TRAVERSE_DEFAULT))) ||
        (error = col_add_int_property(col, NULL, "test", 1))) {
        printf("Error in delete test %d\n", error);
        col_destroy_collection(col);
        return error;
    }

    COLOUT(col_debug_collection(col, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("\n\n==== DELETION TEST 2 END ====\n\n"));


    col_destroy_collection(col);

    return error;
}

/* Search test */
int search_test(void)
{
    struct collection_item *level1 = NULL;
    struct collection_item *level2 = NULL;
    struct collection_item *level3 = NULL;
    struct collection_item *level4 = NULL;
    char binary_dump[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    int found = 0;
    int error = 0;

    COLOUT(printf("\n\n==== SEARCH TEST ====\n\n"));

    if ((error = col_create_collection(&level1, "level1", 0)) ||
        (error = col_create_collection(&level2, "level2", 0)) ||
        (error = col_add_collection_to_collection(level1, NULL, NULL, level2, COL_ADD_MODE_REFERENCE)) ||
        (error = col_create_collection(&level3, "level3", 0)) ||
        (error = col_add_collection_to_collection(level1, "level2", NULL, level3, COL_ADD_MODE_REFERENCE)) ||
        (error = col_create_collection(&level4, "leveL4", 0)) ||
        (error = col_add_collection_to_collection(level1, "level3", NULL, level4, COL_ADD_MODE_REFERENCE)) ||
        (error = col_add_int_property(level1, "leveL4", "id", 1)) ||
        (error = col_add_long_property(level1, "level3", "packets", 100000000L)) ||
        (error = col_add_binary_property(level1, "level2", "stack", binary_dump, sizeof(binary_dump)))) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Failed to build test. Error %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    error = col_is_item_in_collection(level1, "level1!level2!level3!level4!", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if (!error) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Expected error here since the search data is illegal but got success\n");
        return EINVAL;
    }

    found = 0;
    error = 0;
    error = col_is_item_in_collection(level1, "level1!level2!level3!level4!id", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if ((error) || (!found)) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Failed to find item [level1!level2!level3!level4!id]. Error %d\n", error);
        return error ? error : ENOENT;
    }
    else COLOUT(printf("Expected item is found\n"));


    found = 0;
    error = 0;
    error = col_is_item_in_collection(level1, "level3!level4!id", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if ((error) || (!found)) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Failed to find item [level3!level4!id]. Error %d\n", error);
        return error ? error : ENOENT;
    }
    else COLOUT(printf("Expected item is found\n"));

    found = 0;
    error = 0;
    error = col_is_item_in_collection(level1, "level3!packets", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if ((error) || (!found)) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Failed to find item [level3.packets]. Error %d\n", error);
        return error ? error : ENOENT;
    }
    else COLOUT(printf("Expected item is found\n"));

    found = 0;
    error = 0;
    error = col_is_item_in_collection(level1, "level1!level2!stack", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if ((error) || (!found)) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Failed to find item [level1!level2!stack]. Error %d\n", error);
        return error ? error : ENOENT;
    }
    else COLOUT(printf("Expected item is found\n"));

    found = 0;
    error = 0;
    error = col_is_item_in_collection(level1, "level1!level2!level3", COL_TYPE_ANY, COL_TRAVERSE_DEFAULT, &found);
    if ((error) || (!found)) {
        col_destroy_collection(level1);
        col_destroy_collection(level2);
        col_destroy_collection(level3);
        col_destroy_collection(level4);
        printf("Failed to find item [level1!level2!level3]. Error %d\n", error);
        return error ? error : ENOENT;
    }
    else COLOUT(printf("Expected item is found\n"));

    col_destroy_collection(level1);
    col_destroy_collection(level2);
    col_destroy_collection(level3);
    col_destroy_collection(level4);

    COLOUT(printf("\n\n==== SEARCH TEST END ====\n\n"));

    return EOK;
}

/* Sort test */
int sort_test(void)
{
    struct collection_item *level1 = NULL;
    struct collection_item *level2a = NULL;
    struct collection_item *level2b = NULL;
    struct collection_item *level3 = NULL;
    int error = 0;

    COLOUT(printf("\n\n==== SORT TEST ====\n\n"));

    if ((error = col_create_collection(&level1, "level1", 0)) ||
        (error = col_create_collection(&level2a, "level2a", 0)) ||
        (error = col_add_collection_to_collection(level1, NULL, NULL, level2a, COL_ADD_MODE_REFERENCE)) ||
        (error = col_create_collection(&level2b, "level2b", 0)) ||
        (error = col_add_collection_to_collection(level1, NULL, NULL, level2b, COL_ADD_MODE_REFERENCE)) ||
        (error = col_create_collection(&level3, "level3", 0)) ||
        (error = col_add_collection_to_collection(level1, "level2a", NULL, level3, COL_ADD_MODE_REFERENCE)) ||
        (error = col_add_collection_to_collection(level1, "level2b", NULL, level3, COL_ADD_MODE_REFERENCE)) ||
        (error = col_add_int_property(level1, NULL, "int3", 1)) ||
        (error = col_add_int_property(level1, NULL, "int2", 2)) ||
        (error = col_add_int_property(level1, NULL, "int1", 3)) ||
        (error = col_add_bool_property(level1, NULL, "bool3", 1)) ||
        (error = col_add_bool_property(level1, NULL, "bool2", 1)) ||
        (error = col_add_bool_property(level1, NULL, "bool1", 0)) ||
        (error = col_add_unsigned_property(level1, NULL, "unsigned1", 2)) ||
        (error = col_add_unsigned_property(level1, NULL, "unsigned3", 1)) ||
        (error = col_add_unsigned_property(level1, NULL, "unsigned2", 3)) ||
        (error = col_add_long_property(level1, NULL, "long3", 1)) ||
        (error = col_add_long_property(level1, NULL, "long2", 2)) ||
        (error = col_add_long_property(level1, NULL, "long1", 3)) ||
        (error = col_add_ulong_property(level1, NULL, "ulong1", 2)) ||
        (error = col_add_ulong_property(level1, NULL, "ulong3", 1)) ||
        (error = col_add_ulong_property(level1, NULL, "ulong2", 3)) ||
        (error = col_add_double_property(level1, NULL, "double1", 2.2)) ||
        (error = col_add_double_property(level1, NULL, "double3", 1.1)) ||
        (error = col_add_double_property(level1, NULL, "double2", 3.3)) ||
        (error = col_add_int_property(level3, NULL, "int3L3", 1)) ||
        (error = col_add_int_property(level3, NULL, "int2L3", 2)) ||
        (error = col_add_int_property(level3, NULL, "int1L3", 3)) ||
        (error = col_add_unsigned_property(level1, "level2a!level3", "unsigned1L3", 2)) ||
        (error = col_add_unsigned_property(level1, "level2a!level3", "unsigned3L3", 1)) ||
        (error = col_add_unsigned_property(level1, "level2a!level3", "unsigned2L3", 3)) ||
        (error = col_add_long_property(level1, "level2b!level3", "long3L3", 1)) ||
        (error = col_add_long_property(level1, "level2b!level3", "long2L3", 2)) ||
        (error = col_add_long_property(level1, "level2b!level3", "long1L3", 3)) ||
        (error = col_add_ulong_property(level1, "level3", "ulong1L3", 2)) ||
        (error = col_add_ulong_property(level1, "level3", "ulong3L3", 1)) ||
        (error = col_add_ulong_property(level1, "level3", "ulong2L3", 3)) ||
        (error = col_add_bool_property(level3, NULL, "bool3", 1)) ||
        (error = col_add_bool_property(level3, NULL, "bool2", 1)) ||
        (error = col_add_bool_property(level3, NULL, "bool1", 0)) ||
        (error = col_add_double_property(level3, NULL, "double1L3", 2.2)) ||
        (error = col_add_double_property(level3, NULL, "double3L3", 1.1)) ||
        (error = col_add_double_property(level3, NULL, "double2L3", 3.3))) {
        col_destroy_collection(level1);
        col_destroy_collection(level2a);
        col_destroy_collection(level2b);
        col_destroy_collection(level3);
        printf("Failed to build test. Error %d\n", error);
        return error;
    }

    COLOUT(printf("\nUNSORTED COLLECTION\n\n"));
    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    error = col_sort_collection(level1, COL_CMPIN_PROP_EQU, COL_SORT_SUB | COL_SORT_MYSUB);
    if (error) {
        col_destroy_collection(level1);
        col_destroy_collection(level2a);
        col_destroy_collection(level2b);
        col_destroy_collection(level3);
        printf("Failed sort. Error %d\n", error);
        return error;
    }

    COLOUT(printf("\nSORTED BUT SKIPPING REFERENCES\n\n"));
    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    error = col_sort_collection(level1, COL_CMPIN_PROP_EQU, COL_SORT_SUB);
    if (error) {
        col_destroy_collection(level1);
        col_destroy_collection(level2a);
        col_destroy_collection(level2b);
        col_destroy_collection(level3);
        printf("Failed sort. Error %d\n", error);
        return error;
    }

    COLOUT(printf("\nSORTED BUT NOT SKIPPING REFERENCES\n\n"));
    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    error = col_sort_collection(level1, COL_CMPIN_DATA_LEN, COL_SORT_SUB | COL_SORT_DESC);
    if (error) {
        col_destroy_collection(level1);
        col_destroy_collection(level2a);
        col_destroy_collection(level2b);
        col_destroy_collection(level3);
        printf("Failed sort. Error %d\n", error);
        return error;
    }

    COLOUT(printf("\nSORTED DESC NOT SKIPPING BY LENGTH OF DATA\n\n"));
    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    error = col_sort_collection(level1, COL_CMPIN_PROP_LEN, COL_SORT_SUB | COL_SORT_DESC);
    if (error) {
        col_destroy_collection(level1);
        col_destroy_collection(level2a);
        col_destroy_collection(level2b);
        col_destroy_collection(level3);
        printf("Failed sort. Error %d\n", error);
        return error;
    }

    COLOUT(printf("\nSORTED DESC NOT SKIPPING BY LENGTH OF PROPERTY\n\n"));
    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    error = col_sort_collection(level1, COL_CMPIN_DATA, COL_SORT_SUB | COL_SORT_DESC);
    if (error) {
        col_destroy_collection(level1);
        col_destroy_collection(level2a);
        col_destroy_collection(level2b);
        col_destroy_collection(level3);
        printf("Failed sort. Error %d\n", error);
        return error;
    }

    COLOUT(printf("\nSORTED DESC NOT SKIPPING BY DATA\n\n"));
    COLOUT(col_debug_collection(level1, COL_TRAVERSE_DEFAULT));

    col_destroy_collection(level1);
    col_destroy_collection(level2a);
    col_destroy_collection(level2b);
    col_destroy_collection(level3);

    COLOUT(printf("\n\n==== SORT TEST END ====\n\n"));

    return EOK;
}

/* Main function of the unit test */

int main(int argc, char *argv[])
{
    int error = 0;
    test_fn tests[] = { ref_collection_test,
                        single_collection_test,
                        add_collection_test,
                        mixed_collection_test,
                        iterator_test,
                        insert_extract_test,
                        delete_test,
                        search_test,
                        sort_test,
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

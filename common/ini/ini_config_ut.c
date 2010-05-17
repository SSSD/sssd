/*
    INI LIBRARY

    Unit test for the INI library.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#define TRACE_HOME
#include "trace.h"
#include "ini_config.h"
#include "collection.h"
#include "collection_tools.h"


int verbose = 0;

#define COLOUT(foo) \
    do { \
        if (verbose) foo; \
    } while(0)


int basic_test(void)
{
    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *error_set = NULL;

    error = config_for_app("test", NULL, NULL,
                           &ini_config, INI_STOP_ON_NONE, &error_set);
    if (error != EINVAL) {
        printf("Expected error EINVAL got somethign else: %d\n", error);
        return EINVAL;
    }

    error = config_for_app("test", "foo", "bar",
                           &ini_config, INI_STOP_ON_ANY, &error_set);
    if (error != ENOENT) {
        printf("Expected error ENOENT got somethign else: %d\n", error);
        return ENOENT;
    }

    error = config_for_app("test", "./ini.conf", "./ini.d",
                           &ini_config, INI_STOP_ON_NONE, &error_set);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(ini_config,COL_TRAVERSE_DEFAULT));
    COLOUT(col_print_collection(ini_config));
    COLOUT(col_print_collection(error_set));

    COLOUT(printf("\n\n----------------------\n"));
    /* Output parsing errors (if any) */
    COLOUT(print_config_parsing_errors(stdout, error_set));
    COLOUT(printf("----------------------\n\n\n"));


    free_ini_config(ini_config);
    free_ini_config_errors(error_set);
    return 0;
}

int single_file(void)
{
    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *error_set = NULL;
    struct collection_item *metadata = NULL;
    uint32_t flags;

    error = config_from_file("test", "./not_exist_ini.conf",
                             &ini_config, INI_STOP_ON_NONE, &error_set);
    if (error) {
        COLOUT(printf("Attempt to read configuration returned error: %d."
                      " EXPECTED.\n\n", error));
        if(error != ENOENT) return error;
    }

    error = config_from_file("test",
                             "./ini.conf",
                             &ini_config,
                             INI_STOP_ON_NONE,
                             &error_set);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n", error);
        return error;
    }

    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));
    COLOUT(col_print_collection(ini_config));
    COLOUT(col_print_collection(error_set));

    COLOUT(printf("\n\n----------------------\n"));
    /* Output parsing errors (if any) */
    COLOUT(print_file_parsing_errors(stdout, error_set));
    COLOUT(printf("----------------------\n\n\n"));


    free_ini_config(ini_config);
    free_ini_config_errors(error_set);

    ini_config = NULL;
    error_set = NULL;

    COLOUT(printf("TEST WITH METADATA NO PARSE\n"));
    flags = INI_META_SEC_ACCESS_FLAG |
            INI_META_SEC_ERROR_FLAG  |
            INI_META_ACTION_NOPARSE;

    error = config_from_file_with_metadata("test", "./ini.conf",
                                           &ini_config, INI_STOP_ON_NONE,
                                           NULL,
                                           flags,
                                           &metadata);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        if (metadata) {
            printf("\n\nMeta data\n");
            col_debug_collection(metadata, COL_TRAVERSE_DEFAULT);
        }
        free_ini_config_metadata(metadata);
        return error;
    }

    if (ini_config) {
        printf("Expected no config but got some.\n");
        col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT);
        free_ini_config(ini_config);
        printf("\n\nMeta data\n");
        col_debug_collection(metadata, COL_TRAVERSE_DEFAULT);
        free_ini_config_metadata(metadata);
        return EINVAL;
    }

    COLOUT(printf("\n\nMeta data\n"));
    COLOUT(col_debug_collection(metadata, COL_TRAVERSE_DEFAULT));
    free_ini_config_metadata(metadata);

    COLOUT(printf("\n\n----------------------\n"));

    error = config_from_file_with_metadata("test", "./ini.conf",
                                           &ini_config, INI_STOP_ON_NONE,
                                           &error_set,
                                           0,
                                           NULL);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        print_file_parsing_errors(stdout, error_set);
        free_ini_config_errors(error_set);
        return error;
    }

    COLOUT(printf("\n\n----------------------\n"));
    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("\n\n----------------------\n"));
    /* Output parsing errors (if any) */
    COLOUT(print_file_parsing_errors(stdout, error_set));
    COLOUT(printf("----------------------\n\n\n"));


    free_ini_config(ini_config);
    free_ini_config_errors(error_set);

    return 0;
}

int single_fd(void)
{
    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *error_set = NULL;
    struct collection_item *metadata = NULL;
    uint32_t flags;

    int fd = open("./ini.conf", O_RDONLY);
    if (fd < 0) {
        error = errno;
        printf("Attempt to read configuration returned error: %d\n", error);
        return error;
    }

    error = config_from_fd("test", fd, "./ini.conf", &ini_config,
                           INI_STOP_ON_NONE, &error_set);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        return error;
    }

    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));
    COLOUT(col_print_collection(ini_config));
    COLOUT(col_print_collection(error_set));

    COLOUT(printf("\n\n----------------------\n"));
    /* Output parsing errors (if any) */
    COLOUT(print_file_parsing_errors(stdout, error_set));
    COLOUT(printf("----------------------\n\n\n"));


    free_ini_config(ini_config);
    free_ini_config_errors(error_set);
    close(fd);

    ini_config = NULL;
    error_set = NULL;

    COLOUT(printf("TEST WITH FILE FD & META DATA\n"));

    fd = open("./ini.conf", O_RDONLY);
    if (fd < 0) {
        error = errno;
        printf("Attempt to read configuration returned error: %d\n", error);
        return error;
    }

    flags = INI_META_SEC_ACCESS_FLAG |
            INI_META_SEC_ERROR_FLAG  |
            INI_META_ACTION_NOPARSE;

    error = config_from_fd_with_metadata("test", fd,
                                         "./ini.conf",
                                         &ini_config,
                                         INI_STOP_ON_NONE,
                                         &error_set,
                                         flags,
                                         &metadata);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        printf("\n\nErrors\n");
        print_file_parsing_errors(stdout, error_set);
        free_ini_config_errors(error_set);
        if (metadata) {
            printf("\n\nMeta data\n");
            col_debug_collection(metadata, COL_TRAVERSE_DEFAULT);
        }
        free_ini_config_metadata(metadata);
        return error;
    }

    if (ini_config) {
        printf("Expected no config but got some.\n");
        col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT);
        free_ini_config(ini_config);
        return EINVAL;
    }


    COLOUT(printf("\n\nMeta data\n"));
    COLOUT(col_debug_collection(metadata, COL_TRAVERSE_DEFAULT));
    free_ini_config_metadata(metadata);


    error = config_from_fd_with_metadata("test", fd,
                                         "./ini.conf",
                                         &ini_config,
                                         INI_STOP_ON_NONE,
                                         &error_set,
                                         0,
                                         NULL);

    close(fd);

    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        printf("\n\nErrors\n");
        print_file_parsing_errors(stdout, error_set);
        free_ini_config_errors(error_set);
        return error;
    }

    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("\n\n----------------------\n"));
    /* Output parsing errors (if any) */
    COLOUT(print_file_parsing_errors(stdout, error_set));
    COLOUT(printf("----------------------\n\n\n"));


    free_ini_config(ini_config);
    free_ini_config_errors(error_set);

    return 0;
}

int negative_test(void)
{
    int error;
    unsigned int count;
    struct collection_item *ini_config = NULL;

    /* App name is null - expect failure */
    error = config_for_app(NULL,
                           NULL,
                           NULL,
                           NULL,
                           INI_STOP_ON_NONE,
                           NULL);
    if (!error) {
        printf("Expected error: %d got success\n", EINVAL);
        return -1;
    }

    /* Config collection storage is NULL - expect failure */
    error = config_for_app("real",
                           NULL,
                           NULL,
                           NULL,
                           INI_STOP_ON_NONE,
                           NULL);
    if (!error) {
        printf("Expected error: %d got success\n", EINVAL);
        return -1;
    }

    /* Config collection storage is NULL - expect failure */
    error = config_for_app("real",
                           "real.conf",
                           NULL,
                           NULL,
                           INI_STOP_ON_NONE,
                           NULL);
    if (!error) {
        printf("Expected error: %d got success\n", EINVAL);
        return -1;
    }

    /* Expect success but empty config */
    error = config_for_app("real",
                           "real.conf",
                           NULL,
                           &ini_config,
                           INI_STOP_ON_NONE,
                           NULL);
    if (error) {
        printf("Expected success got error: %d\n",error);
        return error;
    }

    count = 0;
    (void)col_get_collection_count(ini_config, &count);
    if (count > 1) {
        printf("Expected empty collection but"
               " got contents with %d elements\n", count);
        col_print_collection(ini_config);
        return -1;
    }

    free_ini_config(ini_config);
    return 0;

}

int real_test(const char *file)
{
    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *error_set = NULL;
    struct collection_iterator *iterator = NULL;
    struct collection_item *item = NULL;
    int type;

    COLOUT(printf("\n\n===== REAL TEST START ======\n"));
    COLOUT(printf("Reading collection\n"));
    error = config_for_app("real", file, "./ini.d",
                           &ini_config, INI_STOP_ON_NONE, &error_set);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n", error);
        return error;
    }

    COLOUT(printf("Debugging the config collection:\n"));
    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));
    COLOUT(printf("Debugging the error collection:\n"));
    COLOUT(col_debug_collection(error_set, COL_TRAVERSE_DEFAULT));

    COLOUT(printf("About to print parsing errors:\n"));
    COLOUT(printf("\n\n----------------------\n"));
    /* Output parsing errors (if any) */
    COLOUT(print_config_parsing_errors(stdout, error_set));
    COLOUT(printf("----------------------\n\n\n"));

    COLOUT(printf("About to bind iterator to print"
                  " the config file contents.\n"));
    /* Bind iterator */
    error =  col_bind_iterator(&iterator, ini_config,
                           COL_TRAVERSE_DEFAULT|COL_TRAVERSE_END);
    if (error) {
        printf("Failed to bind iterator: %d\n",error);
        col_destroy_collection(ini_config);
        col_destroy_collection(error_set);
        return error;
    }

    COLOUT(printf("About to start iteration loop.\n"));
    do {
        /* Loop through a collection */
        error = col_iterate_collection(iterator, &item);
        if (error) {
            printf("Error iterating collection: %d", error);
            col_unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if (item == NULL) break;

        type = col_get_item_type(item);

        /* Start of the collection */
        if (type == COL_TYPE_COLLECTION)
            COLOUT(printf("Contents of the application's configuration %s\n",
                          col_get_item_property(item, NULL)));
        /* End of section */
        else if (type == COL_TYPE_END) COLOUT(printf("\n"));
        /* Section header ? */
        else if (type == COL_TYPE_COLLECTIONREF)
            COLOUT(printf("[%s]\n", col_get_item_property(item, NULL)));
        /* Anything else - we know they are all strings*/
        else
            COLOUT(printf("%s = %s\n",
                          col_get_item_property(item, NULL),
                          (char *)col_get_item_data(item)));
    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
    COLOUT(printf("About to clean up.\n"));
    col_unbind_iterator(iterator);

    free_ini_config(ini_config);
    free_ini_config_errors(error_set);
    return 0;
}

int get_test(void)
{

    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *error_set = NULL;
    struct collection_item *item = NULL;
    int number;
    long number_long;
    double number_double;
    unsigned number_unsigned;
    unsigned long number_ulong;
    unsigned char logical;
    char *str;
    const char *cstr;
    const char *cstrn;
    void *binary;
    int length;
    int i = 0;
    char **strarray;
    char **strptr;
    int size;
    long *array;
    double *darray;
    char **prop_array;
    int32_t val_int32;
    uint32_t val_uint32;
    int64_t val_int64;
    uint64_t val_uint64;


    COLOUT(printf("\n\n===== GET TEST START ======\n"));
    COLOUT(printf("Reading collection\n"));

    error = config_for_app("real", NULL, "./ini.d",
                           &ini_config, INI_STOP_ON_NONE, &error_set);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n", error);
        return error;
    }

    COLOUT(printf("Debugging the config collection:\n"));
    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));
    COLOUT(printf("Debugging the error collection:\n"));
    COLOUT(col_debug_collection(error_set, COL_TRAVERSE_DEFAULT));
    free_ini_config_errors(error_set);

    COLOUT(printf("Negtive test - trying to get non"
                  " existing key-value pair.\n"));

    /* Negative test */
    item = NULL;
    error = get_config_item("monitor1", "description1", ini_config, &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should not be found */
    if (item != NULL) {
        printf("Expected NULL but got something else!\n");
        free_ini_config(ini_config);
        return -1;
    }

    /* Another negative test but section exists this time */
    item = NULL;
    error = get_config_item("monitor", "description1", ini_config, &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should not be found */
    if(item != NULL) {
        printf("Expected NULL but got something else!\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Trying to get an item.\n"));

    /* Positive test */
    item = NULL;
    error = get_config_item("monitor", "description", ini_config, &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected item but got something NULL!\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    COLOUT(printf("Get item as string without duplication"
                  " from the NULL item.\n"));

    /* Get a string without duplicication */
    /* Negative test */
    cstrn = get_const_string_config_value(NULL, NULL);
    if (cstrn != NULL) {
        printf("Expected error got success.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Get item as string without duplication"
                  "from the correct item.\n"));

    /* Now get string from the right item */
    error = 0;
    cstr = get_const_string_config_value(item, &error);
    if (error) {
        printf("Expected success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    COLOUT(printf("Value: [%s]\n", cstr));

    /* Same thing but create a dup */

    COLOUT(printf("Get item as string with duplication"
                  " from correct item.\n"));

    error = 0;
    str = get_string_config_value(item, &error);
    if (error) {
        printf("Expected success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    COLOUT(printf("Value: [%s]\n", str));
    free(str);


    /* Get a badly formated number */
    COLOUT(printf("Convert item to number with strict conversion.\n"));

    item = NULL;
    error = get_config_item("monitor", "bad_number", ini_config, &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected item but got something NULL!\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));


    /* Now try to get value in different ways */
    error = 0;
    number = get_int_config_value(item, 1, 10, &error);
    if (error) {
        /* We expected error in this case */
        COLOUT(printf("Expected error.\n"));
        if(number != 10) {
            printf("It failed to set default value.\n");
            free_ini_config(ini_config);
            return -1;
        }
    }

    COLOUT(printf("Convert item to number without strict conversion.\n"));

    error = 0;
    number = 1;
    number = get_int_config_value(item, 0, 10, &error);
    if (error) {
        /* We expected error in this case */
        printf("Did not expect error.\n");
        free_ini_config(ini_config);
        return error;
    }

    if (number != 5) {
        /* We expected error in this case */
        printf("We expected that the conversion will return 5.\n");
        free_ini_config(ini_config);
        return -1;
    }

    /* Get real integer */

    COLOUT(printf("Fetch another item from section \"domains/LOCAL\""
                  " named \"enumerate\".\n"));

    item = NULL;
    error = get_config_item("domains/LOCAL","enumerate", ini_config, &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Convert item to integer.\n"));

    /* Take number out of it */
    error = 0;
    number = get_int_config_value(item, 1, 100, &error);
    if (error) {
        printf("Did not expect error. Got %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if (number != 3) {
        printf("We expected that the conversion will return 3.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Expected 3 got %d\n", number));

    COLOUT(printf("Convert item to long.\n"));

    /* Take number out of it */
    error = 0;
    number_long = get_long_config_value(item, 1, 100, &error);
    if (error) {
        printf("Did not expect error. Got %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if (number_long != 3) {
        printf("We expected that the conversion will return 3.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Expected 3 got %ld\n", number_long));

    COLOUT(printf("Convert item to unsigned.\n"));

    /* Take number out of it */
    error = 0;
    number_unsigned = get_unsigned_config_value(item, 1, 100, &error);
    if (error) {
        printf("Did not expect error. Got %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if(number_unsigned != 3) {
        printf("We expected that the conversion will return 3.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Expected 3 got %d\n", number_unsigned));

    COLOUT(printf("Convert item to unsigned long.\n"));

    /* Take number out of it */
    error = 0;
    number_ulong = get_ulong_config_value(item, 1, 100, &error);
    if (error) {
        printf("Did not expect error. Got %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if (number_ulong != 3) {
        printf("We expected that the conversion will return 3.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Expected 3 got %lu\n", number_ulong));

    COLOUT(printf("Convert item to double.\n"));

    /* Take number out of it */
    error = 0;
    number_double = get_double_config_value(item, 1, 100., &error);
    if (error) {
        printf("Did not expect error. Got %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if (number_double != 3.) {
        printf("We expected that the conversion will return 3.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Expected 3 got %e\n", number_double));

    COLOUT(printf("Convert item to bool.\n"));

    /* Take number out of it */
    error = 0;
    logical = get_bool_config_value(item, 1, &error);
    if (!error) {
        printf("Expect error. Got success.\n");
        free_ini_config(ini_config);
        return -1;
    }

    /* Get real bool item and convert it */
    COLOUT(printf("Get real bool item \"legacy\" and convert it.\n"));

    item = NULL;
    error = get_config_item("domains/LOCAL","legacy", ini_config, &item);
    if (error) {
        printf("Expected success but got error! %d\n",error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(printf("Convert item to bool.\n"));

    error = 0;
    logical = get_bool_config_value(item, 1, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    if (logical) {
        printf("Expected false but got true - bad.\n");
        return -1;
    }

    COLOUT(printf("In the files it is FALSE so we got false.\n"));

    COLOUT(printf("Get binary item\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "binary_test",
                            ini_config,
                            &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    binary = get_bin_config_value(item, &length, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    COLOUT(printf("Binary value (expect 123) = "));
    COLOUT(for (i=0;i<length;i++) {
                printf("%d",*((unsigned char*)(binary)+i));
           });
    COLOUT(printf("\n"));

    free_bin_config_value(binary);

    COLOUT(printf("Get string array item\n"));

    item = NULL;
    error = get_config_item("domains", "domainsorder", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    COLOUT(printf("Get str array without size.\n"));

    error = 0;
    strarray = get_string_config_array(item, ",", NULL, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    strptr = strarray;
    while (*strptr != NULL) {
        COLOUT(printf("[%s]\n",*strptr));
        strptr++;
    }

    free_string_config_array(strarray);

    COLOUT(printf("Get raw str array without size.\n"));

    error = 0;
    strarray = get_raw_string_config_array(item, ",", NULL, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    strptr = strarray;
    while (*strptr != NULL) {
        COLOUT(printf("[%s]\n",*strptr));
        strptr++;
    }

    free_string_config_array(strarray);

    COLOUT(printf("Get str array with size.\n"));

    error = 0;
    size = 0;
    strarray = get_string_config_array(item, ",", &size, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    COLOUT(for (i=0;i<size;i++) printf("[%s]\n",*(strarray + i)));

    free_string_config_array(strarray);

    COLOUT(printf("Get raw str array with size.\n"));

    error = 0;
    size = 0;
    strarray = get_raw_string_config_array(item, ",", &size, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    COLOUT(for (i=0;i<size;i++) printf("[%s]\n",*(strarray + i)));

    free_string_config_array(strarray);

    COLOUT(printf("Get long array item\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "long_array",
                            ini_config,
                            &item);
    if(error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    size = 0; /* Here size is not optional!!! */
    array = get_long_config_array(item, &size, &error);
    if(error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    COLOUT(for (i=0;i<size;i++) printf("%ld\n", *(array + i)));

    free_long_config_array(array);

    COLOUT(printf("Get double array item\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "double_array",
                            ini_config,
                            &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    size = 0; /* Here size is not optional!!! */
    darray = get_double_config_array(item, &size, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    COLOUT(for (i=0;i<size;i++) printf("%.4f\n", darray[i]));

    free_double_config_array(darray);

    COLOUT(printf("\n\nSection list - no size\n"));

    /* Do not care about the error or size */
    prop_array = get_section_list(ini_config, NULL, NULL);
    if (prop_array == NULL) {
        printf("Expect success got error.\n");
        free_ini_config(ini_config);
        return -1;
    }

    i = 0;
    COLOUT(while (prop_array[i]) {
               printf("Section: [%s]\n", prop_array[i]);
               i++;
           });

    free_section_list(prop_array);

    COLOUT(printf("\n\nSection list - with size\n"));

    /* Do not care about the error or size */
    prop_array = get_section_list(ini_config, &size, NULL);
    if (prop_array == NULL) {
        printf("Expect success got error.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(for (i=0;i<size;i++) printf("Section: [%s]\n", prop_array[i]));
    free_section_list(prop_array);

    COLOUT(printf("\n\nAttributes in the section - with size and error\n"));

    /* Do not care about the error or size */
    prop_array = get_attribute_list(ini_config,
                                    "domains/EXAMPLE.COM",
                                    &size,
                                    &error);
    if (prop_array == NULL) {
        printf("Expect success got error.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(for (i=0;i<size;i++) printf("Attribute: [%s]\n", prop_array[i]));
    free_attribute_list(prop_array);


    /***************************************/
    /* Test special types                  */
    /***************************************/
    COLOUT(printf("Test int32_t\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "int32_t",
                            ini_config,
                            &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    val_int32 = get_int32_config_value(item, 1, 0, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    COLOUT(printf("Value: %d\n", val_int32));

    /***************************************/

    COLOUT(printf("Test uint32_t\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "uint32_t",
                            ini_config,
                            &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    val_uint32 = get_uint32_config_value(item, 1, 0, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
   }

    COLOUT(printf("Value: %u\n", val_uint32));

    /***************************************/

    COLOUT(printf("Test int64_t\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "int64_t",
                            ini_config,
                            &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    val_int64 = get_int64_config_value(item, 1, 0, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    COLOUT(printf("Value: %lld\n", (long long)val_int64));

    /***************************************/

    COLOUT(printf("Test uint32_t\n"));

    item = NULL;
    error = get_config_item("domains/EXAMPLE.COM",
                            "uint64_t",
                            ini_config,
                            &item);
    if (error) {
        printf("Expected success but got error! %d\n", error);
        free_ini_config(ini_config);
        return error;
    }

    /* Item should be found */
    if (item == NULL) {
        printf("Expected success but got NULL.\n");
        free_ini_config(ini_config);
        return -1;
    }

    COLOUT(col_debug_item(item));

    error = 0;
    val_uint64 = get_uint64_config_value(item, 1, 0, &error);
    if (error) {
        printf("Expect success got error %d.\n", error);
        free_ini_config(ini_config);
        return error;
    }

    COLOUT(printf("Value: %llu\n", (unsigned long long)val_uint64));

    /***************************************/

    free_ini_config(ini_config);
    COLOUT(printf("Done with get test!\n"));
    return EOK;
}

/* This is an emulation of the case when daemon starts
 * and one needs to parse the configuration file
 * for the first time and load configuration
 */
int startup_test(void)
{
    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *error_set = NULL;
    struct collection_item *metadata = NULL;
    uint32_t flags;


    /* At startup we can simplify our life by
     * parsing configuration and then checking
     * the permissions. It is less optimal from
     * the performnce point of view but simple to implement.
     * Since it is the start of the daemon we can
     * hope that parsing the config file would
     * usually not a be a wasted effort.
     * If permission check fails that means we should
     * exit. Ok so we just parse the INI file for nothing.
     * Not a big deal, I would say...
     */

    COLOUT(printf("STARTUP TEST\n"));

    /* Set file permissions to 0664 */
    chmod("./ini.conf", 0664);

    flags = INI_META_SEC_ACCESS_FLAG |
            INI_META_SEC_ERROR_FLAG;

    error = config_from_file_with_metadata("test", "./ini.conf",
                                           &ini_config, INI_STOP_ON_NONE,
                                           &error_set,
                                           flags,
                                           &metadata);
    /*
     * This is just for debugging.
     * do not copy into your implementation
     */
    if (metadata) {
        COLOUT(printf("\n\nMeta data\n"));
        COLOUT(col_debug_collection(metadata, COL_TRAVERSE_DEFAULT));
    }


    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);

        /* If you want to do any specific error checking, do it here.
         * If you want to get the file error code from the
         * metadata get it here.
         */
        free_ini_config_metadata(metadata);

        /* Error reporting start ==> */
        if (error_set) {
            printf("\n\nErrors\n");
            col_debug_collection(error_set, COL_TRAVERSE_DEFAULT);
        }
        /* <==== end */
        free_ini_config_errors(error_set);
        return error;
    }

    free_ini_config_errors(error_set);

    /* So we are here if we successfully got configuration. */
    /* You can check ownership and permissions here in one call */
    /* We will check just permissions here. */
    error = config_access_check(metadata,
                                INI_ACCESS_CHECK_MODE, /* add uid & gui flags
                                                        * in real case
                                                        */
                                0, /* <- will be real uid in real case */
                                0, /* <- will be real gid in real case */
                                0440, /* Checking for r--r----- */
                                0);
    /* This check is expected to fail since
     * the actual permissions on the test file are: rw-rw-r--
     */

    if (!error) {
        printf("Expected error got success!\n");
        free_ini_config_metadata(metadata);
        free_ini_config(ini_config);
        return EACCES;
    }

    error = config_access_check(metadata,
                                INI_ACCESS_CHECK_MODE, /* add uid & gui flags
                                                        * in real case
                                                        */
                                0, /* <- will be real uid in real case */
                                0, /* <- will be real gid in real case */
                                0664, /* Checkling for rw-rw-r-- */
                                0);

    if (error) {
        printf("Access check failed %d!\n", error);
        free_ini_config_metadata(metadata);
        free_ini_config(ini_config);
        return EACCES;
    }


    /* Use configuration */

    COLOUT(printf("\n\nMeta data\n"));
    COLOUT(col_debug_collection(metadata, COL_TRAVERSE_DEFAULT));
    free_ini_config_metadata(metadata);

    COLOUT(printf("\n\n----------------------\n"));

    COLOUT(printf("\n\nConfiguration\n"));
    COLOUT(col_debug_collection(ini_config, COL_TRAVERSE_DEFAULT));
    free_ini_config(ini_config);

    return 0;
}

int reload_test(void)
{

    int error;
    struct collection_item *ini_config = NULL;
    struct collection_item *metadata = NULL;
    struct collection_item *saved_metadata = NULL;
    uint32_t flags;
    int changed = 0;
    int fd;

    COLOUT(printf("RELOAD TEST\n"));

    /* Assume we saved metadata at the beginning
     * when we opened the file and read configuration
     * for the first time.
     * Here we have to emulate it.
     */

    flags = INI_META_SEC_ACCESS_FLAG |
            INI_META_ACTION_NOPARSE;

    error = config_from_file_with_metadata("test", "./ini.conf",
                                           &ini_config,
                                           0,
                                           NULL,
                                           flags,
                                           &saved_metadata);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        free_ini_config_metadata(saved_metadata);
        return error;
    }

    /*****************************************/

    /* We are reloading so we probably doing it becuase
     * we got a signal ot some kind of time out expired
     * and it might be time for us to check if we need
     * to reload. So assume it is time to check...
     */

    /* It is safer to open file first */
    fd = open("./ini.conf", O_RDONLY);
    if (fd < 0) {
        error = errno;
        printf("Attempt to read configuration returned error: %d\n", error);
        free_ini_config_metadata(saved_metadata);
        return error;
    }

    /* You migth be checking pretty frequently, once in 5 min for example
     * but the config usually does not change for months
     * so you do not want to do any extra processing every time you check.
     */

    /* Do permission check here right away on the file, or... */


    flags = INI_META_SEC_ACCESS_FLAG |
            INI_META_ACTION_NOPARSE;

    error = config_from_fd_with_metadata("test", fd,
                                         "./ini.conf",
                                         &ini_config,
                                         0,
                                         NULL,
                                         flags,
                                         &metadata);
    if (error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        if (metadata) {
            printf("\n\nMeta data\n");
            col_debug_collection(metadata, COL_TRAVERSE_DEFAULT);
        }
        free_ini_config_metadata(metadata);
        free_ini_config_metadata(saved_metadata);
        close(fd);
        return error;
    }

    /* ...or you can do permission check here using the metadata
     * as it is done in the startup test.
     * For now we skip this part and move on.
     */

    error = config_changed(metadata, saved_metadata, &changed);

    if (error) {
        printf("Internal error: %d\n",error);
        printf("\n\nSaved Meta data\n");
        col_debug_collection(saved_metadata, COL_TRAVERSE_DEFAULT);
        printf("\n\nMeta data\n");
        col_debug_collection(metadata, COL_TRAVERSE_DEFAULT);
        free_ini_config_metadata(saved_metadata);
        free_ini_config_metadata(metadata);
        close(fd);
        return error;

    }

    if (changed) {

        /* Read the config from the descriptor and use it.
         * Discard old saved meta data and save
         * the latest one for future use...
         */

        /* Here it would be an error if it is different */
        printf("Meta data is supposed to be same but different.\n");
        printf("\n\nSaved Meta data\n");
        col_debug_collection(saved_metadata, COL_TRAVERSE_DEFAULT);
        printf("\n\nMeta data\n");
        col_debug_collection(metadata, COL_TRAVERSE_DEFAULT);
    }

    free_ini_config_metadata(saved_metadata);
    free_ini_config_metadata(metadata);
    close(fd);

    return 0;
}


int main(int argc, char *argv[])
{
    int error = EOK;
    char *srcdir = NULL;

    if ((argc > 1) && (strcmp(argv[1], "-v") == 0)) verbose = 1;

    COLOUT(printf("Start\n"));

    srcdir = getenv("srcdir");
    if(srcdir) {
        if(chdir(srcdir) != 0) {
            error = errno;
            printf("Failed to change directory, error %d\n", error);
            return error;
        }
    }

    if ((error = basic_test()) ||
        (error = single_file()) ||
        (error = single_fd()) ||
        (error = real_test(NULL)) ||
         /* This should result in merged configuration */
        (error = real_test("./ini.conf")) ||
        (error = startup_test()) ||
        (error = reload_test()) ||
        (error = get_test())) {
        printf("Test failed! Error %d.\n", error);
        return -1;
    }

    COLOUT(printf("Success!\n"));
    return 0;
}

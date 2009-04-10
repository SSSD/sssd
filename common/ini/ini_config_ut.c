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
#include <errno.h>
#define TRACE_HOME
#include "ini_config.h"
#include "collection.h"
#include "collection_tools.h"


int basic_test()
{
    int error;
    struct collection_item *ini_config = (struct collection_item *)(NULL);
    struct collection_item *error_set = (struct collection_item *)(NULL);

    error = config_for_app("test", "./ini/ini.conf", "./ini/ini.d", &ini_config,INI_STOP_ON_NONE,&error_set);
    if(error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        return error;
    }

    debug_collection(ini_config,COL_TRAVERSE_DEFAULT);
    print_collection(ini_config);
    print_collection(error_set);

	printf("\n\n----------------------\n");
    /* Output parsing errors (if any) */
    print_config_parsing_errors(stdout,error_set);
	printf("----------------------\n\n\n");


    destroy_collection(ini_config);
    destroy_collection(error_set);
    return 0;
}

int single_file()
{
    int error;
    struct collection_item *ini_config = (struct collection_item *)(NULL);
    struct collection_item *error_set = (struct collection_item *)(NULL);

    error = config_from_file("test", "./ini/ini.conf", &ini_config,INI_STOP_ON_NONE,&error_set);
    if(error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        return error;
    }

    debug_collection(ini_config,COL_TRAVERSE_DEFAULT);
    print_collection(ini_config);
    print_collection(error_set);

	printf("\n\n----------------------\n");
    /* Output parsing errors (if any) */
    print_file_parsing_errors(stdout,error_set);
	printf("----------------------\n\n\n");


    destroy_collection(ini_config);
    destroy_collection(error_set);
    return 0;
}

int negative_test()
{
    int error;
    unsigned int count;
    struct collection_item *ini_config = (struct collection_item *)(NULL);

    /* App name is null - expect failure */
    error = config_for_app(NULL, NULL, NULL, NULL,INI_STOP_ON_NONE,NULL);
    if(!error) {
        printf("Expected error: %d got success\n",EINVAL);
        return -1;
    }

    /* Config collection storage is NULL - expect failure */
    error = config_for_app("real", NULL, NULL, NULL,INI_STOP_ON_NONE,NULL);
    if(!error) {
        printf("Expected error: %d got success\n",EINVAL);
        return -1;
    }

    /* Config collection storage is NULL - expect failure */
    error = config_for_app("real", "real.conf", NULL, NULL,INI_STOP_ON_NONE,NULL);
    if(!error) {
        printf("Expected error: %d got success\n",EINVAL);
        return -1;
    }

    /* Expect success but empty config */
    error = config_for_app("real", "real.conf", NULL, &ini_config,INI_STOP_ON_NONE,NULL);
    if(error) {
        printf("Expected success got error: %d\n",error);
        return error;
    }

    count = 0;
    (void)get_collection_count(ini_config,&count);
    if(count > 1) {
        printf("Expected empty collection but got contents with %d elements\n",count);
        print_collection(ini_config);
        return -1;
    }

    destroy_collection(ini_config);
    return 0;

}

int real_test(const char *file)
{
    int error;
    struct collection_item *ini_config = (struct collection_item *)(NULL);
    struct collection_item *error_set = (struct collection_item *)(NULL);
    struct collection_iterator *iterator = (struct collection_iterator *)(NULL);
    struct collection_item *item = (struct collection_item *)(NULL);
    int type;

	printf("\n\n===== REAL TEST START ======\n");
	printf("Reading collection\n");
    error = config_for_app("real", file, "./ini/ini.d", &ini_config,INI_STOP_ON_NONE,&error_set);
    if(error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        return error;
    }

	printf("Debugging the config collection:\n");
    debug_collection(ini_config,COL_TRAVERSE_DEFAULT);
	printf("Debugging the error collection:\n");
    debug_collection(error_set,COL_TRAVERSE_DEFAULT);

	printf("About to print parsing errors:\n");
	printf("\n\n----------------------\n");
    /* Output parsing errors (if any) */
    print_config_parsing_errors(stdout,error_set);
	printf("----------------------\n\n\n");

	printf("About to bind iterator to print the config file contents.\n");
    /* Bind iterator */
    error =  bind_iterator(&iterator,ini_config,COL_TRAVERSE_DEFAULT|COL_TRAVERSE_END);
    if(error) {
        printf("Failed to bind iterator: %d\n",error);
        destroy_collection(ini_config);
        destroy_collection(error_set);
        return error;
    }

	printf("About to start iteration loop.\n");
    do {
        /* Loop through a collection */
        error = iterate_collection(iterator, &item);
        if(error) {
            printf("Error iterating collection: %d",error);
            unbind_iterator(iterator);
            return error;
        }

        /* Are we done ? */
        if(item == (struct collection_item *)(NULL)) break;

        type = get_item_type(item);

        /* Start of the collection */
        if(type == COL_TYPE_COLLECTION)
            printf("Contents of the configuration for application %s\n",get_item_property(item,NULL));
        /* End of section */
        else if(type == COL_TYPE_END) printf("\n");
        /* Section header ? */
        else if(type == COL_TYPE_COLLECTIONREF) printf("[%s]\n",get_item_property(item,NULL));
        /* Anything else - we know they are all strings*/
        else printf("%s = %s\n",get_item_property(item,NULL), (char *)get_item_data(item));
    }
    while(1);

    /* Do not forget to unbind iterator - otherwise there will be a leak */
	printf("About to clean up.\n");
    unbind_iterator(iterator);

    destroy_collection(ini_config);
    destroy_collection(error_set);
    return 0;
}

int get_test()
{

    int error;
    struct collection_item *ini_config = (struct collection_item *)(NULL);
    struct collection_item *error_set = (struct collection_item *)(NULL);
    struct collection_item *item = (struct collection_item *)(NULL);
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
    int i;
	char **strarray;
    char **strptr;
    int size;
    long *array;
    double *darray;
    char **prop_array;

	printf("\n\n===== GET TEST START ======\n");
	printf("Reading collection\n");
    error = config_for_app("real", NULL, "./ini/ini.d", &ini_config,INI_STOP_ON_NONE,&error_set);
    if(error) {
        printf("Attempt to read configuration returned error: %d\n",error);
        return error;
    }

	printf("Debugging the config collection:\n");
    debug_collection(ini_config,COL_TRAVERSE_DEFAULT);
	printf("Debugging the error collection:\n");
    debug_collection(error_set,COL_TRAVERSE_DEFAULT);
    destroy_collection(error_set);

    printf("Negtive test - trying to get non existing key-value pair.\n");

    /* Negative test */
    item = (struct collection_item *)(NULL);
    error = get_config_item("monitor1","description1", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should not be found */
    if(item != (struct collection_item *)(NULL)) {
        printf("Expected NULL but got something else!\n");
        destroy_collection(ini_config);
        return -1;
    }

    /* Another negative test but section exists this time */
    item = (struct collection_item *)(NULL);
    error = get_config_item("monitor","description1", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should not be found */
    if(item != (struct collection_item *)(NULL)) {
        printf("Expected NULL but got something else!\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Trying to get an item.\n");

    /* Positive test */
    item = (struct collection_item *)(NULL);
    error = get_config_item("monitor","description", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected item but got something NULL!\n");
        destroy_collection(ini_config);
        return -1;
    }

    debug_item(item);


    printf("Get item as string without duplication from NULL item.\n");

    /* Get a string without duplicication */
    /* Negative test */
    cstrn = get_const_string_config_value(NULL, NULL);
    if(cstrn != NULL) {
        printf("Expected error got success.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Get item as string without duplication from correct item.\n");

    /* Now get string from the right item */
    error = 0;
    cstr = get_const_string_config_value(item, &error);
    if(error) {
        printf("Expected success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    printf("Value: [%s]\n",cstr);

    /* Same thing but create a dup */

    printf("Get item as string with duplication from correct item.\n");

    error = 0;
    str = get_string_config_value(item, &error);
    if(error) {
        printf("Expected success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    printf("Value: [%s]\n",str);
    free(str);


    /* Get a badly formated number */
    printf("Convert item to number with strict conversion.\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("monitor","bad_number", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected item but got something NULL!\n");
        destroy_collection(ini_config);
        return -1;
    }

    debug_item(item);


    /* Now try to get value in different ways */
    error = 0;
    number = get_int_config_value(item, 1, 10, &error);
    if(error) {
        /* We expected error in this case */
        printf("Expected error.\n");
        if(number != 10) {
            printf("It failed to set default value.\n");
            destroy_collection(ini_config);
            return -1;
        }
    }

    printf("Convert item to number without strict conversion.\n");

    error = 0;
    number = 1;
    number = get_int_config_value(item, 0, 10, &error);
    if(error) {
        /* We expected error in this case */
        printf("Did not expect error.\n");
        destroy_collection(ini_config);
        return error;
    }

    if(number != 5) {
        /* We expected error in this case */
        printf("We expected that the conversion will return 5.\n");
        destroy_collection(ini_config);
        return -1;
    }



    /* Get real integer */

    printf("Fetch another item from section \"domains/LOCAL\" named \"enumerate\".\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("domains/LOCAL","enumerate", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected success but got NULL.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Convert item to integer.\n");

    /* Take number out of it */
    error = 0;
    number = get_int_config_value(item, 1, 100, &error);
    if(error) {
        printf("Did not expect error. Got %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if(number != 3) {
        printf("We expected that the conversion will return 3.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Expected 3 got %d\n", number);

    printf("Convert item to long.\n");

    /* Take number out of it */
    error = 0;
    number_long = get_long_config_value(item, 1, 100, &error);
    if(error) {
        printf("Did not expect error. Got %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if(number_long != 3) {
        printf("We expected that the conversion will return 3.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Expected 3 got %ld\n", number_long);

    printf("Convert item to unsigned.\n");

    /* Take number out of it */
    error = 0;
    number_unsigned = get_unsigned_config_value(item, 1, 100, &error);
    if(error) {
        printf("Did not expect error. Got %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if(number_unsigned != 3) {
        printf("We expected that the conversion will return 3.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Expected 3 got %d\n", number_unsigned);

    printf("Convert item to unsigned long.\n");

    /* Take number out of it */
    error = 0;
    number_ulong = get_ulong_config_value(item, 1, 100, &error);
    if(error) {
        printf("Did not expect error. Got %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if(number_ulong != 3) {
        printf("We expected that the conversion will return 3.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Expected 3 got %lu\n", number_ulong);

    printf("Convert item to double.\n");

    /* Take number out of it */
    error = 0;
    number_double = get_double_config_value(item, 1, 100., &error);
    if(error) {
        printf("Did not expect error. Got %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* It is 3 in the file */
    if(number_double != 3.) {
        printf("We expected that the conversion will return 3.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Expected 3 got %e\n", number_double);

    printf("Convert item to bool.\n");

    /* Take number out of it */
    error = 0;
    logical = get_bool_config_value(item, 1, &error);
    if(!error) {
        printf("Expect error. Got success.\n");
        destroy_collection(ini_config);
        return -1;
    }

    /* Get real bool item and convert it */
    printf("Get real bool item \"legacy\" and convert it.\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("domains/LOCAL","legacy", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected success but got NULL.\n");
        destroy_collection(ini_config);
        return -1;
    }

    printf("Convert item to bool.\n");

    error = 0;
    logical = get_bool_config_value(item, 1, &error);
    if(error) {
        printf("Expect success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    if(logical) {
        printf("Expected false but got true - bad.\n");
        return -1;
    }

    printf("In the files it is FALSE so we got false.\n");

    printf("Get binary item\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("domains/EXAMPLE.COM","binary_test", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected success but got NULL.\n");
        destroy_collection(ini_config);
        return -1;
    }

    debug_item(item);

    error = 0;
    binary = get_bin_config_value(item, &length, &error);
    if(error) {
        printf("Expect success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    printf("Binary value (expect 123) = ");
    for(i=0;i<length;i++) {
        printf("%d",*((unsigned char*)(binary)+i));
    }
    printf("\n");

    free_bin_config_value(binary);

    printf("Get string array item\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("domains","domainsorder", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected success but got NULL.\n");
        destroy_collection(ini_config);
        return -1;
    }

    debug_item(item);

    printf("Get str array without size.\n");

    error = 0;
    strarray = get_string_config_array(item, ",", NULL, &error);
    if(error) {
        printf("Expect success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    strptr = strarray;
    while(*strptr != NULL) {
        printf("[%s]\n",*strptr);
        strptr++;
    }

    free_string_config_array(strarray);

    printf("Get str array with size.\n");

    error = 0;
    size = 0;
    strarray = get_string_config_array(item, ",", &size, &error);
    if(error) {
        printf("Expect success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    for(i=0;i<size;i++) printf("[%s]\n",*(strarray + i));

    free_string_config_array(strarray);

    printf("Get long array item\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("domains/EXAMPLE.COM","long_array", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected success but got NULL.\n");
        destroy_collection(ini_config);
        return -1;
    }

    debug_item(item);

    error = 0;
    size = 0; /* Here size is not optional!!! */
    array = get_long_config_array(item, &size, &error);
    if(error) {
        printf("Expect success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    for(i=0;i<size;i++) printf("%ld\n",*(array + i));

    free_long_config_array(array);

    printf("Get double array item\n");

    item = (struct collection_item *)(NULL);
    error = get_config_item("domains/EXAMPLE.COM","double_array", ini_config, &item);
    if(error) {
        printf("Expected success but got error! %d\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Item should be found */
    if(item == (struct collection_item *)(NULL)) {
        printf("Expected success but got NULL.\n");
        destroy_collection(ini_config);
        return -1;
    }

    debug_item(item);

    error = 0;
    size = 0; /* Here size is not optional!!! */
    darray = get_double_config_array(item, &size, &error);
    if(error) {
        printf("Expect success got error %d.\n",error);
        destroy_collection(ini_config);
        return error;
    }

    /* Can be used with this cycle */
    for(i=0;i<size;i++) printf("%.4f\n",darray[i]);

    free_double_config_array(darray);

    printf("\n\nSection list - no size\n");

    /* Do not care about the error or size */
    prop_array = get_section_list(ini_config,NULL,NULL);
    if (prop_array == NULL) {
        printf("Expect success got error.\n");
        destroy_collection(ini_config);
        return -1;
    }

    i = 0;
    while (prop_array[i]) {
		printf("Section: [%s]\n", prop_array[i]);
		i++;
    }
    free_section_list(prop_array);

    printf("\n\nSection list - with size\n");

    /* Do not care about the error or size */
    prop_array = get_section_list(ini_config, &size, NULL);
    if (prop_array == NULL) {
        printf("Expect success got error.\n");
        destroy_collection(ini_config);
        return -1;
    }

    for (i=0;i<size;i++) printf("Section: [%s]\n", prop_array[i]);
    free_section_list(prop_array);

    printf("\n\nAttributes in the section - with size and error\n");

    /* Do not care about the error or size */
    prop_array = get_attribute_list(ini_config, "domains/EXAMPLE.COM", &size, &error);
    if (prop_array == NULL) {
        printf("Expect success got error.\n");
        destroy_collection(ini_config);
        return -1;
    }

    for (i=0;i<size;i++) printf("Section: [%s]\n", prop_array[i]);
    free_attribute_list(prop_array);

    printf("Done with get test!\n");
    return EOK;
}

int main()
{
    int error;

    if((error=basic_test()) ||
       (error=single_file()) ||
       (error=real_test(NULL)) ||
		/* This should result in merged configuration */
       (error=real_test("./ini/ini.conf")) ||
       (error= get_test())) {
        printf("Test failed! Error %d.\n",error);
        return -1;
    }
    printf("Success!\n");
    return 0;
}

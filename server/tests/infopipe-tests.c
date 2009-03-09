/*
   SSSD

   InfoPipe

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>    2009

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

#include <stdlib.h>
#include <check.h>
#include <talloc.h>
#include <tevent.h>
#include <popt.h>
#include <dbus/dbus.h>
#include "util/util.h"
#include "confdb/confdb.h"
#include "sbus/sssd_dbus.h"
#include "infopipe/infopipe.h"
#include "db/sysdb.h"

#define INFP_TEST_DBUS_NAME "org.freeipa.sssd.infopipe1.test"
#define TEST_TIMEOUT 30000 /* 30 seconds */

static int setup_infp_tests(DBusConnection **bus)
{
    DBusError error;
    int ret;

    /* Connect to the system bus */
    dbus_error_init(&error);
    *bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    if (*bus == NULL) {
        fail("Could not connect to the system bus. %s:%s", error.name, error.message);
        dbus_error_free(&error);
        return EIO;
    }

    /* Abort the tests if disconnect occurs */
    dbus_connection_set_exit_on_disconnect(*bus, TRUE);

    ret = dbus_bus_request_name(*bus,
                                INFP_TEST_DBUS_NAME,
                                /* We want exclusive access */
                                DBUS_NAME_FLAG_DO_NOT_QUEUE,
                                &error);
    if (ret != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        /* We were unable to register on the system bus */
        fail("Unable to request name on the system bus. Error: %s:%s\n", error.name, error.message);
        dbus_error_free(&error);
        return EIO;
    }
    return EOK;
}

static int teardown_infp_tests(DBusConnection *bus)
{
    dbus_connection_unref(bus);
    return EOK;
}

#define INTROSPECT_CHUNK_SIZE 4096
START_TEST(test_infp_introspect)
{
    TALLOC_CTX *tmp_ctx;
    DBusConnection *bus;
    DBusError error;
    DBusMessage *introspect_req;
    DBusMessage *reply;
    FILE *xml_stream;
    char *chunk;
    char *introspect_xml;
    char *returned_xml;
    unsigned long xml_size;
    size_t chunk_size;
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        fail("Could not create temporary talloc context");
        goto done;
    }

    /* Create introspection method call */
    introspect_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                                  INFOPIPE_PATH,
                                                  DBUS_INTROSPECT_INTERFACE,
                                                  DBUS_INTROSPECT_METHOD);
    if(!introspect_req) {
        fail("Could not create new method call message");
        goto done;
    }

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      introspect_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        /* Read in the reference Introspection XML */
        xml_stream = fopen("introspect.ref", "r");
        if(xml_stream == NULL) {
            DEBUG(0, ("Could not open the introspection XML for reading: [%d].\n", errno));
            return;
        }

        chunk = talloc_size(tmp_ctx, INTROSPECT_CHUNK_SIZE);
        if (chunk == NULL) goto done;

        xml_size = 0;
        introspect_xml = NULL;
        do {
            chunk_size = fread(chunk, 1, INTROSPECT_CHUNK_SIZE, xml_stream);
            introspect_xml = talloc_realloc_size(tmp_ctx, introspect_xml, xml_size+chunk_size+1);
            if (introspect_xml == NULL) goto done;

            memcpy(introspect_xml+xml_size, chunk, chunk_size);
            xml_size += chunk_size;
        } while(chunk_size == INTROSPECT_CHUNK_SIZE);
        introspect_xml[xml_size] = '\0';
        talloc_free(chunk);

        /* Get the XML from the message */
        dbus_message_get_args(reply, &error,
                              DBUS_TYPE_STRING, &returned_xml,
                              DBUS_TYPE_INVALID);

        /* Verify that the reply matches the reference file */
        int c;
        if ((c = strcmp(introspect_xml, returned_xml)) != 0) {
            DEBUG(0, ("Verify Introspection XML: FAILED %d\nstrlen: %d, %d\n", c, strlen(introspect_xml), strlen(returned_xml)));
            fail("");//"Verify Introspection XML: FAILED %d\n %s\nstrlen: %d", c, returned_xml, strlen(returned_xml));
        }
        break;
    case DBUS_MESSAGE_TYPE_ERROR:
        fail("Error: %s\n", dbus_message_get_error_name(reply));
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_check_permissions)
{
    TALLOC_CTX *tmp_ctx;
    DBusConnection *bus;
    DBusError error;
    DBusMessage *permission_req;
    DBusMessage *reply;
    DBusMessageIter msg_iter;
    DBusMessageIter array_iter;
    DBusMessageIter struct_iter;
    dbus_bool_t *permission_array;
    int permission_count;
    char *domain;
    char *object;
    char *instance;
    char *action;
    char *attribute;
    int type, i;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        fail("Could not create temporary talloc context");
        goto done;
    }

    /* Create permission request message */
    permission_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                                  INFOPIPE_PATH,
                                                  INFOPIPE_INTERFACE,
                                                  INFP_CHECK_PERMISSIONS);
    if(!permission_req) {
        fail("Could not create new method call message");
        goto done;
    }

    /* Add arguments */
    domain = talloc_strdup(tmp_ctx, "LOCAL");
    object = talloc_strdup(tmp_ctx, "user");
    instance = talloc_strdup(tmp_ctx, "testuser1");
    action = talloc_strdup(tmp_ctx, "modify");
    attribute = talloc_strdup(tmp_ctx, "userpic");

    dbus_message_append_args(permission_req,
                             DBUS_TYPE_STRING, &domain,
                             DBUS_TYPE_STRING, &object,
                             DBUS_TYPE_STRING, &instance,
                             DBUS_TYPE_INVALID);

    dbus_message_iter_init_append(permission_req, &msg_iter);
    dbus_message_iter_open_container(&msg_iter,
                                     DBUS_TYPE_ARRAY, "(ss)", /* Array of structs */
                                     &array_iter);
    dbus_message_iter_open_container(&array_iter,
                                     DBUS_TYPE_STRUCT, NULL,
                                     &struct_iter);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &action);
    dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &attribute);
    dbus_message_iter_close_container(&array_iter, &struct_iter);
    dbus_message_iter_close_container(&msg_iter, &array_iter);


    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      permission_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    type = dbus_message_get_type(reply);
    switch (type) {
    case DBUS_MESSAGE_TYPE_ERROR:
        fail("Error: %s\n", dbus_message_get_error_name(reply));
        goto done;
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        dbus_message_get_args(reply, &error,
                              DBUS_TYPE_ARRAY, DBUS_TYPE_BOOLEAN, &permission_array, &permission_count,
                              DBUS_TYPE_INVALID);
    }

    i = 0;
    while(i < permission_count) {
        if (permission_array[i] == true) {
            fail("User was granted permission unexpectedly");
            goto done;
        }
        i++;
    }

done:
    talloc_free(tmp_ctx);
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_set_user_attrs)
{
    TALLOC_CTX *tmp_ctx;
    DBusConnection *bus;
    DBusMessage *setattr_req;
    const char *username = "testuser1";
    const char *domain = "LOCAL";
    const char *shell_attr = SYSDB_SHELL;
    const char *shell_value = "/usr/bin/testshell";
    DBusMessageIter iter, array_iter, dict_array_iter, dict_iter, variant_iter;
    DBusError error;
    DBusMessage *reply;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        fail("Could not create temporary talloc context");
        goto done;
    }

    setattr_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                               INFOPIPE_PATH,
                                               INFOPIPE_INTERFACE,
                                               INFP_USERS_SET_ATTR);
    if (!setattr_req) {
        fail("Could not create new method call message");
        goto done;
    }

    /* Usernames */
    dbus_message_iter_init_append(setattr_req, &iter);
    dbus_message_iter_open_container(&iter,
                                         DBUS_TYPE_ARRAY, "s",
                                         &array_iter); /* Array of dict array of string->variant pairs */
    dbus_message_iter_append_basic(&array_iter, DBUS_TYPE_STRING, &username);
    dbus_message_iter_close_container(&iter, &array_iter);

    /* Domain */
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);

    dbus_message_iter_open_container(&iter,
                                     DBUS_TYPE_ARRAY, "a{sv}",
                                     &array_iter); /* Array of dict array of string->variant pairs */
    dbus_message_iter_open_container(&array_iter,
                                     DBUS_TYPE_ARRAY, "{sv}",
                                     &dict_array_iter); /* Array of dict of string->variant pairs */
    dbus_message_iter_open_container(&dict_array_iter,
                                     DBUS_TYPE_DICT_ENTRY, NULL,
                                     &dict_iter); /* Dict entry of string->variant pair */
    dbus_message_iter_append_basic(&dict_iter, DBUS_TYPE_STRING, &shell_attr);
    dbus_message_iter_open_container(&dict_iter,
                                     DBUS_TYPE_VARIANT, "s",
                                     &variant_iter); /* Variant */
    dbus_message_iter_append_basic(&variant_iter, DBUS_TYPE_STRING, &shell_value);
    dbus_message_iter_close_container(&dict_iter, &variant_iter);
    dbus_message_iter_close_container(&dict_array_iter, &dict_iter);
    dbus_message_iter_close_container(&array_iter, &dict_array_iter);
    dbus_message_iter_close_container(&iter, &array_iter);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      setattr_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    teardown_infp_tests(bus);
}
END_TEST

Suite *create_infopipe_suite(void)
{
    Suite *s = suite_create("infopipe");

    TCase *tc_infp = tcase_create("InfoPipe Tests");

    /* Test the Introspection XML */
    tcase_add_test(tc_infp, test_infp_introspect);
    tcase_add_test(tc_infp, test_infp_check_permissions);
    tcase_add_test(tc_infp, test_infp_set_user_attrs);

/* Add all test cases to the test suite */
    suite_add_tcase(s, tc_infp);

    return s;
}

int main(int argc, const char *argv[]) {
    int opt;
    poptContext pc;
    int failure_count;
    Suite *infopipe_suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        { NULL }
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    infopipe_suite = create_infopipe_suite();
    sr = srunner_create(infopipe_suite);
    srunner_run_all(sr, CK_VERBOSE);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
   SSSD

   InfoPipe

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>    2009

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

#define INFP_TEST_DBUS_NAME "org.freedesktop.sssd.infopipe1.test"
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

START_TEST(test_infp_users_delete)
{
    DBusConnection *bus;
    DBusMessage *delete_req;
    DBusMessageIter iter;
    DBusError error;
    DBusMessage *reply;
    const char *username = "testuser1";
    const char *domain = "LOCAL";
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    delete_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                              INFOPIPE_PATH,
                                              INFOPIPE_INTERFACE,
                                              INFP_USERS_DELETE);
    if (!delete_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(delete_req, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &username);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      delete_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* assert that the reply is an empty return message */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_users_set_uid)
{
    DBusConnection *bus;
    DBusMessage *setuid_req;
    DBusMessageIter iter;
    DBusError error;
    DBusMessage *reply;
    const char *username = "testuser1";
    const char *domain = "LOCAL";
    u_int32_t   new_id = 1666;
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    setuid_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                              INFOPIPE_PATH,
                                              INFOPIPE_INTERFACE,
                                              INFP_USERS_SET_UID);
    if (!setuid_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(setuid_req, &iter);

    dbus_message_iter_init_append(setuid_req, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &username);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &new_id);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      setuid_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* assert that the reply is an empty return message */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_users_get_attr)
{
    DBusConnection *bus;
    DBusMessage *get_attr_req;
    DBusMessageIter iter, user_iter, attr_iter;
    DBusError error;
    DBusMessage *reply;
    const char *username = "testuser1";
    const char *domain = "LOCAL";
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    get_attr_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                               INFOPIPE_PATH,
                                               INFOPIPE_INTERFACE,
                                               INFP_USERS_GET_ATTR);
    if (!get_attr_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(get_attr_req, &iter);

    /* append the username */
    dbus_message_iter_open_container(&iter,
                                     DBUS_TYPE_ARRAY, "s",
                                     &user_iter); /* Array of usernames */
    dbus_message_iter_append_basic(&user_iter, DBUS_TYPE_STRING, &username);
    dbus_message_iter_close_container(&iter, &user_iter);

    /* append the domain */
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);

    /* no attributes specified means retrieve all possible */
    dbus_message_iter_open_container(&iter,
                                     DBUS_TYPE_ARRAY, "s",
                                     &attr_iter); /* Array of attributes */
    dbus_message_iter_close_container(&iter, &attr_iter);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      get_attr_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* Retreive the result */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_users_create)
{
    DBusConnection *bus;
    DBusMessage *create_req;
    const char *username = "testuser1";
    const char *fullname = "test create user";
    const char *domain = "LOCAL";
    const char *homedir = "/home/test_create_user";
    const char *shell = "/bin/sh";
    DBusMessageIter iter;
    DBusError error;
    DBusMessage *reply;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    create_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                               INFOPIPE_PATH,
                                               INFOPIPE_INTERFACE,
                                               INFP_USERS_CREATE);
    if (!create_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(create_req, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &username);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &fullname);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &homedir);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &shell);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      create_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_groups_create)
{
    DBusConnection *bus;
    DBusMessage *create_req;
    const char *groupname = "testgroup1";
    const char *domain = "LOCAL";
    DBusMessageIter iter, group_iter;
    DBusError error;
    DBusMessage *reply;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    create_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                              INFOPIPE_PATH,
                                              INFOPIPE_INTERFACE,
                                              INFP_GROUPS_CREATE);
    if (!create_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(create_req, &iter);

    dbus_message_iter_open_container(&iter,
                                     DBUS_TYPE_ARRAY, "s",
                                     &group_iter); /* Array of groupnames */
    dbus_message_iter_append_basic(&group_iter, DBUS_TYPE_STRING, &groupname);
    dbus_message_iter_close_container(&iter, &group_iter);

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      create_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_groups_set_gid)
{
    DBusConnection *bus;
    DBusMessage *setgid_req;
    DBusMessageIter iter;
    DBusError error;
    DBusMessage *reply;
    const char *groupname = "testgroup1";
    const char *domain = "LOCAL";
    u_int32_t   new_id = 1666;
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    setgid_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                              INFOPIPE_PATH,
                                              INFOPIPE_INTERFACE,
                                              INFP_GROUPS_SET_GID);
    if (!setgid_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(setgid_req, &iter);

    dbus_message_iter_init_append(setgid_req, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &groupname);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &new_id);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      setgid_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* assert that the reply is an empty return message */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_groups_add_members)
{
    DBusConnection *bus;
    DBusMessage *add_member_req;
    const char *groupname = "testgroup1";
    const char *membername = "testuser1";
    const char *domain = "LOCAL";
    DBusMessageIter iter, array_iter;
    DBusError error;
    DBusMessage *reply;
    int type;
    int membertype = 0;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    add_member_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                                  INFOPIPE_PATH,
                                                  INFOPIPE_INTERFACE,
                                                  INFP_GROUPS_ADD_MEMBERS);
    if (!add_member_req) {
        fail("Could not create new method call message");
        goto done;
    }

    /* Add the parameters */
    dbus_message_iter_init_append(add_member_req, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &groupname);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);

    dbus_message_iter_open_container(&iter,
                                     DBUS_TYPE_ARRAY, "(ss)", /* Array of members */
                                     &array_iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &membername);
    dbus_message_iter_close_container(&iter, &array_iter);

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_BYTE, &membertype);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      add_member_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* assert that the reply is an empty return message */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_groups_del_members)
{
    DBusConnection *bus;
    DBusMessage *del_member_req;
    DBusError error;
    DBusMessage *reply;
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    del_member_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                                  INFOPIPE_PATH,
                                                  INFOPIPE_INTERFACE,
                                                  INFP_GROUPS_REMOVE_MEMBERS);
    if (!del_member_req) {
        fail("Could not create new method call message");
        goto done;
    }

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      del_member_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* assert that the reply is an empty return message */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

START_TEST(test_infp_groups_delete)
{
    DBusConnection *bus;
    DBusMessage *delete_req;
    const char *groupname = "testgroup1";
    const char *domain = "LOCAL";
    DBusMessageIter iter;
    DBusError error;
    DBusMessage *reply;
    int type;

    if (setup_infp_tests(&bus) != EOK) {
        fail("Could not set up the tests");
        return;
    }

    delete_req = dbus_message_new_method_call(INFOPIPE_DBUS_NAME,
                                              INFOPIPE_PATH,
                                              INFOPIPE_INTERFACE,
                                              INFP_GROUPS_DELETE);
    if (!delete_req) {
        fail("Could not create new method call message");
        goto done;
    }

    dbus_message_iter_init_append(delete_req, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &groupname);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &domain);

    /* Send the message */
    dbus_error_init(&error);
    reply = dbus_connection_send_with_reply_and_block(bus,
                                                      delete_req,
                                                      TEST_TIMEOUT,
                                                      &error);
    if(!reply) {
        fail("Could not send message. Error: %s:%s", error.name, error.message);
        dbus_error_free(&error);
        goto done;
    }

    /* assert that the reply is an empty return message */
    type = dbus_message_get_type(reply);
    fail_unless(type == DBUS_MESSAGE_TYPE_METHOD_RETURN,
                "Method call returned %d instead of METHOD_RETURN", type);

done:
    teardown_infp_tests(bus);
}
END_TEST

Suite *create_infopipe_suite(void)
{
    Suite *s = suite_create("infopipe");

    TCase *tc_infp = tcase_create("InfoPipe Privileged Tests");

    /* Test user methods */
    tcase_add_test(tc_infp, test_infp_users_create);
    tcase_add_test(tc_infp, test_infp_users_set_uid);
    tcase_add_test(tc_infp, test_infp_users_get_attr);

    /* Test group methods */
    tcase_add_test(tc_infp, test_infp_groups_create);
    tcase_add_test(tc_infp, test_infp_groups_set_gid);

    /* Clean up */
    tcase_add_test(tc_infp, test_infp_users_delete);
    tcase_add_test(tc_infp, test_infp_groups_delete);

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

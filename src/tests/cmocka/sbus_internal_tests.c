/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: SBUS internals

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

#include <popt.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "responder/common/responder.h"
#include "tests/cmocka/common_mock.h"
#include "sbus/sssd_dbus_private.h"

struct sbus_get_id_ctx {
    struct sss_test_ctx *stc;
    struct sbus_connection *conn;

    DBusPendingCallNotifyFunction reply_handler;
    void *reply_pvt;
    int last_hash_lookup;

    int64_t expected;
};

struct sbus_get_id_ctx *global_test_ctx;

DBusConnection *
__wrap_dbus_bus_get(DBusBusType  type,
	            DBusError   *error)
{
    /* just don't return NULL */
    return (DBusConnection *) 0x42;
}

void
__wrap_dbus_connection_set_exit_on_disconnect(DBusConnection *connection,
                                              dbus_bool_t     exit_on_disconnect)
{
    return;
}

void __wrap_dbus_pending_call_unref(DBusPendingCall *pending)
{
    return;
}

void __wrap_dbus_message_unref(DBusMessage *message)
{
    return;
}

void __wrap_dbus_connection_unref(DBusConnection *connection)
{
    return;
}

DBusMessage*
__wrap_dbus_pending_call_steal_reply(DBusPendingCall *pending)
{
    return sss_mock_ptr_type(DBusMessage *);
}

int __real_hash_lookup(hash_table_t *table, hash_key_t *key, hash_value_t *value);

int __wrap_hash_lookup(hash_table_t *table, hash_key_t *key, hash_value_t *value)
{
    global_test_ctx->last_hash_lookup = __real_hash_lookup(table, key, value);
    return global_test_ctx->last_hash_lookup;
}

static void fake_sbus_msg_done(struct tevent_context *ev,
                               struct tevent_immediate *imm,
                               void *pvt)
{
    struct sbus_get_id_ctx *test_ctx = talloc_get_type(pvt,
                                            struct sbus_get_id_ctx);
    talloc_free(imm);
    test_ctx->reply_handler(NULL, test_ctx->reply_pvt);
}

int sss_dbus_conn_send(DBusConnection *dbus_conn,
                       DBusMessage *msg,
                       int timeout_ms,
                       DBusPendingCallNotifyFunction reply_handler,
                       void *pvt,
                       DBusPendingCall **pending)
{
    struct tevent_immediate *imm;

    global_test_ctx->reply_pvt = pvt;
    global_test_ctx->reply_handler = reply_handler;

    imm = tevent_create_immediate(global_test_ctx->stc->ev);
    assert_non_null(imm);
    tevent_schedule_immediate(imm, global_test_ctx->stc->ev, fake_sbus_msg_done, global_test_ctx);

    return EOK;
}

void sbus_get_id_test_setup(void **state)
{
    struct sbus_get_id_ctx *test_ctx;
    int ret;

    test_ctx = talloc(global_talloc_context, struct sbus_get_id_ctx);
    assert_non_null(test_ctx);

    test_ctx->conn = talloc(test_ctx, struct sbus_connection);
    assert_non_null(test_ctx->conn);
    test_ctx->conn->connection_type = SBUS_CONN_TYPE_SYSBUS;
    ret = sss_hash_create(test_ctx->conn, 32, &test_ctx->conn->clients);
    assert_int_equal(ret, EOK);

    test_ctx->stc = create_ev_test_ctx(test_ctx);
    assert_non_null(test_ctx->stc);

    *state = test_ctx;
    global_test_ctx = test_ctx;
}

void sbus_int_test_get_uid_done(struct tevent_req *req)
{
    errno_t ret;
    int64_t uid;
    struct sbus_get_id_ctx *test_ctx = tevent_req_callback_data(req,
                                            struct sbus_get_id_ctx);

    ret = sbus_get_sender_id_recv(req, &uid);
    talloc_free(req);
    assert_int_equal(ret, EOK);

    test_ctx->stc->done = true;
    assert_int_equal(uid, test_ctx->expected);
}

void sbus_int_test_get_uid(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    DBusMessage *reply;
    struct sbus_get_id_ctx *test_ctx = talloc_get_type(*state,
                                            struct sbus_get_id_ctx);

    uint32_t uid;

    test_ctx->expected = 42;
    uid = test_ctx->expected;

    reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
    assert_non_null(reply);
    dbus_message_append_args(reply,
                             DBUS_TYPE_UINT32, &uid,
                             DBUS_TYPE_INVALID);
    will_return(__wrap_dbus_pending_call_steal_reply, reply);

    req = sbus_get_sender_id_send(test_ctx, test_ctx->stc->ev,
                                  test_ctx->conn, __FILE__);
    tevent_req_set_callback(req, sbus_int_test_get_uid_done, test_ctx);

    ret = test_ev_loop(test_ctx->stc);
    assert_int_equal(ret, EOK);
    assert_int_equal(test_ctx->last_hash_lookup, HASH_ERROR_KEY_NOT_FOUND);

    /* Now do the same lookup again, just make sure the result was cached */
    req = sbus_get_sender_id_send(test_ctx, test_ctx->stc->ev,
                                  test_ctx->conn, __FILE__);
    tevent_req_set_callback(req, sbus_int_test_get_uid_done, test_ctx);

    ret = test_ev_loop(test_ctx->stc);
    assert_int_equal(ret, EOK);
    assert_int_equal(test_ctx->last_hash_lookup, HASH_SUCCESS);
}

void sbus_int_test_get_uid_no_sender_done(struct tevent_req *req)
{
    errno_t ret;
    int64_t uid;
    struct sbus_get_id_ctx *test_ctx = tevent_req_callback_data(req,
                                            struct sbus_get_id_ctx);

    ret = sbus_get_sender_id_recv(req, &uid);
    talloc_free(req);
    assert_int_equal(ret, ERR_SBUS_NO_SENDER);
    test_ctx->stc->done = true;
}

void sbus_int_test_get_uid_no_sender(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct sbus_get_id_ctx *test_ctx = talloc_get_type(*state,
                                            struct sbus_get_id_ctx);

    test_ctx->expected = -1;

    req = sbus_get_sender_id_send(test_ctx, test_ctx->stc->ev,
                                  test_ctx->conn, NULL);
    tevent_req_set_callback(req, sbus_int_test_get_uid_no_sender_done, test_ctx);

    ret = test_ev_loop(test_ctx->stc);
    assert_int_equal(ret, EOK);
}

void sbus_get_id_test_teardown(void **state)
{
    struct sbus_get_id_ctx *test_ctx = talloc_get_type(*state,
                                            struct sbus_get_id_ctx);
    talloc_free(test_ctx);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(sbus_int_test_get_uid,
                                 sbus_get_id_test_setup,
                                 sbus_get_id_test_teardown),
        unit_test_setup_teardown(sbus_int_test_get_uid_no_sender,
                                 sbus_get_id_test_setup,
                                 sbus_get_id_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

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

    DEBUG_CLI_INIT(debug_level);
    tests_set_cwd();
    return run_tests(tests);
}

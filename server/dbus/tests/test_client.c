#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "events.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "dbus/sssd_dbus.h"

/* TODO: get this value from LDB */
#define DBUS_ADDRESS "unix:path=/var/lib/sss/pipes/private/dbus"

/* Monitor Interface */
#define MONITOR_DBUS_INTERFACE "org.freeipa.sssd.monitor"
#define MONITOR_DBUS_PATH "/org/freeipa/sssd/monitor"
#define MONITOR_METHOD_VERSION "getVersion"

struct test_cli_ctx {
    struct sssd_dbus_ctx *sd_ctx;
    DBusConnection *conn;
};

static void request_version_timed(struct test_cli_ctx *ctx);

static void print_version(DBusPendingCall *pending, void *data)
{
    DBusMessage *reply;
    DBusError error;
    const char *version_string;
    int type;

    dbus_error_init(&error);

    reply = dbus_pending_call_steal_reply(pending);
    if (!reply) {
        /* reply should never be null. This function shouldn't be called
         * until reply is valid. If reply is NULL here, something is seriously
         * wrong and we should bail out.
         */
        DEBUG(0, ("Serious error. A reply callback was called but no reply was received"));
        exit(3);
    }

    type = dbus_message_get_type(reply);

    switch (type) {
    case DBUS_MESSAGE_TYPE_METHOD_RETURN:
        if (dbus_message_get_args(reply, &error,
                                  DBUS_TYPE_STRING,
                                  &version_string,
                                  DBUS_TYPE_INVALID)) {
            fprintf(stdout, "Version: %s\n", version_string);
            fflush(stdout);
        } else {
            DEBUG(0, ("Error getting arguments in print_version"));
        }
        break;
    case DBUS_MESSAGE_TYPE_ERROR:
        break;
    default:
        DEBUG(0, ("Received unexpected message"));
        exit(4);
    }
}

static void test_timed_handler(struct event_context *ev,
                               struct timed_event *te,
                               struct timeval tv, void *data)
{
    struct test_cli_ctx *test_ctx;
    struct sssd_dbus_ctx *ctx;
    DBusPendingCall *pending_reply;
    DBusMessage *vmsg;
    DBusError error;
    dbus_bool_t dbret;

    test_ctx = talloc_get_type(data, struct test_cli_ctx);
    ctx = test_ctx->sd_ctx;

    fprintf(stdout, ".");
    fflush(stdout);

    dbus_error_init(&error);
    vmsg = dbus_message_new_method_call(NULL,
                                        ctx->path, ctx->name,
                                        MONITOR_METHOD_VERSION);

    dbret = dbus_connection_send_with_reply(test_ctx->conn, vmsg,
                                            &pending_reply, -1);
    if (!dbret) {
        /* Critical failure */
        DEBUG(0,("Failed to send version_request"));
        exit(2);
    }

    dbus_pending_call_set_notify(pending_reply, print_version, NULL, NULL);

    dbus_message_unref(vmsg);

    request_version_timed(test_ctx);
}

static void request_version_timed(struct test_cli_ctx *ctx)
{
    struct timed_event *te = NULL;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tv.tv_sec += 5;
    tv.tv_usec = 0;
    te = event_add_timed(ctx->sd_ctx->ev, ctx, tv, test_timed_handler, ctx);
    if (te == NULL) {
        DEBUG(0, ("failed to add event!\n"));
        exit(1);
    }
}

int main (int argc, const char *argv[])
{
    struct event_context *event_ctx;
    struct sssd_dbus_ctx *ctx;
    struct test_cli_ctx *test_ctx;
    DBusConnection *dbus_conn;
    int ret;

    event_ctx = event_context_init(talloc_autofree_context());
    if (!event_ctx) {
        printf("Out of memory!?\n");
        exit(1);
    }

    ctx = talloc_zero(event_ctx, struct sssd_dbus_ctx);
    if (!ctx) {
        printf("Out of memory!?\n");
        exit(1);
    }
    ctx->ev = event_ctx;
    ctx->name = talloc_strdup(ctx, MONITOR_DBUS_INTERFACE);
    ctx->path = talloc_strdup(ctx, MONITOR_DBUS_PATH);
    if (!ctx->name || !ctx->path) {
        printf("Out of memory!?\n");
        exit(1);
    }

    ret = sssd_new_dbus_connection(ctx, DBUS_ADDRESS, &dbus_conn);
    if (ret != EOK) {
        exit(1);
    }

    test_ctx = talloc(ctx, struct test_cli_ctx);
    if (!test_ctx) {
        printf("Out of memory!?\n");
        exit(1);
    }
    test_ctx->sd_ctx = ctx;
    test_ctx->conn = dbus_conn;

    dbus_connection_set_exit_on_disconnect(dbus_conn, TRUE);

    /* Set up a timed event to request the server version every
     * five seconds and print it to the screen.
     */
    request_version_timed(test_ctx);

    /* Enter the main loop (and hopefully never return) */
    event_loop_wait(event_ctx);

    talloc_free(event_ctx);
    return EXIT_SUCCESS;
}

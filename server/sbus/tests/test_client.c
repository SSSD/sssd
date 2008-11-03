#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "events.h"
#include "util/util.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"

/* TODO: get this value from LDB */
#define DBUS_ADDRESS "unix:path=/var/lib/sss/pipes/private/dbus"

/* Identity */
#define TEST_CLIENT_NAME "testclient"
#define TEST_CLIENT_VERSION 1

/* Monitor Interface */
#define MONITOR_DBUS_INTERFACE "org.freeipa.sssd.monitor"
#define MONITOR_DBUS_PATH "/org/freeipa/sssd/monitor"
#define MONITOR_METHOD_VERSION "getVersion"

/* Service Interface */
#define SERVICE_PATH "/org/freeipa/sssd/service"
#define SERVICE_INTERFACE "org.freeipa.sssd.service"
#define SERVICE_METHOD_IDENTITY "getIdentity"

struct test_cli_ctx {
    struct sbus_method_ctx *sd_ctx;
    /*DBusConnection *conn;*/
    struct event_context *ev;
    struct sbus_conn_ctx *dct_ctx;
};

static int provide_identity(DBusMessage *message, void *data, DBusMessage **r);

struct sbus_method monitor_service_methods [] = {
        {SERVICE_METHOD_IDENTITY, provide_identity},
        {NULL, NULL}
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
        
        if (strcmp(DBUS_ERROR_NO_REPLY, dbus_message_get_error_name(reply))==0) {
            DEBUG(0, ("Received error. Timeout"));
        }
        else {
            DEBUG(0, ("Received error. Not a timeout: %s", dbus_message_get_error_name(reply)));
        }
        break;
    default:
        DEBUG(0, ("Received unexpected message\n"));
        exit(4);
    }
}

static void test_timed_handler(struct event_context *ev,
                               struct timed_event *te,
                               struct timeval tv, void *data)
{
    struct test_cli_ctx *test_ctx;
    struct sbus_method_ctx *ctx;
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
                                        ctx->path, ctx->interface,
                                        MONITOR_METHOD_VERSION);

    dbret = dbus_connection_send_with_reply(sbus_get_connection(test_ctx->dct_ctx), vmsg,
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
    te = event_add_timed(ctx->ev, ctx, tv, test_timed_handler, ctx);
    if (te == NULL) {
        DEBUG(0, ("failed to add event!\n"));
        exit(1);
    }
}

int main (int argc, const char *argv[])
{
    struct event_context *event_ctx;
    struct sbus_method_ctx *ctx;
    struct test_cli_ctx *test_ctx;
    struct sbus_method_ctx *service_methods;
    int ret;

    event_ctx = event_context_init(talloc_autofree_context());
    if (!event_ctx) {
        printf("Out of memory!?\n");
        exit(1);
    }

    ctx = talloc_zero(event_ctx, struct sbus_method_ctx);
    if (!ctx) {
        printf("Out of memory!?\n");
        exit(1);
    }
    
    test_ctx = talloc(event_ctx, struct test_cli_ctx);
    if (!test_ctx) {
        printf("Out of memory!?\n");
        exit(1);
    }
    
    test_ctx->ev = event_ctx;
    ctx->interface = talloc_strdup(ctx, MONITOR_DBUS_INTERFACE);
    ctx->path = talloc_strdup(ctx, MONITOR_DBUS_PATH);
    if (!ctx->interface || !ctx->path) {
        printf("Out of memory!?\n");
        exit(1);
    }

    ret = sbus_new_connection(test_ctx, test_ctx->ev, DBUS_ADDRESS, &(test_ctx->dct_ctx), NULL);
    if (ret != EOK) {
        exit(1);
    }

    test_ctx->sd_ctx = ctx;

    dbus_connection_set_exit_on_disconnect(sbus_get_connection(test_ctx->dct_ctx), TRUE);

    /* Set up a timed event to request the server version every
     * five seconds and print it to the screen.
     */
    request_version_timed(test_ctx);
    
    /* Set up handler for service methods */
    service_methods = talloc_zero(test_ctx, struct sbus_method_ctx);
    service_methods->interface = talloc_strdup(service_methods, SERVICE_INTERFACE);
    service_methods->path = talloc_strdup(service_methods, SERVICE_PATH);
    service_methods->methods = monitor_service_methods;
    sbus_conn_add_method_ctx(test_ctx->dct_ctx, service_methods);

    /* Enter the main loop (and hopefully never return) */
    event_loop_wait(event_ctx);

    talloc_free(event_ctx);
    return EXIT_SUCCESS;
}

static int provide_identity(DBusMessage *message, void *data, DBusMessage **r) {
    const char *name = TEST_CLIENT_NAME;
    dbus_uint16_t version = TEST_CLIENT_VERSION;
    
    DBusMessage *reply;
    dbus_bool_t ret;

    reply = dbus_message_new_method_return(message);
    ret = dbus_message_append_args(reply, 
            DBUS_TYPE_STRING, &name,
            DBUS_TYPE_UINT16, &version,
            DBUS_TYPE_INVALID);

    if (!ret) {
        return EIO;
    }

    *r = reply;
    return EOK;
}

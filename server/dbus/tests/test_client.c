#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "events.h"
#include "dbus/dbus.h"
#include "monitor.h"
#include "dbus/sssd_dbus_common.h"
#include "dbus/sssd_dbus_client.h"
#include "util/util.h"

static void request_version_timed(struct event_context *ev,
        DBusConnection *conn);

static void print_version (DBusPendingCall *pending, void *ptr) {
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
        DEBUG(0,("Serious error. A reply callback was called but no reply was received"));
        exit(3);
    }

    type = dbus_message_get_type(reply);

    if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        if(dbus_message_get_args(reply, &error, DBUS_TYPE_STRING, &version_string, DBUS_TYPE_INVALID)) {
            fprintf(stdout, "Version: %s\n", version_string);
            fflush(stdout);
        }
        else {
            DEBUG(0, ("Error getting arguments in print_version"));
        }
    }
    else if (type == DBUS_MESSAGE_TYPE_ERROR) {

    }
    else {
        DEBUG(0, ("Received unexpected message"));
        exit(4);
    }
}

static void test_timed_handler(struct event_context *ev,
                               struct timed_event *te,
                               struct timeval t, void *ptr) {
    DBusConnection *conn;
    DBusPendingCall *pending_reply;
    DBusMessage *version_request;
    DBusError error;
    conn = (DBusConnection *) ptr;

    fprintf(stdout, ".");
    fflush(stdout);

    dbus_error_init(&error);
    version_request = dbus_message_new_method_call(
            NULL, MONITOR_DBUS_PATH, MONITOR_DBUS_INTERFACE,
            MONITOR_METHOD_VERSION);

    if(!dbus_connection_send_with_reply(conn, version_request, &pending_reply, -1)){
        /* Critical failure */
        DEBUG(0,("Failed to send version_request"));
        exit(2);
    }

    dbus_pending_call_set_notify(pending_reply, print_version, NULL, NULL);

    dbus_message_unref(version_request);

    request_version_timed(ev,conn);
}

static void request_version_timed(struct event_context *ev, DBusConnection *conn) {
    struct timed_event *te = NULL;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tv.tv_sec += 5;
    tv.tv_usec = 0;
    te = event_add_timed(ev, ev, tv, test_timed_handler, conn);
    if (te == NULL) {
        DEBUG(0, ("failed to add event!\n"));
        exit(1);
    }
}

int main (int argc, const char *argv[]) {
    DBusError dbus_error;
    DBusConnection *dbus_conn;
    struct event_context *event_ctx;

    event_ctx = event_context_init(talloc_autofree_context());

    dbus_error_init(&dbus_error);
    dbus_conn = dbus_connection_open(DBUS_ADDRESS, &dbus_error);
    if (dbus_conn == NULL) {
        printf ("Error: name=%s, message=%s\n", dbus_error.name, dbus_error.message);
        exit(1);
    }

    integrate_connection_with_event_loop(event_ctx,dbus_conn);
    dbus_connection_set_exit_on_disconnect (dbus_conn, TRUE);

    /* Set up a timed event to request the server version every
     * five seconds and print it to the screen.
     */
    request_version_timed(event_ctx,dbus_conn);

    /* Enter the main loop (and hopefully never return) */
    event_loop_wait(event_ctx);

    talloc_free(event_ctx);
    return EXIT_SUCCESS;
}
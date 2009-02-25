#include <sys/time.h>
#include "tevent.h"
#include "dbus/dbus.h"
#include "util/util.h"

struct timeval _dbus_timeout_get_interval_tv(int interval) {
    struct timeval tv;
    struct timeval rightnow;

    gettimeofday(&rightnow,NULL);

    tv.tv_sec = interval / 1000 + rightnow.tv_sec;
    tv.tv_usec = (interval % 1000) * 1000 + rightnow.tv_usec;
    return tv;
}

/*
 * sbus_remove_watch
 * Hook for D-BUS to remove file descriptor-based events
 * from the libevents mainloop
 */
void sbus_remove_watch(DBusWatch *watch, void *data) {
    struct tevent_fd *fde;

    DEBUG(5, ("%lX\n", watch));
    fde = talloc_get_type(dbus_watch_get_data(watch), struct tevent_fd);

    /* Freeing the event object will remove it from the event loop */
    talloc_free(fde);
    dbus_watch_set_data(watch, NULL, NULL);
}


/*
 * sbus_remove_timeout
 * Hook for D-BUS to remove time-based events from the mainloop
 */
void sbus_remove_timeout(DBusTimeout *timeout, void *data) {
    struct tevent_timer *te;
    te = talloc_get_type(dbus_timeout_get_data(timeout), struct tevent_timer);

    /* Freeing the event object will remove it from the event loop */
    talloc_free(te);
    dbus_timeout_set_data(timeout, NULL, NULL);
}

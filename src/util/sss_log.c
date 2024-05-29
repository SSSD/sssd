/*
    SSSD

    sss_log.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include "util/util.h"

#if defined(WITH_JOURNALD)
#include <systemd/sd-journal.h>
#elif defined(WITH_STDERR_SYSLOG)
#include <stdio.h>
#define LOG_DAEMON 0
#else
#include <syslog.h>
#endif

#if !defined(WITH_STDERR_SYSLOG)
static int sss_to_syslog(int priority)
{
    switch(priority) {
    case SSS_LOG_EMERG:
        return LOG_EMERG;
    case SSS_LOG_ALERT:
        return LOG_ALERT;
    case SSS_LOG_CRIT:
        return LOG_CRIT;
    case SSS_LOG_ERR:
        return LOG_ERR;
    case SSS_LOG_WARNING:
        return LOG_WARNING;
    case SSS_LOG_NOTICE:
        return LOG_NOTICE;
    case SSS_LOG_INFO:
        return LOG_INFO;
    case SSS_LOG_DEBUG:
        return LOG_DEBUG;
    default:
        /* If we've been passed an invalid priority, it's
         * best to assume it's an emergency.
         */
        return LOG_EMERG;
    }
}
#endif

static void sss_log_internal(int priority, int facility, const char *format,
                             va_list ap);


void sss_log(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    sss_log_internal(priority, LOG_DAEMON, format, ap);
    va_end(ap);
}

void sss_log_ext(int priority, int facility, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    sss_log_internal(priority, facility, format, ap);
    va_end(ap);
}



#if defined(WITH_JOURNALD)

static void sss_log_internal(int priority, int facility, const char *format,
                             va_list ap)
{
    int syslog_priority;
    int ret;
    char *message;
    const char *domain;

    ret = vasprintf(&message, format, ap);

    if (ret == -1) {
        /* ENOMEM */
        return;
    }

    domain = getenv(SSS_DOM_ENV);
    if (domain == NULL) {
        domain = "";
    }

    syslog_priority = sss_to_syslog(priority);
    sd_journal_send("MESSAGE=%s", message,
                    "SSSD_DOMAIN=%s", domain,
                    "SSSD_PRG_NAME=sssd[%s]", debug_prg_name,
                    "PRIORITY=%i", syslog_priority,
                    "SYSLOG_FACILITY=%i", LOG_FAC(facility),
                    NULL);

    free(message);
}

#elif defined(WITH_STDERR_SYSLOG)

static void sss_log_internal(int, int, const char *format, va_list ap)
{
    fprintf(stderr, "%s: ", debug_prg_name);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
}

#else  /* SYSLOG */

static void sss_log_internal(int priority, int facility, const char *format,
                            va_list ap)
{
    int syslog_priority = sss_to_syslog(priority);

    vsyslog(facility|syslog_priority, format, ap);
}

#endif

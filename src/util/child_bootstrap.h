/*
    SSSD

    Helpers to do a basic setup (mostly of logging) of a child process.

    Copyright (C) 2025 Red Hat

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

#ifndef __CHILD_BOOTSTRAP_H__

#include <stdbool.h>
#include <popt.h>

#include "util/debug.h"

struct sss_child_basic_settings_t
{
    const char *opt_logger;
    int dumpable;
    bool ignore_dumpable; /* ldap_ and krb5_child ignore 'dumpable' argument */
    int backtrace;
    int debug_fd;
    long chain_id;
    const char *name;
    bool is_responder_invoked;
};

extern struct sss_child_basic_settings_t sss_child_basic_settings;

#define SSSD_BASIC_CHILD_OPTS \
    POPT_AUTOHELP \
    SSSD_DEBUG_OPTS \
    SSSD_LOGGER_OPTS(&sss_child_basic_settings.opt_logger) \
    {"dumpable", 0, POPT_ARG_INT, &sss_child_basic_settings.dumpable, 0, \
     sss_child_basic_settings.ignore_dumpable ? _("Ignored") : _("Allow core dumps"), NULL }, \
    {"backtrace", 0, POPT_ARG_INT, &sss_child_basic_settings.backtrace, 0, \
     _("Enable debug backtrace"), NULL }, \
    {"chain-id", 0, POPT_ARG_LONG, &sss_child_basic_settings.chain_id, \
     0, _("Tevent chain ID used for logging purposes"), NULL}, \
    {"debug-fd", 0, POPT_ARG_INT, &sss_child_basic_settings.debug_fd, 0, \
     _("An open file descriptor for the debug logs"), NULL},

bool sss_child_setup_basics(struct sss_child_basic_settings_t *settings);

#define __CHILD_BOOTSTRAP_H__

#endif /* __CHILD_BOOTSTRAP_H__ */

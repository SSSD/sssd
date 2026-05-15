/*
    SSSD

    Session recording utilities

    Authors:
        Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef __SESSION_RECORDING_H__
#define __SESSION_RECORDING_H__

#include "confdb/confdb.h"
#include "util/util_errors.h"

/** Scope of users/groups whose session should be recorded */
enum session_recording_scope {
    SESSION_RECORDING_SCOPE_NONE,   /**< None, no users/groups */
    SESSION_RECORDING_SCOPE_SOME,   /**< Some users/groups specified elsewhere */
    SESSION_RECORDING_SCOPE_ALL     /**< All users/groups */
};

/** Session recording configuration (from "session_recording" section) */
struct session_recording_conf {
    /**
     * Session recording scope:
     * whether to record nobody, everyone, or some users/groups
     */
    enum session_recording_scope    scope;
    /**
     * NULL-terminated list of users whose session should be recorded.
     * Can be NULL, meaning empty list. Only applicable if scope is "some".
     */
    char                          **users;
    /**
     * NULL-terminated list of groups, members of which should have their
     * sessions recorded. Can be NULL, meaning empty list. Only applicable if
     * scope is "some"
     */
    char                          **groups;
    /**
     * NULL-terminated list of users to be excluded from recording.
     * Can be NULL, meaning empty list. Only applicable if scope is "all".
     */
    char                          **exclude_users;
    /**
     * NULL-terminated list of groups, members of which should be excluded
     * from recording. Can be NULL, meaning empty list. Only applicable if
     * scope is "all"
     */
    char                          **exclude_groups;
};

/**
 * Load session recording configuration from configuration database.
 *
 * @param mem_ctx   Memory context to allocate data with.
 * @param cdb       The configuration database connection object to retrieve
 *                  data from.
 * @param pconf     Location for the loaded session recording configuration.
 *
 * @return Status code:
 *          ENOMEM - memory allocation failed,
 *          EINVAL - configuration was invalid,
 *          EIO - an I/O error occurred while communicating with the ConfDB.
 */
extern errno_t session_recording_conf_load(
                                    TALLOC_CTX *mem_ctx,
                                    struct confdb_ctx *cdb,
                                    struct session_recording_conf *pconf);

#endif /* __SESSION_RECORDING_H__ */

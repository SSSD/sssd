/*
   SSSD

   InfoPipe

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#ifndef INFOPIPE_H_
#define INFOPIPE_H_

#include <dbus/dbus.h>
#include "sbus/sssd_dbus.h"

#define INFP_INTROSPECT_XML "infopipe/org.freeipa.sssd.infopipe.Introspect.xml"

#define INFOPIPE_DBUS_NAME "org.freeipa.sssd.infopipe1"
#define INFOPIPE_INTERFACE "org.freeipa.sssd.infopipe1"
#define INFOPIPE_PATH "/org/freeipa/sssd/infopipe1"
#define INFOPIPE_VERSION 0x0001
#define INFOPIPE_SERVICE_NAME "infp"

/* InfoPipe Methods
 * NOTE: Any changes to the method names and arguments for these calls
 * must also be updated in the org.freeipa.sssd.infopipe.Introspect.xml
 * or clients may not behave properly.
 */

/**********************************************************
 * Introspection Methods (from infopipe.c)                *
 **********************************************************/

/* This function must be exposed through the
 * org.freedesktop.DBus.Introspectable interface
 */
#define INFP_INTROSPECT "Introspect"
int infp_introspect(DBusMessage *message, struct sbus_conn_ctx *sconn);

/**********************************************************
 * Permission Methods (from infopipe.c)                   *
 **********************************************************/
#define INFP_CHECK_PERMISSIONS "CheckPermissions1"
int infp_check_permissions(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_PERMISSION_METHODS \
    {INFP_CHECK_PERMISSIONS,infp_check_permissions},

/**********************************************************
 * User Methods (from infopipe_users.c)                   *
 **********************************************************/
#define INFP_USERS_GET_CACHED "GetCachedUsers1"
int infp_users_get_cached(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_USERS_CREATE "CreateUser1"
int infp_users_create(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_USERS_DELETE "DeleteUser1"
int infp_users_delete(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_USERS_GET_ATTR "GetUserAttributes1"
int infp_users_get_attr(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_USERS_SET_ATTR "SetUserAttributes1"
int infp_users_set_attr(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_USERS_SET_UID "Set_YouReallyDoNotWantToUseThisFunction_UserUID1"
int infp_users_set_uid(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_USER_METHODS \
    {INFP_USERS_GET_CACHED, infp_users_get_cached}, \
    {INFP_USERS_CREATE, infp_users_create}, \
    {INFP_USERS_DELETE, infp_users_delete}, \
    {INFP_USERS_GET_ATTR, infp_users_get_attr}, \
    {INFP_USERS_SET_ATTR, infp_users_set_attr}, \
    {INFP_USERS_SET_UID, infp_users_set_uid},

/**********************************************************
 * Group Methods (from infopipe_groups.c)                 *
 **********************************************************/

#define INFP_GROUPS_CREATE "CreateGroup1"
int infp_groups_create(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_GROUPS_DELETE "DeleteGroup1"
int infp_groups_delete(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_GROUPS_ADD_MEMBERS "AddGroupMembers1"
int infp_groups_add_members(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_GROUPS_REMOVE_MEMBERS "RemoveGroupMembers1"
int infp_groups_remove_members(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_GROUPS_SET_GID "Set_YouReallyDoNotWantToUseThisFunction_GroupGID1"
int infp_groups_set_gid(DBusMessage *message, struct sbus_conn_ctx *sconn);

#define INFP_GROUP_METHODS \
    {INFP_GROUPS_CREATE, infp_groups_create}, \
    {INFP_GROUPS_DELETE, infp_groups_delete}, \
    {INFP_GROUPS_ADD_MEMBERS, infp_groups_add_members}, \
    {INFP_GROUPS_REMOVE_MEMBERS, infp_groups_remove_members}, \
    {INFP_GROUPS_SET_GID, infp_groups_set_gid},

#endif /* INFOPIPE_H_ */

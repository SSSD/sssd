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

#ifndef INFOPIPE_PRIVATE_H_
#define INFOPIPE_PRIVATE_H_

struct infp_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *cdb;
    struct service_sbus_ctx *ss_ctx;
    struct sysbus_ctx *sysbus;
    struct sysdb_ctx *sysdb;
    struct btreemap *domain_map;
    char *introspect_xml;

    int cache_timeout;
};

struct infp_req_ctx {
    struct infp_ctx *infp;
    struct sbus_conn_ctx *sconn;
    DBusMessage *req_message;
    bool check_provider;
    struct sss_domain_info *domain;
    char *caller;
};

enum infp_object_types {
    INFP_OBJ_TYPE_INVALID = 0,
    INFP_OBJ_TYPE_USER,
    INFP_OBJ_TYPE_GROUP
};
int infp_get_object_type(const char *obj);

enum infp_action_types {
    INFP_ACTION_TYPE_INVALID = 0,
    INFP_ACTION_TYPE_READ,
    INFP_ACTION_TYPE_CREATE,
    INFP_ACTION_TYPE_DELETE,
    INFP_ACTION_TYPE_MODIFY,
    INFP_ACTION_TYPE_ADDMEMBER,
    INFP_ACTION_TYPE_REMOVEMEMBER
};
int infp_get_action_type(const char *action);

enum infp_attribute_types {
    INFP_ATTR_TYPE_INVALID = 0,
    INFP_ATTR_TYPE_DEFAULTGROUP,
    INFP_ATTR_TYPE_GECOS,
    INFP_ATTR_TYPE_HOMEDIR,
    INFP_ATTR_TYPE_SHELL,
    INFP_ATTR_TYPE_FULLNAME,
    INFP_ATTR_TYPE_LOCALE,
    INFP_ATTR_TYPE_KEYBOARD,
    INFP_ATTR_TYPE_SESSION,
    INFP_ATTR_TYPE_LAST_LOGIN,
    INFP_ATTR_TYPE_USERPIC,
    INFP_ATTR_TYPE_USERID
};
int infp_get_attribute_type(const char *attribute);

int infp_get_user_attr_dbus_type(int attr_type, int *subtype);

bool infp_get_permissions(const char *caller,
                          struct sss_domain_info *domain,
                          int object_type,
                          const char *instance,
                          int action_type,
                          int action_attribute);

struct sss_domain_info *infp_get_domain_obj(struct infp_ctx *infp, const char *domain_name);

int infp_get_ldb_val_from_dbus(TALLOC_CTX *mem_ctx, DBusMessageIter *iter, struct ldb_val **value, int dbus_type, int subtype);

#endif /* INFOPIPE_PRIVATE_H_ */

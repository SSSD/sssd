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

enum object_types {
    INFP_OBJ_TYPE_INVALID = 0,
    INFP_OBJ_TYPE_USER,
    INFP_OBJ_TYPE_GROUP
};
int get_object_type(const char *obj);

enum action_types {
    INFP_ACTION_TYPE_INVALID = 0,
    INFP_ACTION_TYPE_CREATE,
    INFP_ACTION_TYPE_DELETE,
    INFP_ACTION_TYPE_MODIFY,
    INFP_ACTION_TYPE_ADDMEMBER,
    INFP_ACTION_TYPE_REMOVEMEMBER
};
int get_action_type(const char *action);

enum attribute_types {
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
    INFP_ATTR_TYPE_USERPIC
};
int get_attribute_type(const char *attribute);

bool infp_get_permissions(const char *username,
                          const char *domain,
                          int object_type,
                          const char *instance,
                          int action_type,
                          int action_attribute);

#endif /* INFOPIPE_PRIVATE_H_ */

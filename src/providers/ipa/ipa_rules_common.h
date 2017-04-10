/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef IPA_RULES_COMMON_H_
#define IPA_RULES_COMMON_H_

#include "providers/backend.h"

#define IPA_UNIQUE_ID "ipauniqueid"

#define OBJECTCLASS "objectclass"
#define IPA_MEMBER_USER "memberUser"
#define IPA_USER_CATEGORY "userCategory"
#define IPA_EXTERNAL_HOST "externalHost"
#define IPA_ENABLED_FLAG "ipaenabledflag"
#define IPA_MEMBER_HOST "memberHost"
#define IPA_HOST_CATEGORY "hostCategory"
#define IPA_CN "cn"
#define IPA_TRUE_VALUE "TRUE"

/* From ipa_rules_common.c */
errno_t
ipa_common_entries_and_groups_sysdb_save(struct sss_domain_info *domain,
                                         const char *primary_subdir,
                                         const char *attr_name,
                                         size_t primary_count,
                                         struct sysdb_attrs **primary,
                                         const char *group_subdir,
                                         const char *groupattr_name,
                                         size_t group_count,
                                         struct sysdb_attrs **groups);

#endif /* IPA_RULES_COMMON_H_ */

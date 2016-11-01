/*
   SSSD

   Authors:
       Fabiano Fidêncio <fidencio@redhat.com>

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

#ifndef IPA_DESKPROFILE_PRIVATE_H_
#define IPA_DESKPROFILE_PRIVATE_H_

#define IPA_DESKPROFILE_CONFIG "ipaDeskProfileConfig"
#define IPA_DESKPROFILE_RULE "ipaDeskProfileRule"
#define IPA_DESKPROFILE_PRIORITY "ipaDeskProfilePriority"
#define IPA_DESKPROFILE_DATA "ipaDeskData"

#define DESKPROFILE_HOSTS_SUBDIR "deskprofile_hosts"
#define DESKPROFILE_HOSTGROUPS_SUBDIR "deskprofile_hostgroups"

#define IPA_SESSION_RULE_TYPE "sessionRuleType"

#define IPA_DESKPROFILE_BASE_TMPL "cn=desktop-profile,%s"

#define SYSDB_DESKPROFILE_BASE_TMPL "cn=desktop-profile,"SYSDB_TMPL_CUSTOM_BASE

#define DESKPROFILE_RULES_SUBDIR "deskprofile_rules"

#define DESKPROFILE_CONFIG_SUBDIR "deskprofile_config"

struct deskprofile_rule {
    const char *name;
    int priority;
    const char *data;
};

#endif /* IPA_DESKPROFILE_PRIVATE_H_ */

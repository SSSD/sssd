/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#ifndef _SYSDB_SUDO_H_
#define _SYSDB_SUDO_H_

#include "db/sysdb.h"

/* subdirs in cn=custom in sysdb. We don't store sudo stuff in sysdb directly
 * b/c it's not name-service-switch data */
#define SUDORULE_SUBDIR "sudorules"

/* attribute of SUDORULE_SUBDIR
 * should be true if we have downloaded all rules atleast once */
#define SYSDB_SUDO_AT_REFRESHED      "refreshed"
#define SYSDB_SUDO_AT_LAST_FULL_REFRESH "sudoLastFullRefreshTime"

/* sysdb attributes */
#define SYSDB_SUDO_CACHE_OC            "sudoRule"
#define SYSDB_SUDO_CACHE_AT_CN         "cn"
#define SYSDB_SUDO_CACHE_AT_USER       "sudoUser"
#define SYSDB_SUDO_CACHE_AT_HOST       "sudoHost"
#define SYSDB_SUDO_CACHE_AT_COMMAND    "sudoCommand"
#define SYSDB_SUDO_CACHE_AT_OPTION     "sudoOption"
#define SYSDB_SUDO_CACHE_AT_RUNAS      "sudoRunAs"
#define SYSDB_SUDO_CACHE_AT_RUNASUSER  "sudoRunAsUser"
#define SYSDB_SUDO_CACHE_AT_RUNASGROUP "sudoRunAsGroup"
#define SYSDB_SUDO_CACHE_AT_NOTBEFORE  "sudoNotBefore"
#define SYSDB_SUDO_CACHE_AT_NOTAFTER   "sudoNotAfter"
#define SYSDB_SUDO_CACHE_AT_ORDER      "sudoOrder"

/* sysdb ipa attributes */
#define SYSDB_IPA_SUDORULE_OC                 "ipasudorule"
#define SYSDB_IPA_SUDORULE_ENABLED            "ipaEnabledFlag"
#define SYSDB_IPA_SUDORULE_OPTION             "ipaSudoOpt"
#define SYSDB_IPA_SUDORULE_RUNASUSER          "ipaSudoRunAs"
#define SYSDB_IPA_SUDORULE_RUNASGROUP         "ipaSudoRunAsGroup"
#define SYSDB_IPA_SUDORULE_ORIGCMD            "originalMemberCommand"
#define SYSDB_IPA_SUDORULE_ALLOWCMD           "memberAllowCmd"
#define SYSDB_IPA_SUDORULE_DENYCMD            "memberDenyCmd"
#define SYSDB_IPA_SUDORULE_HOST               "memberHost"
#define SYSDB_IPA_SUDORULE_USER               "memberUser"
#define SYSDB_IPA_SUDORULE_NOTAFTER           "sudoNotAfter"
#define SYSDB_IPA_SUDORULE_NOTBEFORE          "sudoNotBefore"
#define SYSDB_IPA_SUDORULE_SUDOORDER          "sudoOrder"
#define SYSDB_IPA_SUDORULE_CMDCATEGORY        "cmdCategory"
#define SYSDB_IPA_SUDORULE_HOSTCATEGORY       "hostCategory"
#define SYSDB_IPA_SUDORULE_USERCATEGORY       "userCategory"
#define SYSDB_IPA_SUDORULE_RUNASUSERCATEGORY  "ipaSudoRunAsUserCategory"
#define SYSDB_IPA_SUDORULE_RUNASGROUPCATEGORY "ipaSudoRunAsGroupCategory"
#define SYSDB_IPA_SUDORULE_RUNASEXTUSER       "ipaSudoRunAsExtUser"
#define SYSDB_IPA_SUDORULE_RUNASEXTGROUP      "ipaSudoRunAsExtGroup"
#define SYSDB_IPA_SUDORULE_RUNASEXTUSERGROUP  "ipaSudoRunAsExtUserGroup"
#define SYSDB_IPA_SUDORULE_EXTUSER            "externalUser"

#define SYSDB_IPA_SUDOCMDGROUP_OC                 "ipasudocmdgrp"

#define SYSDB_IPA_SUDOCMD_OC                 "ipasudocmd"
#define SYSDB_IPA_SUDOCMD_SUDOCMD            "sudoCmd"

/* When constructing a sysdb filter, OR these values to include..   */
#define SYSDB_SUDO_FILTER_NONE           0x00       /* no additional filter */
#define SYSDB_SUDO_FILTER_USERNAME       0x01       /* username             */
#define SYSDB_SUDO_FILTER_UID            0x02       /* uid                  */
#define SYSDB_SUDO_FILTER_GROUPS         0x04       /* groups               */
#define SYSDB_SUDO_FILTER_NGRS           0x08       /* netgroups            */
#define SYSDB_SUDO_FILTER_ONLY_EXPIRED   0x10       /* only expired         */
#define SYSDB_SUDO_FILTER_INCLUDE_ALL    0x20       /* ALL                  */
#define SYSDB_SUDO_FILTER_INCLUDE_DFL    0x40       /* include cn=default   */
#define SYSDB_SUDO_FILTER_USERINFO       SYSDB_SUDO_FILTER_USERNAME \
                                       | SYSDB_SUDO_FILTER_UID \
                                       | SYSDB_SUDO_FILTER_GROUPS \
                                       | SYSDB_SUDO_FILTER_NGRS

errno_t sysdb_sudo_filter_rules_by_time(TALLOC_CTX *mem_ctx,
                                        uint32_t in_num_rules,
                                        struct sysdb_attrs **in_rules,
                                        time_t now,
                                        uint32_t *_num_rules,
                                        struct sysdb_attrs ***_rules);

char *
sysdb_sudo_filter_expired(TALLOC_CTX *mem_ctx,
                          const char *username,
                          char **groupnames,
                          uid_t uid);

char *
sysdb_sudo_filter_defaults(TALLOC_CTX *mem_ctx);

char *
sysdb_sudo_filter_user(TALLOC_CTX *mem_ctx,
                       const char *username,
                       char **groupnames,
                       uid_t uid);

char *
sysdb_sudo_filter_netgroups(TALLOC_CTX *mem_ctx,
                            const char *username,
                            char **groupnames,
                            uid_t uid);

errno_t
sysdb_get_sudo_user_info(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *username,
                         const char **_orig_name,
                         uid_t *_uid,
                         char ***_groupnames);

errno_t sysdb_sudo_set_last_full_refresh(struct sss_domain_info *domain,
                                         time_t value);
errno_t sysdb_sudo_get_last_full_refresh(struct sss_domain_info *domain,
                                         time_t *value);

errno_t sysdb_sudo_purge(struct sss_domain_info *domain,
                         const char *delete_filter,
                         struct sysdb_attrs **rules,
                         size_t num_rules);

errno_t
sysdb_sudo_store(struct sss_domain_info *domain,
                 struct sysdb_attrs **rules,
                 size_t num_rules);

errno_t
sysdb_search_sudo_rules(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *sub_filter,
                        const char **attrs,
                        size_t *_msgs_count,
                        struct ldb_message ***_msgs);

errno_t
sysdb_set_sudo_rule_attr(struct sss_domain_info *domain,
                         const char *name,
                         struct sysdb_attrs *attrs,
                         int mod_op);

#endif /* _SYSDB_SUDO_H_ */

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

#ifndef IPA_DESKPROFILE_RULES_UTIL_H_
#define IPA_DESKPROFILE_RULES_UTIL_H_

#include "db/sysdb.h"

#ifndef IPA_DESKPROFILE_RULES_USER_DIR
#define IPA_DESKPROFILE_RULES_USER_DIR  SSS_STATEDIR"/deskprofile"
#endif /* IPA_DESKPROFILE_RULES_USER_DIR */

errno_t
ipa_deskprofile_get_filename_path(TALLOC_CTX *mem_ctx,
                                  uint16_t config_priority,
                                  const char *rules_dir,
                                  const char *domain,
                                  const char *username,
                                  const char *priority,
                                  const char *user_priority,
                                  const char *group_priority,
                                  const char *host_priority,
                                  const char *hostgroup_priority,
                                  const char *rule_name,
                                  const char *extension,
                                  char **_filename_path);

errno_t
ipa_deskprofile_rules_create_user_dir(
                                    const char *username, /* fully-qualified */
                                    uid_t uid,
                                    gid_t gid);
errno_t
ipa_deskprofile_rules_save_rule_to_disk(
                                    TALLOC_CTX *mem_ctx,
                                    uint16_t priority,
                                    struct sysdb_attrs *rule,
                                    struct sss_domain_info *domain,
                                    const char *hostname,
                                    const char *username, /* fully-qualified */
                                    uid_t uid,
                                    gid_t gid);
errno_t
ipa_deskprofile_rules_remove_user_dir(const char *user_dir,
                                      uid_t uid,
                                      gid_t gid);

errno_t
deskprofile_get_cached_priority(struct sss_domain_info *domain,
                                uint16_t *_priority);

const char **
deskprofile_get_attrs_to_get_cached_rules(TALLOC_CTX *mem_ctx);

#endif /* IPA_DESKPROFILE_RULES_UTIL_H_ */

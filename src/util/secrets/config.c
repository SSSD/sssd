/*
   SSSD

   Local secrets database -- configuration

   Copyright (C) Red Hat 2018

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
#include "util/secrets/secrets.h"

errno_t sss_sec_get_quota(struct confdb_ctx *cdb,
                          const char *section_config_path,
                          int default_max_containers_nest_level,
                          int default_max_num_secrets,
                          int default_max_num_uid_secrets,
                          int default_max_payload,
                          struct sss_sec_quota *quota)
{
    int ret;

    if (cdb == NULL || section_config_path == NULL || quota == NULL) {
        return EINVAL;
    }

    ret = confdb_get_int(cdb,
                         section_config_path,
                         CONFDB_SEC_CONTAINERS_NEST_LEVEL,
                         default_max_containers_nest_level,
                         &quota->containers_nest_level);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get container nesting level for %s\n",
              section_config_path);
        return ret;
    }

    ret = confdb_get_int(cdb,
                         section_config_path,
                         CONFDB_SEC_MAX_SECRETS,
                         default_max_num_secrets,
                         &quota->max_secrets);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get maximum number of entries for %s\n",
              section_config_path);
        return ret;
    }

    ret = confdb_get_int(cdb,
                         section_config_path,
                         CONFDB_SEC_MAX_UID_SECRETS,
                         default_max_num_uid_secrets,
                         &quota->max_uid_secrets);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get maximum number of per-UID entries for %s\n",
              section_config_path);
        return ret;
    }

    ret = confdb_get_int(cdb,
                         section_config_path,
                         CONFDB_SEC_MAX_PAYLOAD_SIZE,
                         default_max_payload,
                         &quota->max_payload_size);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get payload's maximum size for an entry in %s\n",
              section_config_path);
        return ret;
    }

    return EOK;
}

errno_t sss_sec_get_hive_config(struct confdb_ctx *cdb,
                                const char *hive_name,
                                int default_max_containers_nest_level,
                                int default_max_num_secrets,
                                int default_max_num_uid_secrets,
                                int default_max_payload,
                                struct sss_sec_hive_config *hive_config)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    const char *confdb_section;

    if (cdb == NULL || hive_name == NULL || hive_config == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    hive_config->hive_name = hive_name;

    confdb_section = talloc_asprintf(tmp_ctx, "config/secrets/%s", hive_name);
    if (confdb_section == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_sec_get_quota(cdb,
                            confdb_section,
                            default_max_containers_nest_level,
                            default_max_num_secrets,
                            default_max_num_uid_secrets,
                            default_max_payload,
                            &hive_config->quota);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot read quota settings for %s [%d]: %s\n",
              hive_name, ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

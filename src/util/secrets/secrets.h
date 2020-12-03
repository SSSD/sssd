/*
   SSSD

   Local secrets database

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

#ifndef __SECRETS_H_
#define __SECRETS_H_

#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <talloc.h>

#include "confdb/confdb.h"

#define DEFAULT_SEC_CONTAINERS_NEST_LEVEL 4

#define DEFAULT_SEC_MAX_SECRETS      1024
#define DEFAULT_SEC_MAX_UID_SECRETS  256
#define DEFAULT_SEC_MAX_PAYLOAD_SIZE 16

/* The number of secrets in the /kcm hive should be quite small,
 * but the secret size must be large because one secret in the /kcm
 * hive holds the whole ccache which consists of several credentials
 */
#define DEFAULT_SEC_KCM_MAX_SECRETS      0          /* unlimited */
#define DEFAULT_SEC_KCM_MAX_UID_SECRETS  64
#define DEFAULT_SEC_KCM_MAX_PAYLOAD_SIZE 65536

enum sss_sec_enctype {
    SSS_SEC_PLAINTEXT,
    SSS_SEC_MASTERKEY,
    SSS_SEC_ENCTYPE_SENTINEL
};

struct sss_sec_ctx;

struct sss_sec_req;

struct sss_sec_quota_opt {
    const char *opt_name;
    int default_value;
};

struct sss_sec_quota {
    int max_secrets;
    int max_uid_secrets;
    int max_payload_size;
    int containers_nest_level;
};

struct sss_sec_hive_config {
    const char *hive_name;
    struct sss_sec_quota quota;
};

errno_t sss_sec_map_path(TALLOC_CTX *mem_ctx,
                         const char *url,
                         uid_t client,
                         char **_mapped_path);

errno_t sss_sec_init(TALLOC_CTX *mem_ctx,
                     struct sss_sec_hive_config **config_list,
                     struct sss_sec_ctx **_sec_ctx);

errno_t sss_sec_new_req(TALLOC_CTX *mem_ctx,
                        struct sss_sec_ctx *sec_ctx,
                        const char *url,
                        uid_t client,
                        struct sss_sec_req **_req);

errno_t sss_sec_delete(struct sss_sec_req *req);

errno_t sss_sec_list(TALLOC_CTX *mem_ctx,
                     struct sss_sec_req *req,
                     char ***_keys,
                     size_t *num_keys);

errno_t sss_sec_get(TALLOC_CTX *mem_ctx,
                    struct sss_sec_req *req,
                    uint8_t **_secret,
                    size_t *_secret_len,
                    char **_datatype);

errno_t sss_sec_put(struct sss_sec_req *req,
                    uint8_t *secret,
                    size_t secret_len,
                    enum sss_sec_enctype enctype,
                    const char *datatype);

errno_t sss_sec_update(struct sss_sec_req *req,
                       uint8_t *secret,
                       size_t secret_len,
                       enum sss_sec_enctype enctype,
                       const char *datatype);

errno_t sss_sec_create_container(struct sss_sec_req *req);

bool sss_sec_req_is_list(struct sss_sec_req *req);


errno_t sss_sec_get_quota(struct confdb_ctx *cdb,
                          const char *section_config_path,
                          struct sss_sec_quota_opt *dfl_max_containers_nest_level,
                          struct sss_sec_quota_opt *dfl_max_num_secrets,
                          struct sss_sec_quota_opt *dfl_max_num_uid_secrets,
                          struct sss_sec_quota_opt *dfl_max_payload,
                          struct sss_sec_quota *quota);

errno_t sss_sec_get_hive_config(struct confdb_ctx *cdb,
                                const char *hive_name,
                                struct sss_sec_quota_opt *dfl_max_containers_nest_level,
                                struct sss_sec_quota_opt *dfl_max_num_secrets,
                                struct sss_sec_quota_opt *dfl_max_num_uid_secrets,
                                struct sss_sec_quota_opt *dfl_max_payload,
                                struct sss_sec_hive_config *hive_config);

#endif /* __SECRETS_H_ */

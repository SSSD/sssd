/*
   SSSD

   System Database - initialization

   Copyright (C) 2008-2011 Simo Sorce <ssorce@redhat.com>
   Copyright (C) 2008-2011 Stephen Gallagher <ssorce@redhat.com>

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
#include "util/strtonum.h"
#include "util/sss_utf8.h"
#include "db/sysdb_private.h"
#include "confdb/confdb.h"
#include "util/probes.h"
#include <time.h>

#define LDB_MODULES_PATH "LDB_MODULES_PATH"

/* If an entry differs only in these attributes, they are written to
 * the timestamp cache only. In addition, objectclass/objectcategory is added
 * so that we can distinguish between users and groups.
 */
const char *sysdb_ts_cache_attrs[] = {
    SYSDB_OBJECTCLASS,
    SYSDB_OBJECTCATEGORY,
    SYSDB_LAST_UPDATE,
    SYSDB_CACHE_EXPIRE,
    SYSDB_ORIG_MODSTAMP,
    SYSDB_INITGR_EXPIRE,
    SYSDB_USN,

    NULL,
};

errno_t sysdb_ldb_connect(TALLOC_CTX *mem_ctx,
                          const char *filename,
                          int flags,
                          struct ldb_context **_ldb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    struct ldb_context *ldb;
    char *mod_path = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (_ldb == NULL) {
        ret = EINVAL;
        goto done;
    }

    ldb = ldb_init(mem_ctx, NULL);
    if (!ldb) {
        ret = EIO;
        goto done;
    }

    ret = ldb_set_debug(ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = sss_getenv(tmp_ctx, LDB_MODULES_PATH, NULL, &mod_path);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_ALL, "Setting ldb module path to [%s].\n", mod_path);
        ldb_set_modules_dir(ldb, mod_path);
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_ALL, "No ldb module path set in env\n");
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_getenv() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = ldb_connect(ldb, filename, flags, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }

    *_ldb = ldb;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sysdb_ldb_reconnect(TALLOC_CTX *mem_ctx,
                                   const char *ldb_file,
                                   int flags,
                                   struct ldb_context **ldb)
{
    errno_t ret;

    talloc_zfree(*ldb);
    ret = sysdb_ldb_connect(mem_ctx, ldb_file, flags, ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
    }

    return ret;
}

static errno_t sysdb_chown_db_files(struct sysdb_ctx *sysdb,
                                    uid_t uid, gid_t gid)
{
    errno_t ret;

    ret = chown(sysdb->ldb_file, uid, gid);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot set sysdb ownership of %s to %"SPRIuid":%"SPRIgid"\n",
              sysdb->ldb_file, uid, gid);
        return ret;
    }

    if (sysdb->ldb_ts_file != NULL) {
        ret = chown(sysdb->ldb_ts_file, uid, gid);
        if (ret != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot set sysdb ownership of %s to %"SPRIuid":%"SPRIgid"\n",
                  sysdb->ldb_ts_file, uid, gid);
            return ret;
        }
    }

    return EOK;
}

int sysdb_get_db_file(TALLOC_CTX *mem_ctx,
                      const char *provider,
                      const char *name,
                      const char *base_path,
                      char **_ldb_file,
                      char **_ts_file)
{
    char *ldb_file = NULL;
    char *ts_file = NULL;

    if (_ldb_file != NULL) {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"CACHE_SYSDB_FILE,
                                   base_path, name);
        if (!ldb_file) {
            return ENOMEM;
        }
    }
    if (_ts_file != NULL) {
        ts_file = talloc_asprintf(mem_ctx, "%s/"CACHE_TIMESTAMPS_FILE,
                                  base_path, name);
        if (!ts_file) {
            talloc_free(ldb_file);
            return ENOMEM;
        }
    }

    if (_ldb_file != NULL) {
        *_ldb_file = ldb_file;
    }
    if (_ts_file != NULL) {
        *_ts_file = ts_file;
    }

    return EOK;
}

static errno_t sysdb_domain_create_int(struct ldb_context *ldb,
                                       const char *domain_name)
{
    struct ldb_message *msg;
    TALLOC_CTX *tmp_ctx;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* == create base domain object == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ldb, SYSDB_DOM_BASE, domain_name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "cn", domain_name);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to initialize DB (%d, [%s]) "
                                     "for domain %s!\n",
                                     ret, ldb_errstring(ldb),
                                     domain_name);
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    /* == create Users tree == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ldb,
                             SYSDB_TMPL_USER_BASE, domain_name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "cn", "Users");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to initialize DB (%d, [%s]) "
                                     "for domain %s!\n",
                                     ret, ldb_errstring(ldb),
                                     domain_name);
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    /* == create Groups tree == */

    msg = ldb_msg_new(tmp_ctx);
    if (!msg) {
        ret = ENOMEM;
        goto done;
    }
    msg->dn = ldb_dn_new_fmt(msg, ldb,
                             SYSDB_TMPL_GROUP_BASE, domain_name);
    if (!msg->dn) {
        ret = ENOMEM;
        goto done;
    }
    ret = ldb_msg_add_string(msg, "cn", "Groups");
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    /* do a synchronous add */
    ret = ldb_add(ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to initialize DB (%d, [%s]) for "
                                     "domain %s!\n",
                                     ret, ldb_errstring(ldb),
                                     domain_name);
        ret = EIO;
        goto done;
    }
    talloc_zfree(msg);

    ret = EOK;

done:
    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t sysdb_domain_create(struct sysdb_ctx *sysdb, const char *domain_name)
{
    return sysdb_domain_create_int(sysdb->ldb, domain_name);
}

/* Compare versions of sysdb, returns ERRNO accordingly */
static errno_t
sysdb_version_check(const char *expected,
                    const char *received)
{
    int ret;
    unsigned int exp_major, exp_minor, recv_major, recv_minor;

    if (strcmp(received, expected) == 0) {
        return EOK;
    }

    ret = sscanf(expected, "%u.%u", &exp_major, &exp_minor);
    if (ret != 2) {
        return EINVAL;
    }
    ret = sscanf(received, "%u.%u", &recv_major, &recv_minor);
    if (ret != 2) {
        return EINVAL;
    }

    if (recv_major > exp_major) {
        return ERR_SYSDB_VERSION_TOO_NEW;
    } else if (recv_major < exp_major) {
        return ERR_SYSDB_VERSION_TOO_OLD;
    }

    if (recv_minor > exp_minor) {
        return ERR_SYSDB_VERSION_TOO_NEW;
    } else if (recv_minor < exp_minor) {
        return ERR_SYSDB_VERSION_TOO_OLD;
    }

    return EOK;
}

static errno_t sysdb_cache_add_base_ldif(struct ldb_context *ldb,
                                         const char *base_ldif,
                                         const char *domain_name)
{
    int ret;
    struct ldb_ldif *ldif;

    while ((ldif = ldb_ldif_read_string(ldb, &base_ldif))) {
        ret = ldb_add(ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to initialize DB (%d, [%s]) for domain %s!\n",
                  ret, ldb_errstring(ldb), domain_name);
            return EIO;
        }
        ldb_ldif_read_free(ldb, ldif);
    }

    return EOK;
}

static errno_t sysdb_cache_create_empty(struct ldb_context *ldb,
                                        const char *base_ldif,
                                        struct sss_domain_info *domain)
{
    int ret;

    ret = sysdb_cache_add_base_ldif(ldb, base_ldif, domain->name);
    if (ret != EOK) {
        return ret;
    }

    ret = sysdb_domain_create_int(ldb, domain->name);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

static errno_t sysdb_ts_cache_upgrade(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      struct ldb_context *ldb,
                                      struct sss_domain_info *domain,
                                      const char *cur_version,
                                      const char **_new_version)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *version;
    struct ldb_context *save_ldb;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* The upgrade process depends on having ldb around, yet the upgrade
     * function shouldn't set the ldb pointer, only the connect function
     * should after it's successful. To avoid hard refactoring, save the
     * ldb pointer here and restore in the 'done' handler
     */
    save_ldb = sysdb->ldb;
    sysdb->ldb = ldb;

    version = talloc_strdup(tmp_ctx, cur_version);
    if (version == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Upgrading timstamp cache of DB [%s] from version: %s\n",
          domain->name, version);

    if (strcmp(version, SYSDB_TS_VERSION_0_1) == 0) {
        ret = sysdb_ts_upgrade_01(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    sysdb->ldb = save_ldb;
    *_new_version = version;
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sysdb_domain_cache_upgrade(TALLOC_CTX *mem_ctx,
                                          struct sysdb_ctx *sysdb,
                                          struct sysdb_dom_upgrade_ctx *upgrade_ctx,
                                          struct ldb_context *ldb,
                                          struct sss_domain_info *domain,
                                          const char *cur_version,
                                          const char **_new_version)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    const char *version;
    struct ldb_context *save_ldb;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* The upgrade process depends on having ldb around, yet the upgrade
     * function shouldn't set the ldb pointer, only the connect function
     * should after it's successful. To avoid hard refactoring, save the
     * ldb pointer here and restore in the 'done' handler
     */
    save_ldb = sysdb->ldb;
    sysdb->ldb = ldb;

    version = talloc_strdup(tmp_ctx, cur_version);
    if (version == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Upgrading DB [%s] from version: %s\n",
          domain->name, version);

    if (strcmp(version, SYSDB_VERSION_0_3) == 0) {
        ret = sysdb_upgrade_03(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_4) == 0) {
        ret = sysdb_upgrade_04(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_5) == 0) {
        ret = sysdb_upgrade_05(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_6) == 0) {
        ret = sysdb_upgrade_06(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_7) == 0) {
        ret = sysdb_upgrade_07(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_8) == 0) {
        ret = sysdb_upgrade_08(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_9) == 0) {
        ret = sysdb_upgrade_09(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_10) == 0) {
        ret = sysdb_upgrade_10(sysdb, domain, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_11) == 0) {
        ret = sysdb_upgrade_11(sysdb, domain, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_12) == 0) {
        ret = sysdb_upgrade_12(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_13) == 0) {
        ret = sysdb_upgrade_13(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_14) == 0) {
        ret = sysdb_upgrade_14(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_15) == 0) {
        ret = sysdb_upgrade_15(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_16) == 0) {
        ret = sysdb_upgrade_16(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_17) == 0) {
        ret = sysdb_upgrade_17(sysdb, upgrade_ctx, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_18) == 0) {
        ret = sysdb_upgrade_18(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_19) == 0) {
        ret = sysdb_upgrade_19(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_20) == 0) {
        ret = sysdb_upgrade_20(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_21) == 0) {
        ret = sysdb_upgrade_21(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    if (strcmp(version, SYSDB_VERSION_0_22) == 0) {
        ret = sysdb_upgrade_22(sysdb, &version);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;
done:
    sysdb->ldb = save_ldb;
    *_new_version = version;
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t remove_ts_cache(struct sysdb_ctx *sysdb)
{
    errno_t ret;

    if (sysdb->ldb_ts_file == NULL) {
        return EOK;
    }

    ret = unlink(sysdb->ldb_ts_file);
    if (ret != EOK && errno != ENOENT) {
        return errno;
    }

    return EOK;
}

static errno_t sysdb_cache_connect_helper(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *domain,
                                          const char *ldb_file,
                                          int flags,
                                          const char *exp_version,
                                          const char *base_ldif,
                                          bool *_newly_created,
                                          struct ldb_context **_ldb,
                                          const char **_version)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    int ret;
    struct ldb_context *ldb;
    bool newly_created = false;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_ldb_connect(tmp_ctx, ldb_file, flags, &ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
        goto done;
    }

    verdn = ldb_dn_new(tmp_ctx, ldb, SYSDB_BASE);
    if (!verdn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(ldb, tmp_ctx, &res,
                     verdn, LDB_SCOPE_BASE,
                     NULL, NULL);
    if (ret != LDB_SUCCESS) {
        ret = EIO;
        goto done;
    }
    if (res->count > 1) {
        ret = EIO;
        goto done;
    }

    if (res->count == 1) {
        el = ldb_msg_find_element(res->msgs[0], "version");
        if (!el) {
            ret = EIO;
            goto done;
        }

        if (el->num_values != 1) {
            ret = EINVAL;
            goto done;
        }
        version = talloc_strndup(tmp_ctx,
                                 (char *)(el->values[0].data),
                                 el->values[0].length);
        if (!version) {
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_version_check(exp_version, version);
        /* This is not the latest version. Return what version it is
         * and appropriate error
         */
        *_ldb = talloc_steal(mem_ctx, ldb);
        *_version = talloc_steal(mem_ctx, version);
        goto done;
    }

    /* SYSDB_BASE does not exists, means db is empty, populate */
    ret = sysdb_cache_create_empty(ldb, base_ldif, domain);
    if (ret != EOK) {
        goto done;
    }

    newly_created = true;

    /* We need to reopen the LDB to ensure that
     * all of the special values take effect
     * (such as enabling the memberOf plugin and
     * the various indexes).
     */
    ret = sysdb_ldb_reconnect(tmp_ctx, ldb_file, flags, &ldb);
    if (ret != EOK) {
        goto done;
    }

    /* If we connect to a new database, then the version is the
     * latest one
     */
    *_version = talloc_strdup(mem_ctx, exp_version);
    if (*_version == NULL) {
        ret = ENOMEM;
        goto done;
    }
done:
    if (ret == EOK) {
        if (_newly_created != NULL) {
            *_newly_created = newly_created;
        }
        *_ldb = talloc_steal(mem_ctx, ldb);
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sysdb_cache_connect(TALLOC_CTX *mem_ctx,
                                   struct sysdb_ctx *sysdb,
                                   struct sss_domain_info *domain,
                                   struct ldb_context **ldb,
                                   const char **version)
{
    bool newly_created;
    bool ldb_file_exists;
    errno_t ret;

    ldb_file_exists = !(access(sysdb->ldb_file, F_OK) == -1 && errno == ENOENT);

    ret = sysdb_cache_connect_helper(mem_ctx, domain, sysdb->ldb_file,
                                      0, SYSDB_VERSION, SYSDB_BASE_LDIF,
                                      &newly_created, ldb, version);

    /* The cache has been newly created. */
    if (ret == EOK && newly_created && !ldb_file_exists) {
        ret = remove_ts_cache(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not delete the timestamp ldb file (%d) (%s)\n",
                  ret, sss_strerror(ret));
        }
    }

    return ret;
}

static errno_t sysdb_ts_cache_connect(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      struct sss_domain_info *domain,
                                      struct ldb_context **ldb,
                                      const char **version)
{
    return sysdb_cache_connect_helper(mem_ctx, domain, sysdb->ldb_ts_file,
                                      LDB_FLG_NOSYNC, SYSDB_TS_VERSION,
                                      SYSDB_TS_BASE_LDIF, NULL,
                                      ldb, version);
}

static int sysdb_domain_cache_connect(struct sysdb_ctx *sysdb,
                                      struct sss_domain_info *domain,
                                      struct sysdb_dom_upgrade_ctx *upgrade_ctx)
{
    errno_t ret;
    const char *version = NULL;
    TALLOC_CTX *tmp_ctx;
    struct ldb_context *ldb;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_cache_connect(tmp_ctx, sysdb, domain, &ldb, &version);
    switch (ret) {
    case ERR_SYSDB_VERSION_TOO_OLD:
        if (upgrade_ctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "DB version too old [%s], expected [%s] for domain %s!\n",
                   version, SYSDB_VERSION, domain->name);
            goto done;
        }

        ret = sysdb_domain_cache_upgrade(tmp_ctx, sysdb, upgrade_ctx,
                                         ldb, domain, version, &version);
        if (ret != EOK) {
            goto done;
        }

        /* To be on the safe side, nuke the timestamp cache on upgrades.
         * This is just a one-time performance hit after an upgrade
         */
        ret = remove_ts_cache(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not delete the timestamp ldb file (%d) (%s)\n",
                  ret, sss_strerror(ret));
            return ret;
        }


        /* The version should now match SYSDB_VERSION.
         * If not, it means we didn't match any of the
         * known older versions. The DB might be
         * corrupt or generated by a newer version of
         * SSSD.
         */
        ret = sysdb_version_check(SYSDB_VERSION, version);
        if (ret == EOK) {
            /* The cache has been upgraded.
             * We need to reopen the LDB to ensure that
             * any changes made above take effect.
             */
            ret = sysdb_ldb_reconnect(tmp_ctx, sysdb->ldb_file, 0, &ldb);
            goto done;
        }
        break;
    case ERR_SYSDB_VERSION_TOO_NEW:
        DEBUG(SSSDBG_FATAL_FAILURE,
              "DB version too new [%s], expected [%s] for domain %s!\n",
              version, SYSDB_VERSION, domain->name);
        break;
    default:
        break;
    }

done:
    if (ret == EOK) {
        sysdb->ldb = talloc_steal(sysdb, ldb);
    }
    talloc_free(tmp_ctx);
    return ret;
}

static int sysdb_timestamp_cache_connect(struct sysdb_ctx *sysdb,
                                         struct sss_domain_info *domain,
                                         struct sysdb_dom_upgrade_ctx *upgrade_ctx)
{
    errno_t ret;
    const char *version;
    TALLOC_CTX *tmp_ctx;
    struct ldb_context *ldb;

    if (sysdb->ldb_ts_file == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, "No timestamp cache for %s\n", domain->name);
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_ts_cache_connect(tmp_ctx, sysdb, domain, &ldb, &version);
    switch (ret) {
    case ERR_SYSDB_VERSION_TOO_OLD:
        if (upgrade_ctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "DB version too old [%s], expected [%s] for domain %s!\n",
                   version, SYSDB_VERSION, domain->name);
            break;
        }

        ret = sysdb_ts_cache_upgrade(tmp_ctx, sysdb, ldb, domain, version,
                                     &version);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not upgrade the timestamp ldb file (%d) (%s)\n",
                  ret, sss_strerror(ret));
            break;
        }

        /* The version should now match SYSDB_VERSION.
         * If not, it means we didn't match any of the
         * known older versions. The DB might be
         * corrupt or generated by a newer version of
         * SSSD.
         */
        ret = sysdb_version_check(SYSDB_TS_VERSION, version);
        if (ret == EOK) {
            /* The cache has been upgraded.
             * We need to reopen the LDB to ensure that
             * any changes made above take effect.
             */
            ret = sysdb_ldb_reconnect(tmp_ctx,
                                      sysdb->ldb_ts_file,
                                      LDB_FLG_NOSYNC,
                                      &ldb);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not reopen the timestamp ldb file (%d) (%s)\n",
                      ret, sss_strerror(ret));
            }
        }
        break;
    case ERR_SYSDB_VERSION_TOO_NEW:
        DEBUG(SSSDBG_MINOR_FAILURE,
              "DB version too new [%s], expected [%s] for domain %s!\n",
              version, SYSDB_TS_VERSION, domain->name);
        break;
    default:
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "The timestamps cache could not be opened. "
              "Throwing away the database and opening a new one\n");

        ret = remove_ts_cache(sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not delete the timestamp ldb file (%d) (%s)\n",
                  ret, sss_strerror(ret));
            return ret;
        }

        /* Now the connect must succeed because the previous cache doesn't
         * exist anymore.
         */
        ret = sysdb_ts_cache_connect(tmp_ctx, sysdb, domain, &ldb, &version);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not delete the timestamp ldb file (%d) (%s)\n",
                  ret, sss_strerror(ret));
        }
    }

    if (ret == EOK) {
        sysdb->ldb_ts = talloc_steal(sysdb, ldb);
    }
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_domain_init_internal(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *db_path,
                               struct sysdb_dom_upgrade_ctx *upgrade_ctx,
                               struct sysdb_ctx **_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_ctx *sysdb;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    sysdb = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (!sysdb) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_db_file(sysdb, domain->provider, domain->name, db_path,
                            &sysdb->ldb_file, &sysdb->ldb_ts_file);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(SSSDBG_FUNC_DATA,
          "DB File for %s: %s\n", domain->name, sysdb->ldb_file);
    if (sysdb->ldb_ts_file) {
        DEBUG(SSSDBG_FUNC_DATA,
             "Timestamp file for %s: %s\n", domain->name, sysdb->ldb_ts_file);
    }

    ret = sysdb_domain_cache_connect(sysdb, domain, upgrade_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not open the sysdb cache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_timestamp_cache_connect(sysdb, domain, upgrade_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not open the timestamp cache [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    if (ret == EOK) {
        *_ctx = talloc_steal(mem_ctx, sysdb);
    }
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct sss_domain_info *domains)
{
    return sysdb_init_ext(mem_ctx, domains, NULL, false, 0, 0);
}

int sysdb_init_ext(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domains,
                   struct sysdb_upgrade_ctx *upgrade_ctx,
                   bool chown_dbfile,
                   uid_t uid,
                   gid_t gid)
{
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_dom_upgrade_ctx *dom_upgrade_ctx;

    if (upgrade_ctx != NULL) {
        /* check if we have an old sssd.ldb to upgrade */
        ret = sysdb_check_upgrade_02(domains, DB_PATH);
        if (ret != EOK) {
            return ret;
        }
    }

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* open a db for each domain */
    for (dom = domains; dom; dom = dom->next) {
        if (upgrade_ctx) {
            dom_upgrade_ctx = talloc_zero(tmp_ctx,
                                          struct sysdb_dom_upgrade_ctx);

            ret = sss_names_init(tmp_ctx,
                                 upgrade_ctx->cdb,
                                 dom->name,
                                 &dom_upgrade_ctx->names);
            if (ret != EOK) {
                goto done;
            }
        } else {
            dom_upgrade_ctx = NULL;
        }

        ret = sysdb_domain_init_internal(tmp_ctx, dom, DB_PATH,
                                         dom_upgrade_ctx, &sysdb);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot connect to database for %s: [%d]: %s\n",
                  dom->name, ret, sss_strerror(ret));
            goto done;
        }

        if (chown_dbfile) {
            ret = sysdb_chown_db_files(sysdb, uid, gid);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Cannot chown databases for %s: [%d]: %s\n",
                      dom->name, ret, sss_strerror(ret));
                goto done;
            }
        }

        dom->sysdb = talloc_move(dom, &sysdb);
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx)
{
    return sysdb_domain_init_internal(mem_ctx, domain,
                                      db_path, false, _ctx);
}

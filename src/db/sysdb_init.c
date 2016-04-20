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

errno_t sysdb_ldb_connect(TALLOC_CTX *mem_ctx, const char *filename,
                          struct ldb_context **_ldb)
{
    int ret;
    struct ldb_context *ldb;
    const char *mod_path;

    if (_ldb == NULL) {
        return EINVAL;
    }

    ldb = ldb_init(mem_ctx, NULL);
    if (!ldb) {
        return EIO;
    }

    ret = ldb_set_debug(ldb, ldb_debug_messages, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    mod_path = getenv(LDB_MODULES_PATH);
    if (mod_path != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Setting ldb module path to [%s].\n", mod_path);
        ldb_set_modules_dir(ldb, mod_path);
    }

    ret = ldb_connect(ldb, filename, 0, NULL);
    if (ret != LDB_SUCCESS) {
        return EIO;
    }

    *_ldb = ldb;

    return EOK;
}

int sysdb_get_db_file(TALLOC_CTX *mem_ctx,
                      const char *provider, const char *name,
                      const char *base_path, char **_ldb_file)
{
    char *ldb_file;

    /* special case for the local domain */
    if (strcasecmp(provider, "local") == 0) {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"LOCAL_SYSDB_FILE,
                                   base_path);
    } else {
        ldb_file = talloc_asprintf(mem_ctx, "%s/"CACHE_SYSDB_FILE,
                                   base_path, name);
    }
    if (!ldb_file) {
        return ENOMEM;
    }

    *_ldb_file = ldb_file;
    return EOK;
}

errno_t sysdb_domain_create(struct sysdb_ctx *sysdb, const char *domain_name)
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
    msg->dn = ldb_dn_new_fmt(msg, sysdb->ldb, SYSDB_DOM_BASE, domain_name);
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
    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to initialize DB (%d, [%s]) "
                                     "for domain %s!\n",
                                     ret, ldb_errstring(sysdb->ldb),
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
    msg->dn = ldb_dn_new_fmt(msg, sysdb->ldb,
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
    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to initialize DB (%d, [%s]) "
                                     "for domain %s!\n",
                                     ret, ldb_errstring(sysdb->ldb),
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
    msg->dn = ldb_dn_new_fmt(msg, sysdb->ldb,
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
    ret = ldb_add(sysdb->ldb, msg);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to initialize DB (%d, [%s]) for "
                                     "domain %s!\n",
                                     ret, ldb_errstring(sysdb->ldb),
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

/* Compare versions of sysdb, returns ERRNO accordingly */
static errno_t
sysdb_version_check(const char *expected,
                    const char *received)
{
    int ret;
    unsigned int exp_major, exp_minor, recv_major, recv_minor;

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

int sysdb_domain_init_internal(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *db_path,
                               bool allow_upgrade,
                               struct sysdb_ctx **_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_ctx *sysdb;
    const char *base_ldif;
    struct ldb_ldif *ldif;
    struct ldb_message_element *el;
    struct ldb_result *res;
    struct ldb_dn *verdn;
    const char *version = NULL;
    int ret;

    sysdb = talloc_zero(mem_ctx, struct sysdb_ctx);
    if (!sysdb) {
        return ENOMEM;
    }

    ret = sysdb_get_db_file(sysdb, domain->provider,
                            domain->name, db_path,
                            &sysdb->ldb_file);
    if (ret != EOK) {
        goto done;
    }
    DEBUG(SSSDBG_FUNC_DATA,
          "DB File for %s: %s\n", domain->name, sysdb->ldb_file);

    ret = sysdb_ldb_connect(sysdb, sysdb->ldb_file, &sysdb->ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto done;
    }

    verdn = ldb_dn_new(tmp_ctx, sysdb->ldb, SYSDB_BASE);
    if (!verdn) {
        ret = EIO;
        goto done;
    }

    ret = ldb_search(sysdb->ldb, tmp_ctx, &res,
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

        if (strcmp(version, SYSDB_VERSION) == 0) {
            /* all fine, return */
            ret = EOK;
            goto done;
        }

        if (!allow_upgrade) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Wrong DB version (got %s expected %s)\n",
                   version, SYSDB_VERSION);
            ret = sysdb_version_check(SYSDB_VERSION, version);
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "Upgrading DB [%s] from version: %s\n",
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

        /* The version should now match SYSDB_VERSION.
         * If not, it means we didn't match any of the
         * known older versions. The DB might be
         * corrupt or generated by a newer version of
         * SSSD.
         */
        if (strcmp(version, SYSDB_VERSION) == 0) {
            /* The cache has been upgraded.
             * We need to reopen the LDB to ensure that
             * any changes made above take effect.
             */
            talloc_zfree(sysdb->ldb);
            ret = sysdb_ldb_connect(sysdb, sysdb->ldb_file, &sysdb->ldb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
            }
            goto done;
        }

        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unknown DB version [%s], expected [%s] for domain %s!\n",
              version, SYSDB_VERSION, domain->name);
        ret = sysdb_version_check(SYSDB_VERSION, version);
        goto done;
    }

    /* SYSDB_BASE does not exists, means db is empty, populate */

    base_ldif = SYSDB_BASE_LDIF;
    while ((ldif = ldb_ldif_read_string(sysdb->ldb, &base_ldif))) {
        ret = ldb_add(sysdb->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to initialize DB (%d, [%s]) for domain %s!\n",
                      ret, ldb_errstring(sysdb->ldb), domain->name);
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(sysdb->ldb, ldif);
    }

    ret = sysdb_domain_create(sysdb, domain->name);
    if (ret != EOK) {
        goto done;
    }

    /* The cache has been newly created.
     * We need to reopen the LDB to ensure that
     * all of the special values take effect
     * (such as enabling the memberOf plugin and
     * the various indexes).
     */
    talloc_zfree(sysdb->ldb);
    ret = sysdb_ldb_connect(sysdb, sysdb->ldb_file, &sysdb->ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_ldb_connect failed.\n");
    }

done:
    talloc_free(tmp_ctx);
    if (ret == EOK) {
        *_ctx = sysdb;
    } else {
        talloc_free(sysdb);
    }
    return ret;
}

int sysdb_init(TALLOC_CTX *mem_ctx,
               struct sss_domain_info *domains,
               bool allow_upgrade)
{
    return sysdb_init_ext(mem_ctx, domains, allow_upgrade, false, 0, 0);
}

int sysdb_init_ext(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domains,
                   bool allow_upgrade,
                   bool chown_dbfile,
                   uid_t uid,
                   gid_t gid)
{
    struct sss_domain_info *dom;
    struct sysdb_ctx *sysdb;
    int ret;

    if (allow_upgrade) {
        /* check if we have an old sssd.ldb to upgrade */
        ret = sysdb_check_upgrade_02(domains, DB_PATH);
        if (ret != EOK) {
            return ret;
        }
    }

    /* open a db for each domain */
    for (dom = domains; dom; dom = dom->next) {

        ret = sysdb_domain_init_internal(mem_ctx, dom, DB_PATH,
                                         allow_upgrade, &sysdb);
        if (ret != EOK) {
            return ret;
        }

        if (chown_dbfile) {
            ret = chown(sysdb->ldb_file, uid, gid);
            if (ret != 0) {
                ret = errno;
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Cannot set sysdb ownership to %"SPRIuid":%"SPRIgid"\n",
                      uid, gid);
                return ret;
            }
        }

        dom->sysdb = talloc_move(dom, &sysdb);
    }

    return EOK;
}

int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx)
{
    return sysdb_domain_init_internal(mem_ctx, domain,
                                      db_path, false, _ctx);
}

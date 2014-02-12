/*
   SSSD

   Configuration Database

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

#include "config.h"
#include <sys/stat.h>
#include "util/util.h"
#include "db/sysdb.h"
#include "confdb.h"
#include "confdb_private.h"
#include "confdb_setup.h"
#include "util/sss_ini.h"


int confdb_test(struct confdb_ctx *cdb)
{
    char **values;
    int ret;

    ret = confdb_get_param(cdb, cdb,
                           "config",
                           "version",
                           &values);
    if (ret != EOK) {
        return ret;
    }

    if (values[0] == NULL) {
        /* empty database, will need to init */
        talloc_free(values);
        return ENOENT;
    }

    if (values[1] != NULL) {
        /* more than 1 value ?? */
        talloc_free(values);
        return EIO;
    }

    if (strcmp(values[0], CONFDB_VERSION) != 0) {
        /* Existing version does not match executable version */
        DEBUG(SSSDBG_CRIT_FAILURE, "Upgrading confdb version from %s to %s\n",
                  values[0], CONFDB_VERSION);

        /* This is recoverable, since we purge the confdb file
         * when we re-initialize it.
         */
        talloc_free(values);
        return ENOENT;
    }

    talloc_free(values);
    return EOK;
}

static int confdb_purge(struct confdb_ctx *cdb)
{
    int ret, i;
    TALLOC_CTX *tmp_ctx;
    struct ldb_result *res;
    struct ldb_dn *dn;
    const char *attrs[] = { "dn", NULL };

    tmp_ctx = talloc_new(NULL);

    dn = ldb_dn_new(tmp_ctx, cdb->ldb, "cn=config");

    /* Get the list of all DNs */
    ret = ldb_search(cdb->ldb, tmp_ctx, &res, dn,
                     LDB_SCOPE_SUBTREE, attrs, NULL);
    if (ret != LDB_SUCCESS) {
        ret = sysdb_error_to_errno(ret);
        goto done;
    }

    for(i=0; i<res->count; i++) {
        /* Delete this DN */
        ret = ldb_delete(cdb->ldb, res->msgs[i]->dn);
        if (ret != LDB_SUCCESS) {
            ret = sysdb_error_to_errno(ret);
            goto done;
        }
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

int confdb_create_base(struct confdb_ctx *cdb)
{
    int ret;
    struct ldb_ldif *ldif;

    const char *base_ldif = CONFDB_BASE_LDIF;

    while ((ldif = ldb_ldif_read_string(cdb->ldb, &base_ldif))) {
        ret = ldb_add(cdb->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to initialize DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(cdb->ldb));
            return EIO;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    return EOK;
}

int confdb_init_db(const char *config_file, struct confdb_ctx *cdb)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int sret = EOK;
    int version;
    char timestr[21];
    char *lasttimestr;
    bool in_transaction = false;
    const char *config_ldif;
    const char *vals[2] = { timestr, NULL };
    struct ldb_ldif *ldif;
    struct sss_ini_initdata *init_data;


    tmp_ctx = talloc_new(cdb);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        return ENOMEM;
    }

    init_data = sss_ini_initdata_init(tmp_ctx);
    if (!init_data) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Open config file */
    ret = sss_ini_config_file_open(init_data, config_file);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "sss_ini_config_file_open failed: %s [%d]\n", strerror(ret),
               ret);
        if (ret == ENOENT) {
            /* sss specific error denoting missing configuration file */
            ret = ERR_MISSING_CONF;
        }
        goto done;
    }

    ret = sss_ini_config_access_check(init_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Permission check on config file failed.\n");
        ret = EPERM;
        goto done;
    }

    /* Determine if the conf file has changed since we last updated
     * the confdb
     */
    ret = sss_ini_get_stat(init_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Status check on config file failed.\n");
        ret = errno;
        goto done;
    }

    errno = 0;

    ret = sss_ini_get_mtime(init_data, sizeof(timestr), timestr);
    if (ret <= 0 || ret >= sizeof(timestr)) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to convert time_t to string ??\n");
        ret = errno ? errno : EFAULT;
    }
    ret = confdb_get_string(cdb, tmp_ctx, "config", "lastUpdate",
                            NULL, &lasttimestr);
    if (ret == EOK) {

        /* check if we lastUpdate and last file modification change differ*/
        if ((lasttimestr != NULL) && (strcmp(lasttimestr, timestr) == 0)) {
            /* not changed, get out, nothing more to do */
            ret = EOK;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to get lastUpdate attribute.\n");
        goto done;
    }

    ret = sss_ini_get_config(init_data, config_file);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to load configuration\n");
        goto done;
    }

    /* Make sure that the config file version matches the confdb version */
    ret = sss_ini_get_cfgobj(init_data, "sssd", "config_file_version");
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Internal error determining config_file_version\n");
        goto done;
    }

    ret = sss_ini_check_config_obj(init_data);
    if (ret != EOK) {
        /* No known version. Assumed to be version 1 */
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Config file is an old version. "
               "Please run configuration upgrade script.\n");
        ret = EINVAL;
        goto done;
    }

    version = sss_ini_get_int_config_value(init_data, 1, -1, &ret);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Config file version could not be determined\n");
        goto done;
    } else if (version < CONFDB_VERSION_INT) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Config file is an old version. "
                 "Please run configuration upgrade script.\n");
        ret = EINVAL;
        goto done;
    } else if (version > CONFDB_VERSION_INT) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Config file version is newer than confdb\n");
        ret = EINVAL;
        goto done;
    }

    /* Set up a transaction to replace the configuration */
    ret = ldb_transaction_start(cdb->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to start a transaction for "
               "updating the configuration\n");
        ret = sysdb_error_to_errno(ret);
        goto done;
    }
    in_transaction = true;

    /* Purge existing database */
    ret = confdb_purge(cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not purge existing configuration\n");
        goto done;
    }

    ret = sss_confdb_create_ldif(tmp_ctx, init_data, &config_ldif);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not create LDIF for confdb\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "LDIF file to import: \n%s", config_ldif);

    while ((ldif = ldb_ldif_read_string(cdb->ldb, &config_ldif))) {
        ret = ldb_add(cdb->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                    "Failed to initialize DB (%d,[%s]), aborting!\n",
                     ret, ldb_errstring(cdb->ldb));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    /* now store the lastUpdate time so that we do not re-init if nothing
     * changed on restart */

    ret = confdb_add_param(cdb, true, "config", "lastUpdate", vals);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to set last update time on db!\n");
        goto done;
    }

    ret = ldb_transaction_commit(cdb->ldb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;

done:
    if (in_transaction) {
        sret = ldb_transaction_cancel(cdb->ldb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }

    sss_ini_config_destroy(init_data);
    sss_ini_close_file(init_data);

    talloc_zfree(tmp_ctx);
    return ret;
}

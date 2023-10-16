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

#define CONFDB_BASE_LDIF \
     "dn: @ATTRIBUTES\n" \
     "cn: CASE_INSENSITIVE\n" \
     "dc: CASE_INSENSITIVE\n" \
     "dn: CASE_INSENSITIVE\n" \
     "name: CASE_INSENSITIVE\n" \
     "objectclass: CASE_INSENSITIVE\n" \
     "\n" \
     "dn: @INDEXLIST\n" \
     "@IDXATTR: cn\n" \
     "\n" \
     "dn: @MODULES\n" \
     "@LIST: server_sort\n" \
     "\n"


errno_t confdb_read_ini(TALLOC_CTX *mem_ctx,
                        const char *config_file,
                        const char *config_dir,
                        bool allow_missing_file,
                        struct sss_ini **_ini)
{
    int ret;

    *_ini = sss_ini_new(mem_ctx);
    if (*_ini == NULL) {
        return ENOMEM;
    }

    ret = sss_ini_read_sssd_conf(*_ini, config_file, config_dir);
    if (ret != EOK) {
        if ((ret == ERR_INI_EMPTY_CONFIG) && allow_missing_file) {
            return EOK;
        }
        talloc_zfree(*_ini);
        return ret;
    }

    return EOK;
}

static int confdb_create_base(struct confdb_ctx *cdb)
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

static int confdb_write_ldif(struct confdb_ctx *cdb, const char *config_ldif)
{
    int ret;
    struct ldb_ldif *ldif;

    while ((ldif = ldb_ldif_read_string(cdb->ldb, &config_ldif))) {
        if (ldif->changetype == LDB_CHANGETYPE_DELETE) {
            /* We should remove this section */
            ret = ldb_delete(cdb->ldb, ldif->msg->dn);
            if (ret == LDB_ERR_NO_SUCH_OBJECT) {
                /* Removing a non-existing section is not an error */
                ret = LDB_SUCCESS;
            }
        } else {
            ret = ldb_add(cdb->ldb, ldif->msg);
        }

        if (ret != LDB_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to update DB (%d,[%s]), aborting!\n",
                ret, ldb_errstring(cdb->ldb));
            return EIO;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    return EOK;
}

static int confdb_populate(const struct sss_ini *ini,
                           const char *only_section,
                           struct confdb_ctx *cdb,
                           bool allow_missing_content)
{
    TALLOC_CTX *tmp_ctx;
    int ret;
    int sret = EOK;
    bool in_transaction = false;
    const char *config_ldif;

    tmp_ctx = talloc_new(cdb);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory.\n");
        return ENOMEM;
    }

    ret = sss_confdb_create_ldif(tmp_ctx, ini, only_section, &config_ldif);
    if (ret != EOK) {
        if ((ret == ERR_INI_EMPTY_CONFIG) && allow_missing_content) {
            DEBUG(SSSDBG_TRACE_FUNC, "Empty configuration. Using the defaults.\n");
            ret = EOK;
            goto done;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot convert INI to LDIF [%d]: [%s]\n",
                ret, sss_strerror(ret));
            goto done;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "LDIF file to import: \n%s\n", config_ldif);

    /* Set up a transaction to replace the configuration */
    ret = ldb_transaction_start(cdb->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to start a transaction for "
               "updating the configuration\n");
        ret = sss_ldb_error_to_errno(ret);
        goto done;
    }
    in_transaction = true;

    ret = confdb_write_ldif(cdb, config_ldif);
    if (ret != EOK) {
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

    talloc_zfree(tmp_ctx);
    return ret;
}

errno_t confdb_write_ini(TALLOC_CTX *mem_ctx,
                         const struct sss_ini *ini,
                         const char *cdb_file,
                         const char *only_section,
                         bool allow_missing_content,
                         struct confdb_ctx **_cdb)
{
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *cdb;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = unlink(cdb_file);
    if ((ret == -1) && (errno != ENOENT)) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE, "Can't delete old '%s'\n", cdb_file);
        goto done;
    }

    ret = confdb_init(tmp_ctx, &cdb, cdb_file);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "The confdb initialization failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Load special entries */
    ret = confdb_create_base(cdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to load special entries into confdb\n");
        goto done;
    }

    /* Initialize the CDB from the configuration file */
    ret = confdb_populate(ini, only_section, cdb, allow_missing_content);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "ConfDB initialization has failed "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_cdb = talloc_steal(mem_ctx, cdb);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t confdb_setup(TALLOC_CTX *mem_ctx,
                     const char *cdb_file,
                     const char *config_file,
                     const char *config_dir,
                     const char *only_section,
                     bool allow_missing_file,
                     struct confdb_ctx **_cdb)
{
    int ret;
    struct sss_ini *ini;

    ret = confdb_read_ini(mem_ctx, config_file, config_dir, allow_missing_file,
                          &ini);
    if (ret != EOK) {
        return ret;
    }

    ret = confdb_write_ini(mem_ctx, ini, cdb_file, only_section, allow_missing_file,
                           _cdb);

    talloc_free(ini);

    return ret;
}

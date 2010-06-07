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
#include "collection.h"
#include "collection_tools.h"
#include "ini_config.h"


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
        DEBUG(1, ("Upgrading confdb version from %s to %s\n",
                  values[0], CONFDB_VERSION));

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
            DEBUG(0, ("Failed to initialize DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(cdb->ldb)));
            return EIO;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    return EOK;
}

static int confdb_create_ldif(TALLOC_CTX *mem_ctx,
                              struct collection_item *sssd_config,
                              char **config_ldif)
{
    int ret, i, j;
    char *ldif;
    char *tmp_ldif;
    char *writer;
    char **sections;
    int section_count;
    char *dn;
    char *tmp_dn;
    char *sec_dn;
    char **attrs;
    int attr_count;
    char *ldif_attr;
    struct collection_item *attr;
    TALLOC_CTX *tmp_ctx;
    size_t dn_size;
    size_t ldif_len;
    size_t attr_len;

    ldif_len = strlen(CONFDB_INTERNAL_LDIF);
    ldif = talloc_array(mem_ctx, char, ldif_len+1);
    if (!ldif) return ENOMEM;

    tmp_ctx = talloc_new(ldif);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto error;
    }

    memcpy(ldif, CONFDB_INTERNAL_LDIF, ldif_len);
    writer = ldif+ldif_len;

    /* Read in the collection and convert it to an LDIF */
    /* Get the list of sections */
    sections = get_section_list(sssd_config, &section_count, &ret);
    if (ret != EOK) {
        goto error;
    }

    for(i = 0; i < section_count; i++) {
        const char *rdn = NULL;
        DEBUG(6,("Processing config section [%s]\n", sections[i]));
        ret = parse_section(tmp_ctx, sections[i], &sec_dn, &rdn);
        if (ret != EOK) {
            goto error;
        }

        dn = talloc_asprintf(tmp_ctx,
                             "dn: %s,cn=config\n"
                             "cn: %s\n",
                             sec_dn, rdn);
        if(!dn) {
            ret = ENOMEM;
            free_section_list(sections);
            goto error;
        }
        dn_size = strlen(dn);

        /* Get all of the attributes and their values as LDIF */
        attrs = get_attribute_list(sssd_config, sections[i],
                                   &attr_count, &ret);
        if (ret != EOK) {
            free_section_list(sections);
            goto error;
        }

        for(j = 0; j < attr_count; j++) {
            DEBUG(6, ("Processing attribute [%s]\n", attrs[j]));
            ret = get_config_item(sections[i], attrs[j], sssd_config,
                                   &attr);
            if (ret != EOK) goto error;

            const char *value = get_const_string_config_value(attr, &ret);
            if (ret != EOK) goto error;
            if (value && value[0] == '\0') {
                DEBUG(1, ("Attribute '%s' has empty value, ignoring\n", attrs[j]));
                continue;
            }

            ldif_attr = talloc_asprintf(tmp_ctx,
                                        "%s: %s\n", attrs[j], value);
            DEBUG(9, ("%s", ldif_attr));

            attr_len = strlen(ldif_attr);

            tmp_dn = talloc_realloc(tmp_ctx, dn, char,
                                    dn_size+attr_len+1);
            if(!tmp_dn) {
                ret = ENOMEM;
                free_attribute_list(attrs);
                free_section_list(sections);
                goto error;
            }
            dn = tmp_dn;
            memcpy(dn+dn_size, ldif_attr, attr_len+1);
            dn_size += attr_len;
        }

        dn_size ++;
        tmp_dn = talloc_realloc(tmp_ctx, dn, char,
                                dn_size+1);
        if(!tmp_dn) {
            ret = ENOMEM;
            free_attribute_list(attrs);
            free_section_list(sections);
            goto error;
        }
        dn = tmp_dn;
        dn[dn_size-1] = '\n';
        dn[dn_size] = '\0';

        DEBUG(9, ("Section dn\n%s", dn));

        tmp_ldif = talloc_realloc(mem_ctx, ldif, char,
                                  ldif_len+dn_size+1);
        if(!tmp_ldif) {
            ret = ENOMEM;
            free_attribute_list(attrs);
            free_section_list(sections);
            goto error;
        }
        ldif = tmp_ldif;
        memcpy(ldif+ldif_len, dn, dn_size);
        ldif_len += dn_size;

        free_attribute_list(attrs);
        talloc_free(dn);
    }

    ldif[ldif_len] = '\0';

    free_section_list(sections);

    *config_ldif = ldif;
    talloc_free(tmp_ctx);
    return EOK;

error:
    talloc_free(ldif);
    return ret;
}

int confdb_init_db(const char *config_file, struct confdb_ctx *cdb)
{
    int ret, i;
    int fd = -1;
    struct collection_item *sssd_config = NULL;
    struct collection_item *error_list = NULL;
    struct collection_item *item = NULL;
    char *config_ldif;
    struct ldb_ldif *ldif;
    TALLOC_CTX *tmp_ctx;
    char *lasttimestr, timestr[21];
    const char *vals[2] = { timestr, NULL };
    struct stat cstat;
    int version;

    tmp_ctx = talloc_new(cdb);
    if (tmp_ctx == NULL) return ENOMEM;

    ret = check_and_open_readonly(config_file, &fd, 0, 0, (S_IRUSR|S_IWUSR),
                                  CHECK_REG);
    if (ret != EOK) {
        DEBUG(1, ("Permission check on config file failed.\n"));
        talloc_zfree(tmp_ctx);
        return EPERM;
    }

    /* Determine if the conf file has changed since we last updated
     * the confdb
     */
    ret = fstat(fd, &cstat);
    if (ret != 0) {
        DEBUG(0, ("Unable to stat config file [%s]! (%d [%s])\n",
                  config_file, errno, strerror(errno)));
        close(fd);
        talloc_zfree(tmp_ctx);
        return errno;
    }
    ret = snprintf(timestr, 21, "%llu", (long long unsigned)cstat.st_mtime);
    if (ret <= 0 || ret >= 21) {
        DEBUG(0, ("Failed to convert time_t to string ??\n"));
        close(fd);
        talloc_zfree(tmp_ctx);
        return errno ? errno: EFAULT;
    }

    /* check if we need to re-init the db */
    ret = confdb_get_string(cdb, tmp_ctx, "config", "lastUpdate", NULL, &lasttimestr);
    if (ret == EOK && lasttimestr != NULL) {

        /* now check if we lastUpdate and last file modification change differ*/
        if (strcmp(lasttimestr, timestr) == 0) {
            /* not changed, get out, nothing more to do */
            close(fd);
            talloc_zfree(tmp_ctx);
            return EOK;
        }
    }

    /* Set up a transaction to replace the configuration */
    ret = ldb_transaction_start(cdb->ldb);
    if (ret != LDB_SUCCESS) {
        DEBUG(0, ("Failed to start a transaction for updating the configuration\n"));
        talloc_zfree(tmp_ctx);
        close(fd);
        return sysdb_error_to_errno(ret);
    }

    /* Purge existing database */
    ret = confdb_purge(cdb);
    if (ret != EOK) {
        DEBUG(0, ("Could not purge existing configuration\n"));
        close(fd);
        goto done;
    }

    /* Read the configuration into a collection */
    ret = config_from_fd("sssd", fd, config_file, &sssd_config,
                         INI_STOP_ON_ANY, &error_list);
    close(fd);
    if (ret != EOK) {
        DEBUG(0, ("Parse error reading configuration file [%s]\n",
                  config_file));
        print_file_parsing_errors(stderr, error_list);
        free_ini_config_errors(error_list);
        free_ini_config(sssd_config);
        goto done;
    }

    /* Make sure that the config file version matches the confdb version */
    ret = get_config_item("sssd", "config_file_version",
                          sssd_config, &item);
    if (ret != EOK) {
        DEBUG(0, ("Internal error determining config_file_version\n"));
        goto done;
    }
    if (item == NULL) {
        /* No known version. Assumed to be version 1 */
        DEBUG(0, ("Config file is an old version. "
                  "Please run configuration upgrade script.\n"));
        ret = EINVAL;
        goto done;
    }
    version = get_int_config_value(item, 1, -1, &ret);
    if (ret != EOK) {
        DEBUG(0, ("Config file version could not be determined\n"));
        goto done;
    } else if (version < CONFDB_VERSION_INT) {
        DEBUG(0, ("Config file is an old version. "
                  "Please run configuration upgrade script.\n"));
        ret = EINVAL;
        goto done;
    } else if (version > CONFDB_VERSION_INT) {
        DEBUG(0, ("Config file version is newer than confdb\n"));
        ret = EINVAL;
        goto done;
    }

    ret = confdb_create_ldif(tmp_ctx, sssd_config, &config_ldif);
    free_ini_config(sssd_config);
    if (ret != EOK) {
        DEBUG(0, ("Could not create LDIF for confdb\n"));
        goto done;
    }

    DEBUG(7, ("LDIF file to import: \n%s", config_ldif));

    i=0;
    while ((ldif = ldb_ldif_read_string(cdb->ldb, (const char **)&config_ldif))) {
        ret = ldb_add(cdb->ldb, ldif->msg);
        if (ret != LDB_SUCCESS) {
            DEBUG(0, ("Failed to initialize DB (%d,[%s]), aborting!\n",
                      ret, ldb_errstring(cdb->ldb)));
            ret = EIO;
            goto done;
        }
        ldb_ldif_read_free(cdb->ldb, ldif);
    }

    /* now store the lastUpdate time so that we do not re-init if nothing
     * changed on restart */

    ret = confdb_add_param(cdb, true, "config", "lastUpdate", vals);
    if (ret != EOK) {
        DEBUG(1, ("Failed to set last update time on db!\n"));
    }

    ret = EOK;

done:
    ret == EOK ?
            ldb_transaction_commit(cdb->ldb) :
            ldb_transaction_cancel(cdb->ldb);
    talloc_zfree(tmp_ctx);
    return ret;
}

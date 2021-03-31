/*
    SSSD

    sss_ini.c

    Authors:
        Ondrej Kos <okos@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <stdio.h>
#include <errno.h>
#include <talloc.h>

#include "config.h"
#include "util/util.h"
#include "util/sss_ini.h"
#include "confdb/confdb_setup.h"
#include "confdb/confdb_private.h"

#include "ini_configobj.h"
#include "ini_config.h"

struct sss_ini {
    char **error_list;
    struct ref_array *ra_success_list;
    struct ref_array *ra_error_list;
    struct ini_cfgobj *sssd_config;
    struct value_obj *obj;
    const struct stat *cstat;
    struct ini_cfgfile *file;
    bool main_config_exists;
};

#define sss_ini_get_sec_list                   ini_get_section_list
#define sss_ini_get_attr_list                  ini_get_attribute_list
#define sss_ini_get_const_string_config_value  ini_get_const_string_config_value
#define sss_ini_get_config_obj                 ini_get_config_valueobj


static void sss_ini_free_error_messages(struct sss_ini *self)
{
    if (self != NULL) {
        ini_config_free_errors(self->error_list);
        self->error_list = NULL;
    }
}

static void sss_ini_free_ra_messages(struct sss_ini *self)
{
    if (self != NULL) {
        ref_array_destroy(self->ra_success_list);
        self->ra_success_list = NULL;
        ref_array_destroy(self->ra_error_list);
        self->ra_error_list = NULL;
    }
}

static void sss_ini_free_config(struct sss_ini *self)
{
    if (self != NULL && self->sssd_config != NULL) {
        ini_config_destroy(self->sssd_config);
        self->sssd_config = NULL;
    }
}

/* Close file descriptor */

static void sss_ini_close_file(struct sss_ini *self)
{
    if (self != NULL && self->file != NULL) {
        ini_config_file_destroy(self->file);
        self->file = NULL;
    }
}

/* sss_ini destructor */

static int sss_ini_destroy(struct sss_ini *self)
{
    sss_ini_free_error_messages(self);
    sss_ini_free_ra_messages(self);
    sss_ini_free_config(self);
    sss_ini_close_file(self);
    return 0;
}

/* Initialize data structure */

struct sss_ini* sss_ini_new(TALLOC_CTX *mem_ctx)
{
    struct sss_ini *self;


    self = talloc_zero(mem_ctx, struct sss_ini);
    if (!self) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Not enough memory for sss_ini_data.\n");
        return NULL;
    }
    talloc_set_destructor(self, sss_ini_destroy);
    return self;
}

/* Open configuration file */

static int sss_ini_config_file_open(struct sss_ini *self,
                                    const char *config_file)
{
    int ret;

    if (self == NULL) {
        return EINVAL;
    }

    ret = ini_config_file_open(config_file,
                               INI_META_STATS,
                               &self->file);
    self->main_config_exists = (ret != ENOENT);
    return ret;
}

static int sss_ini_config_file_from_mem(struct sss_ini *self,
                                        void *data_buf,
                                        uint32_t data_len)
{
    if (self == NULL) {
        return EINVAL;
    }

    return ini_config_file_from_mem(data_buf, strlen(data_buf),
                                   &self->file);
}

/* Check configuration file permissions */

static int sss_ini_access_check(struct sss_ini *self)
{
    if (!self->main_config_exists) {
        return EOK;
    }

    return ini_config_access_check(self->file,
                                   INI_ACCESS_CHECK_MODE |
                                   INI_ACCESS_CHECK_UID |
                                   INI_ACCESS_CHECK_GID,
                                   0, /* owned by root */
                                   0, /* owned by root */
                                   S_IRUSR, /* r**------ */
                                   ALLPERMS & ~(S_IWUSR|S_IXUSR));
}



/* Get cstat */

int sss_ini_get_stat(struct sss_ini *self)
{
    self->cstat = ini_config_get_stat(self->file);

    if (!self->cstat) return EIO;

    return EOK;
}



/* Get mtime */

int sss_ini_get_mtime(struct sss_ini *self,
                      size_t timestr_len,
                      char *timestr)
{
    return snprintf(timestr, timestr_len, "%llu",
                    (long long unsigned)self->cstat->st_mtime);
}

/* Get file_exists */

bool sss_ini_exists(struct sss_ini *self)
{
    return self->main_config_exists;
}

/* Print ini_config errors */

static void sss_ini_config_print_errors(char **error_list)
{
    unsigned count = 0;

    if (!error_list) {
        return;
    }

    while (error_list[count]) {
        DEBUG(SSSDBG_FATAL_FAILURE, "%s\n", error_list[count]);
        count++;
    }
}

static int sss_ini_parse(struct sss_ini *self)
{
    int ret;

    if (!self) {
        return EINVAL;
    }

    sss_ini_free_error_messages(self);
    sss_ini_free_config(self);

    /* Create config object */
    ret = ini_config_create(&(self->sssd_config));
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to create config object. Error %d.\n", ret);
        return ret;
    }

    /* Parse file */
    ret = ini_config_parse(self->file,
                           INI_STOP_ON_ANY,
                           INI_MV1S_OVERWRITE,
                           INI_PARSE_NOWRAP,
                           self->sssd_config);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to parse configuration. Error %d.\n", ret);

        if (ini_config_error_count(self->sssd_config)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                    "Errors detected while parsing: %s\n",
                     ini_config_get_filename(self->file));

            ini_config_get_errors(self->sssd_config,
                                  &(self->error_list));
        }
    }
    return ret;
}

static int sss_ini_add_snippets(struct sss_ini *self,
                                const char *config_dir)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    int ret;
    const char *patterns[] = { "^[^\\.].*\\.conf$", NULL };
    const char *sections[] = { ".*", NULL };
    uint32_t i = 0;
    char *msg = NULL;
    struct ini_cfgobj *modified_sssd_config = NULL;
    struct access_check snip_check;

    if (self == NULL || self->sssd_config == NULL || config_dir == NULL) {
        return EINVAL;
    }

    sss_ini_free_ra_messages(self);

    snip_check.flags = INI_ACCESS_CHECK_MODE | INI_ACCESS_CHECK_UID
                       | INI_ACCESS_CHECK_GID;
    snip_check.uid = 0; /* owned by root */
    snip_check.gid = 0; /* owned by root */
    snip_check.mode = S_IRUSR; /* r**------ */
    snip_check.mask = ALLPERMS & ~(S_IWUSR | S_IXUSR);

    ret = ini_config_augment(self->sssd_config,
                             config_dir,
                             patterns,
                             sections,
                             &snip_check,
                             INI_STOP_ON_ANY,
                             INI_MV1S_OVERWRITE,
                             INI_PARSE_NOWRAP,
                             INI_MV2S_OVERWRITE,
                             &modified_sssd_config,
                             &self->ra_error_list,
                             &self->ra_success_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to augment configuration: Error %d",
              ret);
    }

    while (ref_array_get(self->ra_success_list, i, &msg) != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Config merge success: %s\n", msg);
        i++;
    }

    i = 0;
    while (ref_array_get(self->ra_error_list, i, &msg) != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Config merge error: %s\n", msg);
        i++;
    }

    /* switch config objects if there are no errors */
    if (modified_sssd_config != NULL) {
        ini_config_destroy(self->sssd_config);
        self->sssd_config = modified_sssd_config;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Using only main configuration file due to errors in merging\n");
    }
    return ret;

#else /* HAVE_LIBINI_CONFIG_V1_3 */
    return EOK;
#endif /* ! HAVE_LIBINI_CONFIG_V1_3 */
}

struct ref_array *
sss_ini_get_ra_success_list(struct sss_ini *self)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    return self->ra_success_list;
#else
    return NULL;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

struct ref_array *
sss_ini_get_ra_error_list(struct sss_ini *self)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    return self->ra_error_list;
#else
    return NULL;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

/* Get configuration object */

int sss_ini_get_cfgobj(struct sss_ini *self,
                       const char *section, const char *name)
{
    return sss_ini_get_config_obj(section,name, self->sssd_config,
                                  INI_GET_FIRST_VALUE, &self->obj);
}

/* Check configuration object */

int sss_ini_check_config_obj(struct sss_ini *self)
{
    if (self->obj == NULL) {
        return ENOENT;
    }

    return EOK;
}



/* Get integer value */

int sss_ini_get_int_config_value(struct sss_ini *self,
                                 int strict, int def, int *error)
{
    return ini_get_int_config_value(self->obj, strict, def, error);
}

/* Get string value */

const char *sss_ini_get_string_config_value(struct sss_ini *self,
                                            int *error)
{
    return ini_get_string_config_value(self->obj, error);
}

/* Create LDIF */

int sss_confdb_create_ldif(TALLOC_CTX *mem_ctx,
                           struct sss_ini *self,
                           const char *only_section,
                           const char **config_ldif)
{
    int ret, i, j;
    char *ldif;
    char *tmp_ldif;
    char **sections;
    int section_count;
    char *dn;
    char *tmp_dn;
    char *sec_dn;
    char **attrs;
    int attr_count;
    char *ldif_attr;
    TALLOC_CTX *tmp_ctx;
    size_t dn_size;
    size_t ldif_len;
    size_t attr_len;
    struct value_obj *obj = NULL;
    bool section_handled = true;

    if (only_section != NULL) {
        /* If the section is specified, we must handle it, either by adding
         * its contents or by deleting the section if it doesn't exist
         */
        section_handled = false;
    }

    ldif_len = strlen(CONFDB_INTERNAL_LDIF);
    ldif = talloc_array(mem_ctx, char, ldif_len+1);
    if (!ldif) return ENOMEM;

    tmp_ctx = talloc_new(ldif);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto error;
    }

    memcpy(ldif, CONFDB_INTERNAL_LDIF, ldif_len);

    /* Read in the collection and convert it to an LDIF */
    /* Get the list of sections */
    sections = sss_ini_get_sec_list(self->sssd_config,
                                    &section_count, &ret);
    if (ret != EOK) {
        goto error;
    }

    for (i = 0; i < section_count; i++) {
        const char *rdn = NULL;
        DEBUG(SSSDBG_TRACE_FUNC,
                "Processing config section [%s]\n", sections[i]);
        ret = parse_section(tmp_ctx, sections[i], &sec_dn, &rdn);
        if (ret != EOK) {
            goto error;
        }

        if (only_section != NULL) {
            if (strcasecmp(only_section, sections[i])) {
                DEBUG(SSSDBG_TRACE_FUNC, "Skipping section %s\n", sections[i]);
                continue;
            } else {
                /* Mark the requested section as handled so that we don't
                 * try to re-add it later
                 */
                section_handled = true;
            }
        }

        dn = talloc_asprintf(tmp_ctx,
                             "dn: %s,cn=config\n"
                             "cn: %s\n",
                             sec_dn, rdn);
        if (!dn) {
            ret = ENOMEM;
            free_section_list(sections);
            goto error;
        }
        dn_size = strlen(dn);

        /* Get all of the attributes and their values as LDIF */
        attrs = sss_ini_get_attr_list(self->sssd_config, sections[i],
                                   &attr_count, &ret);
        if (ret != EOK) {
            free_section_list(sections);
            goto error;
        }

        for (j = 0; j < attr_count; j++) {
            DEBUG(SSSDBG_TRACE_FUNC,
                    "Processing attribute [%s]\n", attrs[j]);
            ret = sss_ini_get_config_obj(sections[i], attrs[j],
                                         self->sssd_config,
                                         INI_GET_FIRST_VALUE, &obj);
            if (ret != EOK) goto error;

            const char *value = sss_ini_get_const_string_config_value(obj, &ret);
            if (ret != EOK) goto error;
            if (value && value[0] == '\0') {
                DEBUG(SSSDBG_CRIT_FAILURE,
                        "Attribute '%s' has empty value, ignoring\n",
                         attrs[j]);
                continue;
            }

            ldif_attr = talloc_asprintf(tmp_ctx,
                                        "%s: %s\n", attrs[j], value);
            DEBUG(SSSDBG_TRACE_ALL, "%s\n", ldif_attr);

            attr_len = strlen(ldif_attr);

            tmp_dn = talloc_realloc(tmp_ctx, dn, char,
                                    dn_size+attr_len+1);
            if (!tmp_dn) {
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
        if (!tmp_dn) {
            ret = ENOMEM;
            free_attribute_list(attrs);
            free_section_list(sections);
            goto error;
        }
        dn = tmp_dn;
        dn[dn_size-1] = '\n';
        dn[dn_size] = '\0';

        DEBUG(SSSDBG_TRACE_ALL, "Section dn\n%s\n", dn);

        tmp_ldif = talloc_realloc(mem_ctx, ldif, char,
                                  ldif_len+dn_size+1);
        if (!tmp_ldif) {
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


    if (only_section != NULL && section_handled == false) {
        /* If only a single section was supposed to be
         * handled, but it wasn't found in the INI file,
         * create an LDIF that would remove the section
         */
        ret = parse_section(tmp_ctx, only_section, &sec_dn, NULL);
        if (ret != EOK) {
            goto error;
        }

        dn = talloc_asprintf(tmp_ctx,
                             "dn: %s,cn=config\n"
                             "changetype: delete\n\n",
                             sec_dn);
        if (dn == NULL) {
            ret = ENOMEM;
            goto error;
        }
        dn_size = strlen(dn);

        tmp_ldif = talloc_realloc(mem_ctx, ldif, char,
                                  ldif_len+dn_size+1);
        if (!tmp_ldif) {
            ret = ENOMEM;
            goto error;
        }

        ldif = tmp_ldif;
        memcpy(ldif+ldif_len, dn, dn_size);
        ldif_len += dn_size;
    }

    ldif[ldif_len] = '\0';

    free_section_list(sections);

    *config_ldif = (const char *)ldif;
    talloc_free(tmp_ctx);
    return EOK;

error:
    talloc_free(ldif);
    return ret;
}

#ifdef HAVE_LIBINI_CONFIG_V1_3
/* Here we can put custom SSSD specific checks that can not be implemented
 * using libini validators */
static int custom_sssd_checks(const char *rule_name,
                              struct ini_cfgobj *rules_obj,
                              struct ini_cfgobj *config_obj,
                              struct ini_errobj *errobj,
                              void **data)
{
    char **cfg_sections = NULL;
    int num_cfg_sections;
    struct value_obj *vo = NULL;
    char dom_prefix[] = "domain/";
    int ret;

    /* Get all sections in configuration */
    cfg_sections = ini_get_section_list(config_obj, &num_cfg_sections, &ret);
    if (ret != EOK) {
        goto done;
    }

    /* Check if a normal domain section (not application domains) has option
     * inherit_from and report error if it does */
    for (int i = 0; i < num_cfg_sections; i++) {
        if (strncmp(dom_prefix, cfg_sections[i], strlen(dom_prefix)) == 0) {
            ret = ini_get_config_valueobj(cfg_sections[i],
                                          "inherit_from",
                                          config_obj,
                                          INI_GET_NEXT_VALUE,
                                          &vo);
            if (vo != NULL) {
                ret = ini_errobj_add_msg(errobj,
                                         "Attribute 'inherit_from' is not "
                                         "allowed in section '%s'. Check for "
                                         "typos.",
                                         cfg_sections[i]);
                if (ret != EOK) {
                    goto done;
                }
            }
        }
    }

    ret = EOK;
done:
    ini_free_section_list(cfg_sections);
    return EOK;
}

static int sss_ini_call_validators_errobj(struct sss_ini *data,
                                          const char *rules_path,
                                          struct ini_errobj *errobj)
{
    int ret;
    struct ini_cfgobj *rules_cfgobj = NULL;
    struct ini_validator custom_sssd = { "sssd_checks", custom_sssd_checks,
                                         NULL };
    struct ini_validator *sss_validators[] = { &custom_sssd, NULL };

    ret = ini_rules_read_from_file(rules_path, &rules_cfgobj);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to read sssd.conf schema %d [%s]\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_rules_check(rules_cfgobj, data->sssd_config, sss_validators, errobj);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "ini_rules_check failed %d [%s]\n", ret, strerror(ret));
        goto done;
    }

done:
    if (rules_cfgobj) ini_config_destroy(rules_cfgobj);

    return ret;
}
#endif /* HAVE_LIBINI_CONFIG_V1_3 */

int sss_ini_call_validators(struct sss_ini *data,
                            const char *rules_path)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    int ret;
    struct ini_errobj *errobj = NULL;

    ret = ini_errobj_create(&errobj);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to create error list\n");
        goto done;
    }

    ret = sss_ini_call_validators_errobj(data,
                                         rules_path,
                                         errobj);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get errors from validators.\n");
        goto done;
    }

    /* Do not error out when validators find some issue */
    while (!ini_errobj_no_more_msgs(errobj)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "%s\n", ini_errobj_get_msg(errobj));
        ini_errobj_next(errobj);
    }

    ret = EOK;

done:
    ini_errobj_destroy(&errobj);
    return ret;
#else
    DEBUG(SSSDBG_TRACE_FUNC,
          "libini_config does not support configuration file validataion\n");
    return EOK;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

int sss_ini_call_validators_strs(TALLOC_CTX *mem_ctx,
                                 struct sss_ini *data,
                                 const char *rules_path,
                                 char ***_errors,
                                 size_t *_num_errors)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    TALLOC_CTX *tmp_ctx = NULL;
    struct ini_errobj *errobj = NULL;
    int ret;
    size_t num_errors;
    char **errors = NULL;

    if (_num_errors == NULL || _errors == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = ini_errobj_create(&errobj);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_ini_call_validators_errobj(data,
                                         rules_path,
                                         errobj);
    if (ret != EOK) {
        goto done;
    }
    num_errors = ini_errobj_count(errobj);
    if (num_errors == 0) {
        *_num_errors = num_errors;
        goto done;
    }

    errors = talloc_array(tmp_ctx, char *, num_errors);
    if (errors == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; i < num_errors; i++) {
        errors[i] = talloc_strdup(errors, ini_errobj_get_msg(errobj));
        if (errors[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ini_errobj_next(errobj);
    }

    *_num_errors = num_errors;
    *_errors = talloc_steal(mem_ctx, errors);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    ini_errobj_destroy(&errobj);

    return ret;

#else
    DEBUG(SSSDBG_TRACE_FUNC,
          "libini_config does not support configuration file validation\n");

    if (_num_errors == NULL || _errors == NULL) {
        return EINVAL;
    }

    _num_errors = 0;
    return EOK;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

int sss_ini_open(struct sss_ini *self,
                 const char *config_file,
                 const char *fallback_cfg)
{
    int ret;

    if (self == NULL) {
        return EINVAL;
    }

    if (config_file != NULL) {
        ret = sss_ini_config_file_open(self, config_file);
    } else {
        ret = ENOENT;
    }

    switch (ret) {
    case EOK:
        break;
    case ENOENT:
        DEBUG(SSSDBG_TRACE_FUNC, "No %s.\n", config_file);
        if (fallback_cfg == NULL) {
            return ret;
        }

        ret = sss_ini_config_file_from_mem(self,
                                           discard_const(fallback_cfg),
                                           strlen(fallback_cfg));
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "sss_ini_config_file_from_mem failed. Error %d\n",
                  ret);
        }
        break;
    default:
        DEBUG(SSSDBG_CONF_SETTINGS,
              "sss_ini_config_file_open failed: Error %d\n",
              ret);
        sss_ini_config_print_errors(self->error_list);
        break;
    }
    return ret;
}

int sss_ini_read_sssd_conf(struct sss_ini *self,
                           const char *config_file,
                           const char *config_dir)
{
    errno_t ret;

    if (self == NULL) {
        return EINVAL;
    }

    ret = sss_ini_open(self, config_file, CONFDB_FALLBACK_CONFIG);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "The sss_ini_open failed %s: %d\n",
              config_file,
              ret);
        return ERR_INI_OPEN_FAILED;
    }

    if (sss_ini_exists(self)) {
        ret = sss_ini_access_check(self);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Permission check on config file failed.\n");
            return ERR_INI_INVALID_PERMISSION;
        }
    } else {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "File %1$s does not exist.\n",
              (config_file ? config_file : "NULL"));
    }

    ret = sss_ini_parse(self);
    if (ret != EOK) {
        sss_ini_config_print_errors(self->error_list);
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to parse configuration.\n");
        return ERR_INI_PARSE_FAILED;
    }

    ret = sss_ini_add_snippets(self, config_dir);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Error while reading configuration directory.\n");
        return ERR_INI_ADD_SNIPPETS_FAILED;
    }

    return ret;
}

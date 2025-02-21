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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
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
    int ret;
    const char *patterns[] = { "^[^\\.].*\\.conf$", NULL };
    const char *sections[] = { ".*", NULL };
    uint32_t i = 0;
    char *msg = NULL;
    struct ini_cfgobj *modified_sssd_config = NULL;

    if (self == NULL || self->sssd_config == NULL || config_dir == NULL) {
        return EINVAL;
    }

    sss_ini_free_ra_messages(self);

    ret = ini_config_augment(self->sssd_config,
                             config_dir,
                             patterns,
                             sections,
                             NULL,
                             INI_STOP_ON_ANY,
                             INI_MV1S_OVERWRITE,
                             INI_PARSE_NOWRAP,
                             INI_MV2S_OVERWRITE,
                             &modified_sssd_config,
                             &self->ra_error_list,
                             &self->ra_success_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to augment configuration [%d]: %s\n",
              ret, sss_strerror(ret));
    }

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
}

struct ref_array *
sss_ini_get_ra_success_list(struct sss_ini *self)
{
    return self->ra_success_list;
}

struct ref_array *
sss_ini_get_ra_error_list(struct sss_ini *self)
{
    return self->ra_error_list;
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

char *sss_ini_get_string_config_value(struct sss_ini *self,
                                      int *error)
{
    return ini_get_string_config_value(self->obj, error);
}

/* Create LDIF */

int sss_confdb_create_ldif(TALLOC_CTX *mem_ctx,
                           const struct sss_ini *self,
                           const char *only_section,
                           const char **config_ldif)
{
    int ret, i, j;
    char *ldif = NULL;
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
    size_t ldif_len = 0;
    size_t attr_len;
    struct value_obj *obj = NULL;

    tmp_ctx = talloc_new(mem_ctx);
    if (!tmp_ctx) {
        ret = ENOMEM;
        goto error;
    }

    /* Read in the collection and convert it to an LDIF */
    /* Get the list of sections */
    sections = sss_ini_get_sec_list(self->sssd_config,
                                    &section_count, &ret);
    if (ret != EOK) {
        goto error;
    }

    for (i = 0; i < section_count; i++) {
        const char *rdn = NULL;
        DEBUG(SSSDBG_TRACE_LDB,
                "Processing config section [%s]\n", sections[i]);
        ret = parse_section(tmp_ctx, sections[i], &sec_dn, &rdn);
        if (ret != EOK) {
            goto error;
        }

        if (only_section != NULL) {
            if (strcasecmp(only_section, sections[i])) {
                DEBUG(SSSDBG_TRACE_LDB, "Skipping section %s\n", sections[i]);
                continue;
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
            DEBUG(SSSDBG_TRACE_LDB,
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
            DEBUG(SSSDBG_TRACE_LDB, "%s\n", ldif_attr);

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

        DEBUG(SSSDBG_TRACE_LDB, "Section dn\n%s\n", dn);

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

    if (ldif == NULL) {
        ret = ERR_INI_EMPTY_CONFIG;
        goto error;
    }
    ldif[ldif_len] = '\0';

    free_section_list(sections);

    *config_ldif = (const char *)ldif;
    talloc_free(tmp_ctx);
    return EOK;

error:
    talloc_free(ldif);
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t check_domain_inherit_from(char *cfg_section,
                                         struct ini_cfgobj *config_obj,
                                         struct ini_errobj *errobj)
{
    struct value_obj *vo = NULL;
    int ret;

    ret = ini_get_config_valueobj(cfg_section,
                                  "inherit_from",
                                  config_obj,
                                  INI_GET_NEXT_VALUE,
                                  &vo);
    if (ret != EOK) {
        goto done;
    }

    if (vo != NULL) {
        ret = ini_errobj_add_msg(errobj,
                                 "Attribute 'inherit_from' is not "
                                 "allowed in section '%s'.",
                                 cfg_section);
        if (ret != EOK) {
            goto done;
        }
    }

    ret = EOK;

done:
    return ret;
}

static errno_t check_domain_id_provider(char *cfg_section,
                                        struct ini_cfgobj *config_obj,
                                        struct ini_errobj *errobj)
{
    struct value_obj *vo = NULL;
    const char *valid_values[] = { "ad", "ipa", "ldap", "proxy", NULL };
    const char **valid_value;
    const char *value;
    int ret;

    ret = ini_get_config_valueobj(cfg_section,
                                  "id_provider",
                                  config_obj,
                                  INI_GET_NEXT_VALUE,
                                  &vo);
    if (ret != EOK) {
        goto done;
    }

    if (vo == NULL) {
        ret = ini_errobj_add_msg(errobj,
                                 "Attribute 'id_provider' is "
                                 "missing in section '%s'.",
                                 cfg_section);
    } else {
        value = sss_ini_get_const_string_config_value(vo, &ret);
        if (ret != EOK) {
            goto done;
        }

        valid_value = valid_values;
        while (*valid_value != NULL) {
            if (strcmp(value, *valid_value) == 0) {
                break;
            }
            valid_value++;
        }
        if (*valid_value == NULL) {
            ret = ini_errobj_add_msg(errobj,
                                     "Attribute 'id_provider' in section '%s' "
                                     "has an invalid value: %s",
                                     cfg_section, value);
            if (ret != EOK) {
                goto done;
            }
        }
    }

    ret = EOK;

done:
    return ret;
}

#define SECTION_IS_DOMAIN(s) \
             (strncmp("domain/", s, strlen("domain/")) == 0)
#define SECTION_DOMAIN_IS_SUBDOMAIN(s) \
             (strchr(s + strlen("domain/"), '/') != NULL)

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
    int ret;

    /* Get all sections in configuration */
    cfg_sections = ini_get_section_list(config_obj, &num_cfg_sections, &ret);
    if (ret != EOK) {
        goto done;
    }

    /* Check a normal domain section (not application domains) */
    for (int i = 0; i < num_cfg_sections; i++) {
        if (SECTION_IS_DOMAIN(cfg_sections[i])) {
            ret = check_domain_inherit_from(cfg_sections[i], config_obj, errobj);
            if (ret != EOK) {
                goto done;
            }

            if (!SECTION_DOMAIN_IS_SUBDOMAIN(cfg_sections[i])) {
                ret = check_domain_id_provider(cfg_sections[i], config_obj, errobj);
                if (ret != EOK) {
                    goto done;
                }
            }
        }
    }

    ret = EOK;
done:
    ini_free_section_list(cfg_sections);
    return ret;
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
              "Failed to read sssd.conf schema [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_rules_check(rules_cfgobj, data->sssd_config, sss_validators, errobj);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "ini_rules_check failed [%d]: %s\n", ret, strerror(ret));
        goto done;
    }

done:
    if (rules_cfgobj) ini_config_destroy(rules_cfgobj);

    return ret;
}

int sss_ini_call_validators(struct sss_ini *data,
                            const char *rules_path)
{
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
}

int sss_ini_call_validators_strs(TALLOC_CTX *mem_ctx,
                                 struct sss_ini *data,
                                 const char *rules_path,
                                 char ***_errors,
                                 size_t *_num_errors)
{
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
                  "sss_ini_config_file_from_mem() failed [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
        break;
    default:
        DEBUG(SSSDBG_CONF_SETTINGS,
              "sss_ini_config_file_open() failed [%d]: %s\n",
              ret, sss_strerror(ret));
        sss_ini_config_print_errors(self->error_list);
        break;
    }
    return ret;
}

static int access_check_file(const char *filename)
{
    int ret;
    struct stat st;
    uid_t uid;
    gid_t gid;

    sss_sssd_user_uid_and_gid(&uid, &gid);

    ret = stat(filename, &st);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "stat(%s) failed: %s\n",
              filename, strerror(ret));
        return EINVAL;
    }

    if ((st.st_uid != 0) && (st.st_uid != uid)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected user owner of '%s': %"SPRIuid"\n",
              filename, st.st_uid);
        return ERR_INI_INVALID_PERMISSION;
    }

    if ((st.st_gid != 0) && (st.st_gid != gid)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected group owner of '%s': %"SPRIgid"\n",
              filename, st.st_gid);
        return ERR_INI_INVALID_PERMISSION;
    }

    if ((st.st_mode & (S_IROTH|S_IWOTH|S_IXOTH)) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected access to '%s' by other users\n",
              filename);
        return ERR_INI_INVALID_PERMISSION;
    }

    return EOK;
}

static int access_check_ini(struct sss_ini *self)
{
    int ret;
    const char *path;
    uint32_t i;
    const char **snippet;
    struct ref_array *used_snippets;

    if (self->main_config_exists) {
        path = ini_config_get_filename(self->file);
        ret = access_check_file(path);
        if (ret != EOK) {
            return ret;
        }
    }

    used_snippets = sss_ini_get_ra_success_list(self);
    for (i = 0; (snippet = ref_array_get(used_snippets, i, NULL)) != NULL; ++i) {
        ret = access_check_file(*snippet);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

int sss_ini_read_sssd_conf(struct sss_ini *self,
                           const char *config_file,
                           const char *config_dir)
{
    errno_t ret;

    if (self == NULL) {
        return EINVAL;
    }

    /* "[sssd]\n" is supplied to `sss_ini_open()` to create empty context
     * in case main config file ('sssd.conf') is missing. This is done in
     * order to be able to add config snippets later - sss_ini_add_snippets()
     * Take a note if both 'sssd.conf' and snippets are missing, then
     * sss_ini_read_sssd_conf() returns ERR_INI_EMPTY_CONFIG, so there is no
     * "fallback config" per se.
     */
    ret = sss_ini_open(self, config_file, "[sssd]\n");
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_ini_open() on '%s' failed [%d]: %s\n",
              config_file, ret, sss_strerror(ret));
        return ERR_INI_OPEN_FAILED;
    }

    if (!self->main_config_exists) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "File %s does not exist.\n", config_file);
    }

    ret = sss_ini_parse(self);
    if (ret != EOK) {
        sss_ini_config_print_errors(self->error_list);
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to parse configuration file %s: %d\n",
              config_file, ret);
        return ERR_INI_PARSE_FAILED;
    }

    ret = sss_ini_add_snippets(self, config_dir);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Error while reading configuration directory '%s' [%d]: %s\n",
              config_dir, ret, sss_strerror(ret));
        return ERR_INI_ADD_SNIPPETS_FAILED;
    }

    if ((!self->main_config_exists) &&
        (ref_array_len(sss_ini_get_ra_success_list(self)) == 0)) {
        return ERR_INI_EMPTY_CONFIG;
    }

    ret = access_check_ini(self);

    return ret;
}

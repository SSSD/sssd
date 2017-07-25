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

#ifdef HAVE_LIBINI_CONFIG_V1
#include "ini_configobj.h"
#else
#include "collection.h"
#include "collection_tools.h"
#endif

#include "ini_config.h"


#ifdef HAVE_LIBINI_CONFIG_V1

struct sss_ini_initdata {
    char **error_list;
    struct ref_array *ra_success_list;
    struct ref_array *ra_error_list;
    struct ini_cfgobj *sssd_config;
    struct value_obj *obj;
    const struct stat *cstat;
    struct ini_cfgfile *file;
};

#define sss_ini_get_sec_list                   ini_get_section_list
#define sss_ini_get_attr_list                  ini_get_attribute_list
#define sss_ini_get_const_string_config_value  ini_get_const_string_config_value
#define sss_ini_get_config_obj                 ini_get_config_valueobj

#else

struct sss_ini_initdata {
    struct collection_item *error_list;
    struct collection_item *sssd_config;
    struct collection_item *obj;
    struct stat cstat;
    int file;
};

#define sss_ini_get_sec_list                   get_section_list
#define sss_ini_get_attr_list                  get_attribute_list
#define sss_ini_get_const_string_config_value  get_const_string_config_value
#define sss_ini_get_config_obj(secs,attrs,cfg,flag,attr) \
    get_config_item(secs,attrs,cfg,attr)

#endif


/* Initialize data structure */

struct sss_ini_initdata* sss_ini_initdata_init(TALLOC_CTX *mem_ctx)
{
    return talloc_zero(mem_ctx, struct sss_ini_initdata);
}



/* Close file descriptor */

void sss_ini_close_file(struct sss_ini_initdata *init_data)
{
    if (init_data == NULL) return;
#ifdef HAVE_LIBINI_CONFIG_V1
    if (init_data->file != NULL) {
        ini_config_file_destroy(init_data->file);
        init_data->file = NULL;
    }
#else
    if (init_data->file != -1) {
        close(init_data->file);
        init_data->file = -1;
    }
#endif
}



/* Open configuration file */

int sss_ini_config_file_open(struct sss_ini_initdata *init_data,
                             const char *config_file)
{
#ifdef HAVE_LIBINI_CONFIG_V1
    return ini_config_file_open(config_file,
                                INI_META_STATS,
                                &init_data->file);
#else
    return check_and_open_readonly(config_file, &init_data->file, 0, 0,
                                   S_IFREG|S_IRUSR, /* f r**------ */
                                   S_IFMT|(ALLPERMS & ~(S_IWUSR|S_IXUSR)));
#endif
}



/* Check configuration file permissions */

int sss_ini_config_access_check(struct sss_ini_initdata *init_data)
{
#ifdef HAVE_LIBINI_CONFIG_V1
    return ini_config_access_check(init_data->file,
                                   INI_ACCESS_CHECK_MODE |
                                   INI_ACCESS_CHECK_UID |
                                   INI_ACCESS_CHECK_GID,
                                   0, /* owned by root */
                                   0, /* owned by root */
                                   S_IRUSR, /* r**------ */
                                   ALLPERMS & ~(S_IWUSR|S_IXUSR));
#else
    return EOK;
#endif
}



/* Get cstat */

int sss_ini_get_stat(struct sss_ini_initdata *init_data)
{
#ifdef HAVE_LIBINI_CONFIG_V1
    init_data->cstat = ini_config_get_stat(init_data->file);

    if (!init_data->cstat) return EIO;

    return EOK;
#else

    return fstat(init_data->file, &init_data->cstat);
#endif
}



/* Get mtime */

int sss_ini_get_mtime(struct sss_ini_initdata *init_data,
                      size_t timestr_len,
                      char *timestr)
{
#ifdef HAVE_LIBINI_CONFIG_V1
    return snprintf(timestr, timestr_len, "%llu",
                    (long long unsigned)init_data->cstat->st_mtime);
#else
    return snprintf(timestr, timestr_len, "%llu",
                    (long long unsigned)init_data->cstat.st_mtime);
#endif
}



/* Print ini_config errors */

static void sss_ini_config_print_errors(char **error_list)
{
#ifdef HAVE_LIBINI_CONFIG_V1
    unsigned count = 0;

    if (!error_list) {
        return;
    }

    while (error_list[count]) {
        DEBUG(SSSDBG_FATAL_FAILURE, "%s\n", error_list[count]);
        count++;
    }
#endif

    return;
}



/* Load configuration */

int sss_ini_get_config(struct sss_ini_initdata *init_data,
                       const char *config_file,
                       const char *config_dir)
{
    int ret;
#ifdef HAVE_LIBINI_CONFIG_V1
#ifdef HAVE_LIBINI_CONFIG_V1_3
    const char *patterns[] = { "^[^\\.].*\\.conf$", NULL };
    const char *sections[] = { ".*", NULL };
    uint32_t i = 0;
    char *msg = NULL;
    struct access_check snip_check;
    struct ini_cfgobj *modified_sssd_config = NULL;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */

    /* Create config object */
    ret = ini_config_create(&(init_data->sssd_config));
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to create config object. Error %d.\n", ret);
        return ret;
    }

    /* Parse file */
    ret = ini_config_parse(init_data->file,
                           INI_STOP_ON_ANY,
                           INI_MV1S_OVERWRITE,
                           INI_PARSE_NOWRAP,
                           init_data->sssd_config);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Failed to parse configuration. Error %d.\n", ret);

        if (ini_config_error_count(init_data->sssd_config)) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                    "Errors detected while parsing: %s\n",
                     ini_config_get_filename(init_data->file));

            ini_config_get_errors(init_data->sssd_config,
                                  &init_data->error_list);
            sss_ini_config_print_errors(init_data->error_list);
            ini_config_free_errors(init_data->error_list);
        }
        ini_config_destroy(init_data->sssd_config);
        init_data->sssd_config = NULL;
        return ret;
    }

#ifdef HAVE_LIBINI_CONFIG_V1_3
    snip_check.flags = INI_ACCESS_CHECK_MODE | INI_ACCESS_CHECK_UID
                       | INI_ACCESS_CHECK_GID;
    snip_check.uid = 0; /* owned by root */
    snip_check.gid = 0; /* owned by root */
    snip_check.mode = S_IRUSR; /* r**------ */
    snip_check.mask = ALLPERMS & ~(S_IWUSR | S_IXUSR);

    ret = ini_config_augment(init_data->sssd_config,
                             config_dir,
                             patterns,
                             sections,
                             &snip_check,
                             INI_STOP_ON_ANY,
                             INI_MV1S_OVERWRITE,
                             INI_PARSE_NOWRAP,
                             INI_MV2S_OVERWRITE,
                             &modified_sssd_config,
                             &init_data->ra_error_list,
                             &init_data->ra_success_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to augment configuration [%d]: %s",
              ret, sss_strerror(ret));
    }

    while (ref_array_get(init_data->ra_success_list, i, &msg) != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Config merge success: %s\n", msg);
        i++;
    }

    i = 0;
    while (ref_array_get(init_data->ra_error_list, i, &msg) != NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Config merge error: %s\n", msg);
        i++;
    }

    /* switch config objects if there are no errors */
    if (modified_sssd_config != NULL) {
        ini_config_destroy(init_data->sssd_config);
        init_data->sssd_config = modified_sssd_config;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Using only main configuration file due to errors in merging\n");
    }
#endif

    return ret;

#else

    /* Read the configuration into a collection */
    ret = config_from_fd("sssd",
                         init_data->file,
                         config_file,
                         &init_data->sssd_config,
                         INI_STOP_ON_ANY,
                         &init_data->error_list);

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
                "Parse error reading configuration file [%s]\n",
                 config_file);

        print_file_parsing_errors(stderr, init_data->error_list);

        free_ini_config_errors(init_data->error_list);
        free_ini_config(init_data->sssd_config);

        return ret;
    }

    return EOK;

#endif
}

struct ref_array *
sss_ini_get_ra_success_list(struct sss_ini_initdata *init_data)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    return init_data->ra_success_list;
#else
    return NULL;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

struct ref_array *
sss_ini_get_ra_error_list(struct sss_ini_initdata *init_data)
{
#ifdef HAVE_LIBINI_CONFIG_V1_3
    return init_data->ra_error_list;
#else
    return NULL;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

/* Get configuration object */

int sss_ini_get_cfgobj(struct sss_ini_initdata *init_data,
                       const char *section, const char *name)
{
    return sss_ini_get_config_obj(section,name, init_data->sssd_config,
                                  INI_GET_FIRST_VALUE, &init_data->obj);
}

/* Check configuration object */

int sss_ini_check_config_obj(struct sss_ini_initdata *init_data)
{
    if (init_data->obj == NULL) {
        return ENOENT;
    }

    return EOK;
}



/* Get integer value */

int sss_ini_get_int_config_value(struct sss_ini_initdata *init_data,
                                 int strict, int def, int *error)
{
#ifdef HAVE_LIBINI_CONFIG_V1
    return ini_get_int_config_value(init_data->obj, strict, def, error);
#else
    return get_int_config_value(init_data->obj, strict, def, error);
#endif
}



/* Destroy ini config (v1) */

void sss_ini_config_destroy(struct sss_ini_initdata *init_data)
{
    if (init_data == NULL) return;
#ifdef HAVE_LIBINI_CONFIG_V1
    if (init_data->sssd_config != NULL) {
        ini_config_destroy(init_data->sssd_config);
        init_data->sssd_config = NULL;
    }
#else
    free_ini_config(init_data->sssd_config);
#endif
}



/* Create LDIF */

int sss_confdb_create_ldif(TALLOC_CTX *mem_ctx,
                           struct sss_ini_initdata *init_data,
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
#ifdef HAVE_LIBINI_CONFIG_V1
    struct value_obj *obj = NULL;
#else
    struct collection_item *obj = NULL;
#endif

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
    sections = sss_ini_get_sec_list(init_data->sssd_config,
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
        attrs = sss_ini_get_attr_list(init_data->sssd_config, sections[i],
                                   &attr_count, &ret);
        if (ret != EOK) {
            free_section_list(sections);
            goto error;
        }

        for (j = 0; j < attr_count; j++) {
            DEBUG(SSSDBG_TRACE_FUNC,
                    "Processing attribute [%s]\n", attrs[j]);
            ret = sss_ini_get_config_obj(sections[i], attrs[j],
                                         init_data->sssd_config,
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

static int sss_ini_call_validators_errobj(struct sss_ini_initdata *data,
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

int sss_ini_call_validators(struct sss_ini_initdata *data,
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
                                 struct sss_ini_initdata *data,
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
          "libini_config does not support configuration file validataion\n");

    if (_num_errors == NULL || _errors == NULL) {
        return EINVAL;
    }

    _num_errors = 0;
    return EOK;
#endif /* HAVE_LIBINI_CONFIG_V1_3 */
}

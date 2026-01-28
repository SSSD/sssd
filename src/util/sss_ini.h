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


#ifndef __SSS_INI_H__
#define __SSS_INI_H__

#include <stdbool.h>
#include <ref_array.h>

/**
 * @brief INI data structure
 */
struct sss_ini;

/**
 * @brief create new ini data object
 *
 * @param[in] tmp_ctx  talloc context
 *
 * @return
 *  - pointer to newly allocated and initialized structure
 *  - NULL in case of error
 */
struct sss_ini* sss_ini_new(TALLOC_CTX *tmp_ctx);


/**
 * @brief Open ini file or use fallback_cfg if file is not present. Include
 *        configuration snippets and perform access check.
 *
 * @param[in] self          pointer to sss_ini structure
 * @param[in] config_file   ini file
 * @param[in] config_dir    directory containing ini files to be included
 *
 * @return
 *  - EOK - success
 *  - ERR_INI_OPEN_FAILED - sss_ini_open failed
 *  - ERR_INI_INVALID_PERMISSION - access check failed
 *  - ERR_INI_PARSE_FAILED - failed to parse configuration file
 *  - ERR_INI_ADD_SNIPPETS_FAILED - failed to add configuration snippets
 *  - ERR_INI_EMPTY_CONFIG - neither main config nor config snippets exist
 */
int sss_ini_read_sssd_conf(struct sss_ini *self,
                           const char *config_file,
                           const char *config_dir);

/**
 * @brief Open ini file or use fallback_cfg if file is not present
 *
 * @param[in] self          pointer to sss_ini structure
 * @param[in] config_file   ini file
 * @param[in] fallback_cfg  string with ini content. This parameter is used
 *                          when config_file doesn't exist or it is set to NULL
 *
 * @return error code
 */
int sss_ini_open(struct sss_ini *self,
                 const char *config_file,
                 const char *fallback_cfg);

/**
 * @brief Get pointer to list of snippet parsing errors
 */
struct ref_array *
sss_ini_get_ra_error_list(struct sss_ini *self);

/**
 * @brief Get pointer to list of successfully merged snippet files
 */
struct ref_array *
sss_ini_get_ra_success_list(struct sss_ini *self);

/**
 * @brief Get configuration object
 */
int sss_ini_get_cfgobj(struct sss_ini *self,
                       const char *section, const char *name);

/**
 * @brief Check configuration object
 */
int sss_ini_check_config_obj(struct sss_ini *self);

/**
 * @brief Get int value
 */
int sss_ini_get_int_config_value(struct sss_ini *self,
                                 int strict, int def, int *error);

/**
 * @brief Get string value
 */
char *sss_ini_get_string_config_value(struct sss_ini *self,
                                      int *error);

/**
 * @brief Create LDIF
 */
int sss_confdb_create_ldif(TALLOC_CTX *mem_ctx,
                           const struct sss_ini *self,
                           const char *only_section,
                           const char **config_ldif);

/**
 * @brief Validate sssd.conf if libini_config support it
 */
int sss_ini_call_validators(struct sss_ini *data,
                            const char *rules_path);

/**
 * @brief Get errors from validators in array of strings
 */
int sss_ini_call_validators_strs(TALLOC_CTX *mem_ctx,
                                 struct sss_ini *data,
                                 const char *rules_path,
                                 char ***_strs,
                                 size_t *_num_errors);

#endif /* __SSS_INI_H__ */

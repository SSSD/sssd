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

/* Structure declarations */

/* INI data structure */
struct sss_ini_initdata;


/* Function declarations */

/* Initialize data structure */
struct sss_ini_initdata* sss_ini_initdata_init(TALLOC_CTX *tmp_ctx);

/* Close file descriptor */
void sss_ini_close_file(struct sss_ini_initdata *init_data);

/* Open config file */
int sss_ini_config_file_open(struct sss_ini_initdata *init_data,
                             const char *config_file);

/* Check file permissions */
int sss_ini_config_access_check(struct sss_ini_initdata *init_data);

/* Cstat */
int sss_ini_get_stat(struct sss_ini_initdata *init_data);

/* Get mtime */
int sss_ini_get_mtime(struct sss_ini_initdata *init_data,
                      size_t timestr_len,
                      char *timestr);

/* Load configuration */
int sss_ini_get_config(struct sss_ini_initdata *init_data,
                       const char *config_file);
/* Get configuration object */
int sss_ini_get_cfgobj(struct sss_ini_initdata *init_data,
                       const char *section, const char *name);

/* Check configuration object */
int sss_ini_check_config_obj(struct sss_ini_initdata *init_data);

/* Get int value */
int sss_ini_get_int_config_value(struct sss_ini_initdata *init_data,
                                 int strict, int def, int *error);

/* Destroy ini config */
void sss_ini_config_destroy(struct sss_ini_initdata *init_data);

/* Create LDIF */
int sss_confdb_create_ldif(TALLOC_CTX *mem_ctx,
                           struct sss_ini_initdata *init_data,
                           const char **config_ldif);

#endif /* __SSS_INI_H__ */

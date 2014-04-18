/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <augeas.h>
#include <talloc.h>
#include <string.h>
#include "util/sss_config.h"

#define PATH_SECTION "/files/%s/target[. = \"%s\"]"
#define PATH_OPTION PATH_SECTION "/%s"

#define build_section_path(mem_ctx, config_ctx, section) \
    talloc_asprintf(mem_ctx, PATH_SECTION, config_ctx->file, section)

#define build_option_path(mem_ctx, config_ctx, section, option) \
    talloc_asprintf(mem_ctx, PATH_OPTION, config_ctx->file, section, option)

struct sss_config_ctx
{
    augeas *auges_ctx;
    const char *file;
};

static errno_t
sss_config_set_option(struct sss_config_ctx *ctx,
                      const char *section,
                      const char *option,
                      const char *value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *target_path = NULL;
    char *option_path = NULL;
    errno_t ret;
    int aug_ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    target_path = build_section_path(tmp_ctx, ctx, section);
    if (target_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    option_path = build_option_path(tmp_ctx, ctx, section, option);
    if (option_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Set configuration option:
     *
     * # make sure the section exists
     * set /files/$file/target[. = "$section"] $section
     *
     * # set value
     * set /files/$file/target[. = "$section"]/$option $value
     */

    aug_ret = aug_set(ctx->auges_ctx, target_path, section);
    if (aug_ret != 0) {
        ret = EIO;
        goto done;
    }

    aug_ret = aug_set(ctx->auges_ctx, option_path, value);
    if (aug_ret != 0) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_config_rm_option(struct sss_config_ctx *ctx,
                      const char *section,
                      const char *option)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *option_path = NULL;
    errno_t ret;
    int aug_ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    option_path = build_option_path(tmp_ctx, ctx, section, option);
    if (option_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Remove configuration option:
     *
     * rm /files/$file/target[. = "$section"]/$option
     */

    aug_ret = aug_rm(ctx->auges_ctx, option_path);
    if (aug_ret != 1) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_config_set_list(struct sss_config_ctx *ctx,
                    const char *section,
                    const char *option,
                    char **list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *value = NULL;
    errno_t ret;
    int i;

    if (list == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    if (list[0] == NULL) {
        ret = sss_config_rm_option(ctx, section, option);
        goto done;
    }

    value = talloc_strdup(tmp_ctx, list[0]);
    if (value == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 1; list[i] != NULL; i++) {
        value = talloc_asprintf_append(value, ", %s", list[i]);
        if (value == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = sss_config_set_option(ctx, section, option, value);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_config_get_list(TALLOC_CTX *mem_ctx,
                    struct sss_config_ctx *ctx,
                    const char *section,
                    const char *option,
                    char ***_list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *option_path = NULL;
    const char *value = NULL;
    char **list = NULL;
    errno_t ret;
    int aug_ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    option_path = build_option_path(tmp_ctx, ctx, section, option);
    if (option_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    aug_ret = aug_get(ctx->auges_ctx, option_path, &value);
    if (aug_ret == 0 || (aug_ret == 1 && (value == NULL || *value == '\0'))) {
        /* option is not present, return empty list */
        list = talloc_zero_array(tmp_ctx, char*, 1);
        if (list == NULL) {
            ret = ENOMEM;
            goto done;
        }

        ret = EOK;
        goto done;
    } else if (aug_ret != 1) {
        /* error: more than one value found */
        ret = EINVAL;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, value, ',', true, true, &list, NULL);
    if (ret != EOK) {
        goto done;
    }

    *_list = talloc_steal(mem_ctx, list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_config_is_in_list(struct sss_config_ctx *ctx,
                      const char *section,
                      const char *option,
                      const char *value,
                      bool *_result)
{
    char **list = NULL;
    errno_t ret;

    ret = sss_config_get_list(ctx, ctx, section, option, &list);
    if (ret != EOK) {
        goto done;
    }

    *_result = string_in_list(value, list, true);

done:
    talloc_free(list);
    return ret;
}

static errno_t
sss_config_add_to_list(struct sss_config_ctx *ctx,
                       const char *section,
                       const char *option,
                       const char *value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **list = NULL;
    errno_t ret;
    bool result = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_config_get_list(tmp_ctx, ctx, section, option, &list);
    if (ret != EOK) {
        goto done;
    }

    result = string_in_list(value, list, true);
    if (result == true) {
        ret = EOK;
        goto done;
    }

    ret = add_string_to_list(tmp_ctx, value, &list);
    if (ret != EOK) {
        goto done;
    }

    ret = sss_config_set_list(ctx, section, option, list);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
sss_config_del_from_list(struct sss_config_ctx *ctx,
                         const char *section,
                         const char *option,
                         const char *value)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **list = NULL;
    errno_t ret;
    bool found;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sss_config_get_list(tmp_ctx, ctx, section, option, &list);
    if (ret != EOK) {
        goto done;
    }

    if (list == NULL) {
        goto done;
    }

    found = false;
    for (i = 0; list[i] != NULL; i++) {
        if (strcmp(list[i], value) == 0) {
            found = true;
        }

        if (found) {
            list[i] = list[i + 1];
        }
    }

    ret = sss_config_set_list(ctx, section, option, list);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int sss_config_ctx_destructor(struct sss_config_ctx *ctx)
{
    if (ctx->auges_ctx != NULL) {
        aug_close(ctx->auges_ctx);
        ctx->auges_ctx = NULL;
    }

    return 0;
}

struct sss_config_ctx *
sss_config_open(TALLOC_CTX *mem_ctx,
                const char *root,
                const char *file)
{
    struct sss_config_ctx *ctx = NULL;
    errno_t ret;
    int aug_ret;

    ctx = talloc_zero(mem_ctx, struct sss_config_ctx);
    if (ctx == NULL) {
        return NULL;
    }

    talloc_set_destructor(ctx, sss_config_ctx_destructor);

    ctx->auges_ctx = aug_init(root, NULL, AUG_NO_LOAD | AUG_NO_MODL_AUTOLOAD
                              | AUG_SAVE_BACKUP);
    if (ctx->auges_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ctx->file = talloc_strdup(ctx, file);
    if (ctx->file == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Load configuration file
     *
     * set /augeas/load/sssd/lens sssd.lns
     * set /augeas/load/sssd/incl $file
     * load
     */

    aug_ret = aug_set(ctx->auges_ctx, "/augeas/load/sssd/lens", "sssd.lns");
    if (aug_ret != 0) {
        ret = EIO;
        goto done;
    }

    aug_ret = aug_set(ctx->auges_ctx, "/augeas/load/sssd/incl", ctx->file);
    if (aug_ret != 0) {
        ret = EIO;
        goto done;
    }

    aug_ret = aug_load(ctx->auges_ctx);
    if (aug_ret != 0) {
        ret = EIO;
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }

    return ctx;
}

errno_t
sss_config_save(struct sss_config_ctx *ctx)
{
    int aug_ret;

    aug_ret = aug_save(ctx->auges_ctx);
    if (aug_ret != 0) {
        return EIO;
    }

    return EOK;
}

void
sss_config_close(struct sss_config_ctx **_ctx)
{
    if (_ctx == NULL || *_ctx == NULL) {
        return;
    }

    talloc_free(*_ctx);
    *_ctx = NULL;
}

errno_t
sss_config_set_debug_level(struct sss_config_ctx *ctx,
                           const char *section,
                           uint32_t level)
{
    char *level_str = NULL;
    errno_t ret;

    level_str = talloc_asprintf(ctx, "%#.4x", level);
    if (level_str == NULL) {
        return ENOMEM;
    }

    ret = sss_config_set_option(ctx, section, CONFDB_SERVICE_DEBUG_LEVEL,
                                level_str);

    talloc_free(level_str);
    return ret;
}

errno_t
sss_config_service_is_enabled(struct sss_config_ctx *ctx,
                              const char *service,
                              bool *_result)
{
    return sss_config_is_in_list(ctx, "sssd", CONFDB_MONITOR_ACTIVE_SERVICES,
                                 service, _result);
}

errno_t
sss_config_service_enable(struct sss_config_ctx *ctx,
                          const char *service)
{
    return sss_config_add_to_list(ctx, "sssd", CONFDB_MONITOR_ACTIVE_SERVICES,
                                  service);
}

errno_t
sss_config_service_disable(struct sss_config_ctx *ctx,
                           const char *service)
{
    return sss_config_del_from_list(ctx, "sssd", CONFDB_MONITOR_ACTIVE_SERVICES,
                                    service);
}

errno_t
sss_config_domain_is_enabled(struct sss_config_ctx *ctx,
                             const char *domain,
                             bool *_result)
{
    return sss_config_is_in_list(ctx, "sssd", CONFDB_MONITOR_ACTIVE_DOMAINS,
                                 domain, _result);
}

errno_t
sss_config_domain_enable(struct sss_config_ctx *ctx,
                         const char *domain)
{
    return sss_config_add_to_list(ctx, "sssd", CONFDB_MONITOR_ACTIVE_DOMAINS,
                                  domain);
}

errno_t
sss_config_domain_disable(struct sss_config_ctx *ctx,
                          const char *domain)
{
    return sss_config_del_from_list(ctx, "sssd", CONFDB_MONITOR_ACTIVE_DOMAINS,
                                    domain);
}

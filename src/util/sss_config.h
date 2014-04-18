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

#ifndef SSS_CONFIG_H_
#define SSS_CONFIG_H_

#include <talloc.h>
#include "util/util.h"

struct sss_config_ctx;

struct sss_config_ctx *
sss_config_open(TALLOC_CTX *mem_ctx,
                const char *root,
                const char *file);

errno_t
sss_config_save(struct sss_config_ctx *ctx);

void
sss_config_close(struct sss_config_ctx **_ctx);

errno_t
sss_config_set_debug_level(struct sss_config_ctx *ctx,
                           const char *section,
                           uint32_t level);

errno_t
sss_config_service_is_enabled(struct sss_config_ctx *ctx,
                              const char *service,
                              bool *_result);

errno_t
sss_config_service_enable(struct sss_config_ctx *ctx,
                          const char *service);

errno_t
sss_config_service_disable(struct sss_config_ctx *ctx,
                           const char *service);

errno_t
sss_config_domain_is_enabled(struct sss_config_ctx *ctx,
                             const char *domain,
                             bool *_result);

errno_t
sss_config_domain_enable(struct sss_config_ctx *ctx,
                         const char *domain);

errno_t
sss_config_domain_disable(struct sss_config_ctx *ctx,
                          const char *domain);

#endif /* SSS_CONFIG_H_ */

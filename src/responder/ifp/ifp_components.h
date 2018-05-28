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

#ifndef _IFP_COMPONENTS_H_
#define _IFP_COMPONENTS_H_

#include "responder/ifp/ifp_iface/ifp_iface_async.h"
#include "responder/ifp/ifp_private.h"

/* org.freedesktop.sssd.infopipe */

errno_t
ifp_list_components(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct ifp_ctx *ctx,
                    const char ***_paths);

errno_t
ifp_list_responders(TALLOC_CTX *mem_ctx,
                    struct sbus_request *sbus_req,
                    struct ifp_ctx *ctx,
                    const char ***_paths);
errno_t
ifp_list_backends(TALLOC_CTX *mem_ctx,
                  struct sbus_request *sbus_req,
                  struct ifp_ctx *ctx,
                  const char ***_paths);

errno_t
ifp_find_monitor(TALLOC_CTX *mem_ctx,
                 struct sbus_request *sbus_req,
                 struct ifp_ctx *ctx,
                 const char **_path);

errno_t
ifp_find_responder_by_name(TALLOC_CTX *mem_ctx,
                           struct sbus_request *sbus_req,
                           struct ifp_ctx *ctx,
                           const char *name,
                           const char **_path);

errno_t
ifp_find_backend_by_name(TALLOC_CTX *mem_ctx,
                         struct sbus_request *sbus_req,
                         struct ifp_ctx *ctx,
                         const char *name,
                         const char **_path);

/* org.freedesktop.sssd.infopipe.Components */

errno_t
ifp_component_get_name(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       const char **_out);

errno_t
ifp_component_get_debug_level(TALLOC_CTX *mem_ctx,
                              struct sbus_request *sbus_req,
                              struct ifp_ctx *ctx,
                              uint32_t *_out);

errno_t
ifp_component_get_enabled(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          bool *_out);

errno_t
ifp_component_get_type(TALLOC_CTX *mem_ctx,
                       struct sbus_request *sbus_req,
                       struct ifp_ctx *ctx,
                       const char **_out);

/* org.freedesktop.sssd.infopipe.Components.Backends */

errno_t
ifp_backend_get_providers(TALLOC_CTX *mem_ctx,
                          struct sbus_request *sbus_req,
                          struct ifp_ctx *ctx,
                          const char ***_out);

#endif /* _IFP_COMPONENTS_H_ */

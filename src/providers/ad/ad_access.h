/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef AD_ACCESS_H_
#define AD_ACCESS_H_

#include "providers/data_provider.h"

struct ad_access_ctx {
    struct dp_option *ad_options;
    struct sdap_access_ctx *sdap_access_ctx;
    struct ad_id_ctx *ad_id_ctx;
    /* supported GPO access control modes */
    enum gpo_access_control_mode {
        GPO_ACCESS_CONTROL_DISABLED,
        GPO_ACCESS_CONTROL_PERMISSIVE,
        GPO_ACCESS_CONTROL_ENFORCING
    } gpo_access_control_mode;
    int gpo_cache_timeout;
    /* supported GPO map options */
    enum gpo_map_type {
        GPO_MAP_INTERACTIVE = 0,
        GPO_MAP_REMOTE_INTERACTIVE,
        GPO_MAP_NETWORK,
        GPO_MAP_BATCH,
        GPO_MAP_SERVICE,
        GPO_MAP_PERMIT,
        GPO_MAP_DENY,
        GPO_MAP_NUM_OPTS
    } gpo_map_type;
    hash_table_t *gpo_map_options_table;
    enum gpo_map_type gpo_default_right;
};

struct tevent_req *
ad_pam_access_handler_send(TALLOC_CTX *mem_ctx,
                           struct ad_access_ctx *access_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params);

errno_t
ad_pam_access_handler_recv(TALLOC_CTX *mem_ctx,
                             struct tevent_req *req,
                             struct pam_data **_data);

#endif /* AD_ACCESS_H_ */

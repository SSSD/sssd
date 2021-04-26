/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef _IPA_SUDO_H_
#define _IPA_SUDO_H_

#include "providers/ipa/ipa_common.h"

struct ipa_sudo_ctx {
    struct sdap_id_ctx *id_ctx;
    struct ipa_options *ipa_opts;
    struct sdap_options *sdap_opts;
    struct be_ptask *full_refresh;
    struct be_ptask *smart_refresh;

    /* sudo */
    struct sdap_attr_map *sudocmdgroup_map;
    struct sdap_attr_map *sudorule_map;
    struct sdap_attr_map *sudocmd_map;
    struct sdap_search_base **sudo_sb;
    int sudocmd_threshold;
};

errno_t
ipa_sudo_ptask_setup(struct be_ctx *be_ctx, struct ipa_sudo_ctx *sudo_ctx);

struct tevent_req *
ipa_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_sudo_ctx *sudo_ctx);

int
ipa_sudo_full_refresh_recv(struct tevent_req *req,
                           int *dp_error);

int
ipa_sudo_rules_refresh_recv(struct tevent_req *req,
                            int *dp_error,
                            bool *deleted);

struct tevent_req *
ipa_sudo_refresh_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct ipa_sudo_ctx *sudo_ctx,
                      const char *cmdgroups_filter,
                      const char *search_filter,
                      const char *delete_filter,
                      bool update_usn);

struct tevent_req *
ipa_sudo_rules_refresh_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ipa_sudo_ctx *sudo_ctx,
                            const char **rules);

errno_t
ipa_sudo_refresh_recv(struct tevent_req *req,
                      int *dp_error,
                      size_t *_num_rules);

struct ipa_sudo_conv;

struct ipa_sudo_conv *
ipa_sudo_conv_init(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *dom,
                   struct sdap_attr_map *map_rule,
                   struct sdap_attr_map *map_cmdgroup,
                   struct sdap_attr_map *map_cmd,
                   struct sdap_attr_map *map_user,
                   struct sdap_attr_map *map_group,
                   struct sdap_attr_map *map_host,
                   struct sdap_attr_map *map_hostgroup);

errno_t
ipa_sudo_conv_rules(struct ipa_sudo_conv *conv,
                    struct sysdb_attrs **rules,
                    size_t num_rules);

errno_t
ipa_sudo_conv_cmdgroups(struct ipa_sudo_conv *conv,
                        struct sysdb_attrs **cmdgroups,
                        size_t num_cmdgroups);

errno_t
ipa_sudo_conv_cmds(struct ipa_sudo_conv *conv,
                   struct sysdb_attrs **cmds,
                   size_t num_cmds);

bool
ipa_sudo_conv_has_cmdgroups(struct ipa_sudo_conv *conv);

bool
ipa_sudo_conv_has_cmds(struct ipa_sudo_conv *conv);

bool
ipa_sudo_cmdgroups_exceed_threshold(struct ipa_sudo_conv *conv, int threshold);

bool
ipa_sudo_cmds_exceed_threshold(struct ipa_sudo_conv *conv, int threshold);

char *
ipa_sudo_conv_cmdgroup_filter(TALLOC_CTX *mem_ctx,
                              struct ipa_sudo_conv *conv,
                              int cmd_threshold);

char *
ipa_sudo_conv_cmd_filter(TALLOC_CTX *mem_ctx,
                         struct ipa_sudo_conv *conv,
                         int cmd_threshold);

errno_t
ipa_sudo_conv_result(TALLOC_CTX *mem_ctx,
                     struct ipa_sudo_conv *conv,
                     struct sysdb_attrs ***_rules,
                     size_t *_num_rules);

#endif /* _IPA_SUDO_H_ */

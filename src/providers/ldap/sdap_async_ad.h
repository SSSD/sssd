/*
    SSSD - header files for AD specific enhancement in the common LDAP/SDAP
           code

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef SDAP_ASYNC_AD_H_
#define SDAP_ASYNC_AD_H_

errno_t sdap_ad_save_group_membership_with_idmapping(const char *username,
                                               struct sdap_options *opts,
                                               struct sss_domain_info *user_dom,
                                               struct sdap_idmap_ctx *idmap_ctx,
                                               size_t num_sids,
                                               char **sids);

errno_t
sdap_ad_tokengroups_get_posix_members(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *user_domain,
                                      size_t num_sids,
                                      char **sids,
                                      size_t *_num_missing,
                                      char ***_missing,
                                      size_t *_num_valid,
                                      char ***_valid_groups);

errno_t
sdap_ad_tokengroups_update_members(const char *username,
                                   struct sysdb_ctx *sysdb,
                                   struct sss_domain_info *domain,
                                   char **ldap_groups);
struct tevent_req *
sdap_ad_resolve_sids_send(TALLOC_CTX *mem_ctx,
                          struct tevent_context *ev,
                          struct sdap_id_ctx *id_ctx,
                          struct sdap_id_conn_ctx *conn,
                          struct sdap_options *opts,
                          struct sss_domain_info *domain,
                          char **sids);

errno_t sdap_ad_resolve_sids_recv(struct tevent_req *req);
#endif /* SDAP_ASYNC_AD_H_ */

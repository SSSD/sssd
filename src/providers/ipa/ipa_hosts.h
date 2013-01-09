/*
    SSSD

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

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

#ifndef IPA_HOSTS_H_
#define IPA_HOSTS_H_

struct tevent_req *
ipa_host_info_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct sdap_handle *sh,
                   struct sdap_options *opts,
                   const char *hostname,
                   struct sdap_attr_map *host_map,
                   struct sdap_attr_map *hostgroup_map,
                   struct sdap_search_base **search_bases);

errno_t
ipa_host_info_recv(struct tevent_req *req,
                   TALLOC_CTX *mem_ctx,
                   size_t *host_count,
                   struct sysdb_attrs ***hosts,
                   size_t *hostgroup_count,
                   struct sysdb_attrs ***hostgroups);

#endif /* IPA_HOSTS_H_ */

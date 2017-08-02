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

#ifndef IPA_HBAC_RULES_H_
#define IPA_HBAC_RULES_H_

/* From ipa_hbac_rules.c */
struct tevent_req *
ipa_hbac_rule_info_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_handle *sh,
                        struct sdap_options *opts,
                        struct sdap_search_base **search_bases,
                        struct sysdb_attrs *ipa_host);

errno_t
ipa_hbac_rule_info_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        size_t *_rule_count,
                        struct sysdb_attrs ***_rules);

#endif /* IPA_HBAC_RULES_H_ */

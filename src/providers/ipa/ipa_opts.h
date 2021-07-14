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

#ifndef IPA_OPTS_H_
#define IPA_OPTS_H_

#include "src/providers/data_provider.h"
#include "providers/ldap/ldap_common.h"

extern struct dp_option ipa_basic_opts[];

extern struct dp_option ipa_dyndns_opts[];

extern struct dp_option ipa_def_ldap_opts[];

extern struct sdap_attr_map ipa_attr_map[];

extern struct sdap_attr_map ipa_user_map[];

extern struct sdap_attr_map ipa_group_map[];

extern struct sdap_attr_map ipa_netgroup_map[];

extern struct sdap_attr_map ipa_subid_map[];

extern struct sdap_attr_map ipa_host_map[];

extern struct sdap_attr_map ipa_hostgroup_map[];

extern struct sdap_attr_map ipa_selinux_user_map[];

extern struct sdap_attr_map ipa_view_map[];

extern struct sdap_attr_map ipa_override_map[];

extern struct dp_option ipa_def_krb5_opts[];

extern struct sdap_attr_map ipa_service_map[];

extern struct sdap_attr_map ipa_autofs_mobject_map[];

extern struct sdap_attr_map ipa_autofs_entry_map[];

extern struct sdap_attr_map ipa_sudorule_map[];

extern struct sdap_attr_map ipa_sudocmdgroup_map[];

extern struct sdap_attr_map ipa_sudocmd_map[];

extern struct dp_option ipa_cli_ad_subdom_opts[];

#endif /* IPA_OPTS_H_ */

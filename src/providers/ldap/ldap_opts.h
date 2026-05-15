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

#ifndef LDAP_OPTS_H_
#define LDAP_OPTS_H_

#include "src/providers/data_provider.h"
#include "providers/ldap/ldap_common.h"

extern struct dp_option default_basic_opts[];

extern struct sdap_attr_map generic_attr_map[];

extern struct sdap_attr_map gen_ipa_attr_map[];

extern struct sdap_attr_map gen_ad_attr_map[];

extern struct sdap_attr_map rfc2307_user_map[];

extern struct sdap_attr_map rfc2307_group_map[];

extern struct sdap_attr_map rfc2307bis_user_map[];

extern struct sdap_attr_map rfc2307bis_group_map[];

extern struct sdap_attr_map gen_ad2008r2_user_map[];

extern struct sdap_attr_map gen_ad2008r2_group_map[];

extern struct sdap_attr_map netgroup_map[];

extern struct sdap_attr_map subid_map[];

extern struct sdap_attr_map host_map[];

extern struct sdap_attr_map native_sudorule_map[];

extern struct sdap_attr_map service_map[];

extern struct sdap_attr_map iphost_map[];

extern struct sdap_attr_map ipnetwork_map[];

extern struct sdap_attr_map rfc2307_autofs_mobject_map[];

extern struct sdap_attr_map rfc2307_autofs_entry_map[];

extern struct sdap_attr_map rfc2307bis_autofs_mobject_map[];

extern struct sdap_attr_map rfc2307bis_autofs_entry_map[];

#endif /* LDAP_OPTS_H_ */

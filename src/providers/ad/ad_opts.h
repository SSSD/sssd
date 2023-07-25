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

#ifndef AD_OPTS_H_
#define AD_OPTS_H_

#include "src/providers/data_provider.h"
#include "providers/ldap/ldap_common.h"

extern struct dp_option ad_basic_opts[];

extern struct dp_option ad_def_ldap_opts[];

extern struct dp_option ad_def_krb5_opts[];

extern struct sdap_attr_map ad_2008r2_attr_map[];

extern struct sdap_attr_map ad_2008r2_user_map[];

extern struct sdap_attr_map ad_2008r2_group_map[];

extern struct sdap_attr_map ad_netgroup_map[];

extern struct sdap_attr_map ad_service_map[];

extern struct sdap_attr_map ad_autofs_mobject_map[];

extern struct sdap_attr_map ad_autofs_entry_map[];

extern struct sdap_attr_map ad_iphost_map[];

extern struct sdap_attr_map ad_ipnetwork_map[];

extern struct dp_option ad_dyndns_opts[];

extern struct sdap_attr_map ad_sudorule_map[];

#endif /* AD_OPTS_H_ */

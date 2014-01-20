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
};

void
ad_access_handler(struct be_req *breq);

#endif /* AD_ACCESS_H_ */

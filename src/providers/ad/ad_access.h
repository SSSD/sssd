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
    struct sdap_id_ctx *sdap_ctx;
    struct dp_option *ad_options;
    struct sdap_access_ctx *sdap_access_ctx;
};

void
ad_access_handler(struct be_req *breq);

#endif /* AD_ACCESS_H_ */

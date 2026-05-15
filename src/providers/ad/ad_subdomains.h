/*
    SSSD

    AD Subdomains Module

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

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

#ifndef _AD_SUBDOMAINS_H_
#define _AD_SUBDOMAINS_H_

#include "providers/backend.h"
#include "providers/ad/ad_common.h"

errno_t ad_subdomains_init(TALLOC_CTX *mem_ctx,
                           struct be_ctx *be_ctx,
                           struct ad_id_ctx *ad_id_ctx,
                           struct dp_method *dp_methods);

#endif /* _AD_SUBDOMAINS_H_ */

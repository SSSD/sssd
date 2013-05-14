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

#ifndef SDAP_RANGE_H_
#define SDAP_RANGE_H_

#include "src/util/util.h"

errno_t sdap_parse_range(TALLOC_CTX *mem_ctx,
                         const char *attr_desc,
                         char **base_attr,
                         uint32_t *range_offset,
                         bool disable_range_retrieval);

#endif /* SDAP_RANGE_H_ */

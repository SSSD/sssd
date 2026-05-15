/*
    Authors:
        Hristo Venev <hristo@venev.name>

    Copyright (C) 2017 Red Hat

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

#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_hostid.h"

errno_t ipa_hostid_init(TALLOC_CTX *mem_ctx,
                        struct be_ctx *be_ctx,
                        struct ipa_id_ctx *id_ctx,
                        struct dp_method *dp_methods)
{
    return sdap_hostid_init(mem_ctx, be_ctx, id_ctx->sdap_id_ctx, dp_methods);
}

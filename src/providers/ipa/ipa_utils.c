/*
    SSSD

    IPA Provider Utility Functions

    Authors:
        Simo Sorce <ssorce@redhat.com>, Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009-2010 Red Hat

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

int domain_to_basedn(TALLOC_CTX *memctx, const char *domain, char **basedn)
{
    const char *s;
    char *dn;
    char *p;
    int l;

    if (!domain || !basedn) {
        return EINVAL;
    }

    s = domain;
    dn = talloc_strdup(memctx, "dc=");

    while ((p = strchr(s, '.'))) {
        l = p - s;
        dn = talloc_asprintf_append_buffer(dn, "%.*s,dc=", l, s);
        if (!dn) {
            return ENOMEM;
        }
        s = p + 1;
    }
    dn = talloc_strdup_append_buffer(dn, s);
    if (!dn) {
        return ENOMEM;
    }

    *basedn = dn;
    return EOK;
}

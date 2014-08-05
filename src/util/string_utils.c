/*
    SSSD

    Authors:
        Lukas Slebodnik <slebodnikl@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "util/util.h"

static char *replace_char(TALLOC_CTX *mem_ctx,
                          const char *in,
                          const char match,
                          const char sub)
{
    char *p;
    char *out;

    out = talloc_strdup(mem_ctx, in);
    if (out == NULL) {
        return NULL;
    }

    for (p = out; *p != '\0'; ++p) {
        if (*p == match) {
            *p = sub;
        }
    }

    return out;
}

char * sss_replace_space(TALLOC_CTX *mem_ctx,
                         const char *orig_name,
                         const char subst)
{
    if (subst == '\0') {
        return talloc_strdup(mem_ctx, orig_name);
    }
    return replace_char(mem_ctx, orig_name, ' ', subst);
}

char * sss_reverse_replace_space(TALLOC_CTX *mem_ctx,
                                 char *orig_name,
                                 const char subst)
{
    if (subst == '\0') {
        return talloc_strdup(mem_ctx, orig_name);
    }
    return replace_char(mem_ctx, orig_name, subst, ' ');
}

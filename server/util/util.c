/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include "talloc.h"
#include "util/util.h"

/* Split string in a list using a set of legal seprators */

int sss_split_list(TALLOC_CTX *memctx, const char *string,
                   const char *sep, char ***_list, int *c)
{
    const char *p;
    const char *s;
    char **list;
    char **t;
    int i;

    /* split server parm into a list */
    list = NULL;
    s = string;
    i = 0;

    while (s) {
        p = strpbrk(s, sep);
        if (p) {
            if (p - s == 1) {
                s++;
                continue;
            }

            t = talloc_realloc(memctx, list, char *, i + 1);
            if (!t) {
                talloc_zfree(list);
                return ENOMEM;
            }
            list = t;
            list[i] = talloc_asprintf(list, "%.*s", (int)(p - s), s);
            if (!list[i]) {
                talloc_zfree(list);
                return ENOMEM;
            }
            i++;

            s = p + 1;
        }
        else {

            t = talloc_realloc(memctx, list, char *, i + 1);
            if (!t) {
                talloc_zfree(list);
                return ENOMEM;
            }
            list = t;
            list[i] = talloc_strdup(list, s);
            if (!list[i]) {
                talloc_zfree(list);
                return ENOMEM;
            }
            i++;

            s = NULL;
        }
    }

    *_list = list;
    *c = i;
    return EOK;
}


/*
   SSSD

   Common Responder utility functions

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

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

#include <talloc.h>

#include "util/util.h"

static inline bool
attr_in_list(const char **list, size_t nlist, const char *str)
{
    size_t i;

    for (i = 0; i < nlist; i++) {
        if (strcasecmp(list[i], str) == 0) {
            break;
        }
    }

    return (i < nlist) ? true : false;
}

const char **parse_attr_list_ex(TALLOC_CTX *mem_ctx, const char *conf_str,
                                const char **defaults)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char **list = NULL;
    const char **res = NULL;
    int list_size;
    char **conf_list = NULL;
    int conf_list_size = 0;
    const char **allow = NULL;
    const char **deny = NULL;
    int ai = 0, di = 0, li = 0;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    if (conf_str) {
        ret = split_on_separator(tmp_ctx, conf_str, ',', true, true,
                                 &conf_list, &conf_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse attribute ACL list  %s: %d\n", conf_str, ret);
            goto done;
        }

        allow = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        deny = talloc_zero_array(tmp_ctx, const char *, conf_list_size);
        if (allow == NULL || deny == NULL) {
            goto done;
        }
    }

    for (i = 0; i < conf_list_size; i++) {
        switch (conf_list[i][0]) {
            case '+':
                allow[ai] = conf_list[i] + 1;
                ai++;
                continue;
            case '-':
                deny[di] = conf_list[i] + 1;
                di++;
                continue;
            default:
                DEBUG(SSSDBG_CRIT_FAILURE, "ACL values must start with "
                      "either '+' (allow) or '-' (deny), got '%s'\n",
                      conf_list[i]);
                goto done;
        }
    }

    /* Assume the output will have to hold defaults and all the configured,
     * values, resize later
     */
    list_size = 0;
    if (defaults != NULL) {
        while (defaults[list_size]) {
            list_size++;
        }
    }
    list_size += conf_list_size;

    list = talloc_zero_array(tmp_ctx, const char *, list_size + 1);
    if (list == NULL) {
        goto done;
    }

    /* Start by copying explicitly allowed attributes */
    for (i = 0; i < ai; i++) {
        /* if the attribute is explicitly denied, skip it */
        if (attr_in_list(deny, di, allow[i])) {
            continue;
        }

        list[li] = talloc_strdup(list, allow[i]);
        if (list[li] == NULL) {
            goto done;
        }
        li++;

        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Added allowed attr %s to whitelist\n", allow[i]);
    }

    /* Add defaults */
    if (defaults != NULL) {
        for (i = 0; defaults[i]; i++) {
            /* if the attribute is explicitly denied, skip it */
            if (attr_in_list(deny, di, defaults[i])) {
                continue;
            }

            list[li] = talloc_strdup(list, defaults[i]);
            if (list[li] == NULL) {
                goto done;
            }
            li++;

            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Added default attr %s to whitelist\n", defaults[i]);
        }
    }

    res = talloc_steal(mem_ctx, list);
done:
    talloc_free(tmp_ctx);
    return res;
}

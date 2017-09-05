/*
   SSSD - certificate handling utils
   The calls defined here should be useable outside of SSSD as well, e.g. in
   libsss_certmap.

   Copyright (C) Sumit Bose <sbose@redhat.com> 2017

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

#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "lib/certmap/sss_certmap_int.h"

int get_short_name(TALLOC_CTX *mem_ctx, const char *full_name,
                   char delim, char **short_name)
{
    char *at;
    char *s;

    if (full_name == NULL || delim == '\0' || short_name == NULL) {
        return EINVAL;
    }

    at = strchr(full_name, delim);
    if (at != NULL) {
        s = talloc_strndup(mem_ctx, full_name, (at - full_name));
    } else {
        s = talloc_strdup(mem_ctx, full_name);
    }
    if (s == NULL) {
        return ENOMEM;
    }

    *short_name = s;

    return 0;
}

int add_to_san_list(TALLOC_CTX *mem_ctx, bool is_bin,
                    enum san_opt san_opt, const uint8_t *data, size_t len,
                    struct san_list **item)
{
    struct san_list *i;

    if (data == NULL || len == 0 || san_opt == SAN_INVALID) {
        return EINVAL;
    }

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }

    i->san_opt = san_opt;
    if (is_bin) {
        i->bin_val = talloc_memdup(i, data, len);
        i->bin_val_len = len;
    } else {
        i->val = talloc_strndup(i, (const char *) data, len);
    }
    if (i->val == NULL) {
        talloc_free(i);
        return ENOMEM;
    }

    *item = i;

    return 0;
}

int add_principal_to_san_list(TALLOC_CTX *mem_ctx, enum san_opt san_opt,
                              const char *princ, struct san_list **item)
{
    struct san_list *i = NULL;
    int ret;

    i = talloc_zero(mem_ctx, struct san_list);
    if (i == NULL) {
        return ENOMEM;
    }
    i->san_opt = san_opt;

    i->val = talloc_strdup(i, princ);
    if (i->val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = get_short_name(i, i->val, '@', &(i->short_name));
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *item = i;
    } else {
        talloc_free(i);
    }

    return ret;
}

int rdn_list_2_dn_str(TALLOC_CTX *mem_ctx, const char *conversion,
                      const char **rdn_list, char **result)
{
    char *str = NULL;
    size_t c;
    int ret;
    char *conv = NULL;

    str = talloc_strdup(mem_ctx, "");
    if (str == NULL) {
        ret = ENOMEM;
        goto done;
    }
    if (conversion == NULL || strcmp(conversion, "nss_ldap") == 0
                           || strcmp(conversion, "nss") == 0) {
        for (c = 0; rdn_list[c] != NULL; c++);
        while (c != 0) {
            c--;
            str = talloc_asprintf_append(str, "%s%s",
                                         (rdn_list[c + 1] == NULL) ? "" : ",",
                                         rdn_list[c]);
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
        };
    } else if (strcmp(conversion, "ad_ldap") == 0) {
        for (c = 0; rdn_list[c] != NULL; c++);
        while (c != 0) {
            c--;
            conv = check_ad_attr_name(str, rdn_list[c]);
            str = talloc_asprintf_append(str, "%s%s",
                                         (rdn_list[c + 1] == NULL) ? "" : ",",
                                         conv == NULL ? rdn_list[c] : conv);
            talloc_free(conv);
            conv = NULL;
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
        };
    } else if (strcmp(conversion, "nss_x500") == 0) {
        for (c = 0; rdn_list[c] != NULL; c++) {
            str = talloc_asprintf_append(str, "%s%s", (c == 0) ? "" : ",",
                                                       rdn_list[c]);
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    } else if (strcmp(conversion, "ad_x500") == 0
                        || strcmp(conversion, "ad") == 0) {
        for (c = 0; rdn_list[c] != NULL; c++) {
            conv = check_ad_attr_name(str, rdn_list[c]);
            str = talloc_asprintf_append(str, "%s%s",
                                         (c == 0) ? "" : ",",
                                         conv == NULL ? rdn_list[c] : conv);
            talloc_free(conv);
            conv = NULL;
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
        }
    } else {
        ret = EINVAL;
        goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *result = str;
    } else {
        talloc_free(str);
    }

    return ret;
}

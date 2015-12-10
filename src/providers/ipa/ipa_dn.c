/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include <ldb.h>
#include "db/sysdb.h"
#include "providers/ipa/ipa_dn.h"

static bool check_dn(struct ldb_dn *dn,
                     const char *rdn_attr,
                     va_list in_ap)
{
    const struct ldb_val *ldbval;
    const char *strval;
    const char *ldbattr;
    const char *attr;
    const char *val;
    va_list ap;
    int num_comp;
    int comp;

    /* check RDN attribute */
    ldbattr = ldb_dn_get_rdn_name(dn);
    if (ldbattr == NULL || strcasecmp(ldbattr, rdn_attr) != 0) {
        return false;
    }

    /* Check DN components. First we check if all attr=value pairs match input.
     * Then we check that the next attribute is a domain component.
     */

    comp = 1;
    num_comp = ldb_dn_get_comp_num(dn);

    va_copy(ap, in_ap);
    while ((attr = va_arg(ap, const char *)) != NULL) {
        val = va_arg(ap, const char *);
        if (val == NULL) {
            goto vafail;
        }

        if (comp > num_comp) {
            goto vafail;
        }

        ldbattr = ldb_dn_get_component_name(dn, comp);
        if (ldbattr == NULL || strcasecmp(ldbattr, attr) != 0) {
            goto vafail;
        }

        ldbval = ldb_dn_get_component_val(dn, comp);
        if (ldbval == NULL) {
            goto vafail;
        }

        strval = (const char *)ldbval->data;
        if (strval == NULL || strncasecmp(strval, val, ldbval->length) != 0) {
            goto vafail;
        }

        comp++;
    }
    va_end(ap);

    ldbattr = ldb_dn_get_component_name(dn, comp);
    if (ldbattr == NULL || strcmp(ldbattr, "dc") != 0) {
        return false;
    }

    return true;

vafail:
    va_end(ap);
    return false;
}

errno_t _ipa_get_rdn(TALLOC_CTX *mem_ctx,
                      struct sysdb_ctx *sysdb,
                      const char *obj_dn,
                      char **_rdn_val,
                      const char *rdn_attr,
                      ...)
{
    const struct ldb_val *val;
    struct ldb_dn *dn;
    errno_t ret;
    bool bret;
    va_list ap;
    char *rdn;

    dn = ldb_dn_new(mem_ctx, sysdb_ctx_get_ldb(sysdb), obj_dn);
    if (dn == NULL) {
        return ENOMEM;
    }

    va_start(ap, rdn_attr);
    bret = check_dn(dn, rdn_attr, ap);
    va_end(ap);
    if (bret == false) {
        ret = ENOENT;
        goto done;
    }

    if (_rdn_val == NULL) {
        ret = EOK;
        goto done;
    }

    val = ldb_dn_get_rdn_val(dn);
    if (val == NULL || val->data == NULL) {
        ret = EINVAL;
        goto done;
    }

    rdn = talloc_strndup(mem_ctx, (const char*)val->data, val->length);
    if (rdn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_rdn_val = rdn;

    ret = EOK;

done:
    talloc_free(dn);
    return ret;
}

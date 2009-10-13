/*
    Authors:
        Sumit Bose <sbose@redhat.com>

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
#include <stdlib.h>

#include "config.h"

#include "util/sss_ldap.h"


int sss_ldap_control_create(const char *oid, int iscritical,
                            struct berval *value, int dupval,
                            LDAPControl **ctrlp)
{
#ifdef HAVE_LDAP_CONTROL_CREATE
    return ldap_control_create(oid, iscritical, value, dupval, ctrlp);
#else
    LDAPControl *lc = NULL;

    if (oid == NULL || ctrlp == NULL) {
        return LDAP_PARAM_ERROR;
    }

    lc = calloc(sizeof(LDAPControl), 1);
    if (lc == NULL) {
        return LDAP_NO_MEMORY;
    }

    lc->ldctl_oid = strdup(oid);
    if (lc->ldctl_oid == NULL) {
        free(lc);
        return LDAP_NO_MEMORY;
    }

    if (value != NULL && value->bv_val != NULL) {
        if (dupval == 0) {
            lc->ldctl_value = *value;
        } else {
            ber_dupbv(&lc->ldctl_value, value);
            if (lc->ldctl_value.bv_val == NULL) {
                free(lc->ldctl_oid);
                free(lc);
                return LDAP_NO_MEMORY;
            }
        }
    }

    lc->ldctl_iscritical = iscritical;

    *ctrlp = lc;

    return LDAP_SUCCESS;
#endif
}

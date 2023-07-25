/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2023 Red Hat

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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <krad.h>
#include <krb5/kdcpreauth_plugin.h>

#include "radius_kdcpreauth.h"
#include "util/util.h"

void
sss_radiuscl_init(krb5_context context,
                  krb5_clpreauth_moddata moddata,
                  krb5_clpreauth_modreq *modreq_out)
{
    return;
}

void
sss_radiuscl_fini(krb5_context context,
                  krb5_clpreauth_moddata moddata,
                  krb5_clpreauth_modreq modreq)
{
    return;
}

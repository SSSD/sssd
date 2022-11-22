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

#ifndef _RADIUS_CLPREAUTH_H_
#define _RADIUS_CLPREAUTH_H_

#include <stdlib.h>
#include <krb5/preauth_plugin.h>

void
sss_radiuscl_init(krb5_context context,
                  krb5_clpreauth_moddata moddata,
                  krb5_clpreauth_modreq *modreq_out);

void
sss_radiuscl_fini(krb5_context context,
                  krb5_clpreauth_moddata moddata,
                  krb5_clpreauth_modreq modreq);

#endif /* _RADIUS_CLPREAUTH_H_ */

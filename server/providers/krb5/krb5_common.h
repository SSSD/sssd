/*
    SSSD

    Kerberos Backend, common header file

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

#ifndef __KRB5_COMMON_H__
#define __KRB5_COMMON_H__

#include "config.h"
#include <stdbool.h>
#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif

#define SSSD_KRB5_KDC "SSSD_KRB5_KDC"
#define SSSD_KRB5_REALM "SSSD_KRB5_REALM"

#endif /* __KRB5_COMMON_H__ */

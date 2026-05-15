/*
    Authors:
        Lukas Slebodnik <lslebodn@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef _SSS_LIBCRYTPO_SSS_OPENSSL_H_
#define _SSS_LIBCRYTPO_SSS_OPENSSL_H_

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

/* EVP_MD_CTX_create and EVP_MD_CTX_destroy are deprecated macros
 * in openssl-1.1 but openssl-1.0 does not know anything about
 * newly added functions EVP_MD_CTX_new, EVP_MD_CTX_free in 1.1
 */

# define EVP_MD_CTX_new() EVP_MD_CTX_create()
# define EVP_MD_CTX_free(ctx) EVP_MD_CTX_destroy((ctx))

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */


#endif /* _SSS_LIBCRYTPO_SSS_OPENSSL_H_ */

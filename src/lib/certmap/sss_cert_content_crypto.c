/*
   SSSD - certificate handling utils - OpenSSL version
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

#include <errno.h>

#include "lib/certmap/sss_certmap.h"
#include "lib/certmap/sss_certmap_int.h"

int sss_cert_get_content(TALLOC_CTX *mem_ctx,
                         const uint8_t *der_blob, size_t der_size,
                         struct sss_cert_content **content)
{
    return EINVAL;
}

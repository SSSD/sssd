/*
    SSSD

    ID-mapping library - private headers

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef SSS_IDMAP_PRIVATE_H_
#define SSS_IDMAP_PRIVATE_H_

#define CHECK_IDMAP_CTX(ctx, ret) do { \
    if (ctx == NULL || ctx->alloc_func == NULL || ctx->free_func == NULL) { \
        return ret; \
    } \
} while(0)

struct sss_idmap_ctx {
    idmap_alloc_func *alloc_func;
    void *alloc_pvt;
    idmap_free_func *free_func;
    struct idmap_domain_info *idmap_domain_info;
};

#endif /* SSS_IDMAP_PRIVATE_H_ */

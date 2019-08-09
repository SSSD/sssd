/*
    Generated by sbus code generator

    Copyright (C) 2017 Red Hat

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

#include <inttypes.h>
#include <talloc.h>

#include "sbus/sbus_request.h"
#include "sss_iface/sbus_sss_arguments.h"
#include "sss_iface/sbus_sss_keygens.h"

const char *
_sbus_sss_key_
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s",
            sbus_req->type, sbus_req->interface, sbus_req->member, sbus_req->path);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member, sbus_req->path);
}

const char *
_sbus_sss_key_s_0
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_s *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s:%s",
            sbus_req->type, sbus_req->interface, sbus_req->member,
            sbus_req->path, args->arg0);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member,
        sbus_req->path, args->arg0);
}

const char *
_sbus_sss_key_u_0
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_u *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s:%" PRIu32 "",
            sbus_req->type, sbus_req->interface, sbus_req->member,
            sbus_req->path, args->arg0);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s:%" PRIu32 "",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member,
        sbus_req->path, args->arg0);
}

const char *
_sbus_sss_key_us_0_1
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_us *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s:%" PRIu32 ":%s",
            sbus_req->type, sbus_req->interface, sbus_req->member,
            sbus_req->path, args->arg0, args->arg1);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s:%" PRIu32 ":%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member,
        sbus_req->path, args->arg0, args->arg1);
}

const char *
_sbus_sss_key_uss_0_1
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_uss *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s:%" PRIu32 ":%s",
            sbus_req->type, sbus_req->interface, sbus_req->member,
            sbus_req->path, args->arg0, args->arg1);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s:%" PRIu32 ":%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member,
        sbus_req->path, args->arg0, args->arg1);
}

const char *
_sbus_sss_key_uss_0_1_2
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_uss *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s:%" PRIu32 ":%s:%s",
            sbus_req->type, sbus_req->interface, sbus_req->member,
            sbus_req->path, args->arg0, args->arg1, args->arg2);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s:%" PRIu32 ":%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member,
        sbus_req->path, args->arg0, args->arg1, args->arg2);
}

const char *
_sbus_sss_key_uusss_0_1_2_3_4
   (TALLOC_CTX *mem_ctx,
    struct sbus_request *sbus_req,
    struct _sbus_sss_invoker_args_uusss *args)
{
    if (sbus_req->sender == NULL) {
        return talloc_asprintf(mem_ctx, "-:%u:%s.%s:%s:%" PRIu32 ":%" PRIu32 ":%s:%s:%s",
            sbus_req->type, sbus_req->interface, sbus_req->member,
            sbus_req->path, args->arg0, args->arg1, args->arg2, args->arg3, args->arg4);
    }

    return talloc_asprintf(mem_ctx, "%"PRIi64":%u:%s.%s:%s:%" PRIu32 ":%" PRIu32 ":%s:%s:%s",
        sbus_req->sender->uid, sbus_req->type, sbus_req->interface, sbus_req->member,
        sbus_req->path, args->arg0, args->arg1, args->arg2, args->arg3, args->arg4);
}


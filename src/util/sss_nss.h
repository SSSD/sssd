/*
   SSSD

   Utility functions related to ID information

   Copyright (C) Jan Zeleny <jzeleny@redhat.com> 2012

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

#ifndef __SSS_NSS_H__
#define __SSS_NSS_H__

#include <stdbool.h>
#include <sys/types.h>
#include <talloc.h>

struct sss_nss_homedir_ctx {
    const char *username;
    uint32_t uid;
    const char *original;
    const char *domain;
    const char *flatname;
    const char *config_homedir_substr;
    const char *upn;
};

char *expand_homedir_template(TALLOC_CTX *mem_ctx, const char *template,
                              bool case_sensitive,
                              struct sss_nss_homedir_ctx *homedir_ctx);
#endif

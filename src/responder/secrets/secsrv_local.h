/*
   SSSD

   Secrets Local Provider

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2016

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

#ifndef __SECSRV_LOCAL_H__
#define __SECSRV_LOCAL_H__

int local_secrets_provider_handle(TALLOC_CTX *mem_ctx,
                                  struct provider_handle **handle);

#endif /* __SECSRV_LOCAL_H__ */

/*
   SSSD

   User tools

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <pwd.h>
#include <talloc.h>

char *get_username_from_uid(TALLOC_CTX *mem_ctx, uid_t uid)
{
    char *username;
    struct passwd *pwd;

    pwd = getpwuid(uid);
    if (!pwd) return NULL;

    username = talloc_strdup(mem_ctx, pwd->pw_name);
    return username;
}

/*
    SSSD

    ID-mapping plugin for winbind - helper library for dlopen test

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "lib/winbind_idmap_sss/winbind_idmap_sss.h"

NTSTATUS smb_register_idmap(int version, const char *name,
                            struct idmap_methods *methods)
{
    return NT_STATUS_OK;
}

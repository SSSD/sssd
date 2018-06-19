/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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

#ifndef _IFP_IFACE_H_
#define _IFP_IFACE_H_

#define IFP_BUS     "org.freedesktop.sssd.infopipe"

#define IFP_PATH "/org/freedesktop/sssd/infopipe"

#define IFP_PATH_DOMAINS IFP_PATH "/Domains"
#define IFP_PATH_DOMAINS_TREE IFP_PATH_DOMAINS "/*"

#define IFP_PATH_COMPONENTS IFP_PATH "/Components"
#define IFP_PATH_COMPONENTS_TREE IFP_PATH_COMPONENTS "/*"

#define IFP_PATH_GROUPS IFP_PATH "/Groups"
#define IFP_PATH_GROUPS_TREE IFP_PATH_GROUPS "/*"

#define IFP_PATH_USERS IFP_PATH "/Users"
#define IFP_PATH_USERS_TREE IFP_PATH_USERS "/*"

#endif /* _IFP_IFACE_H_ */

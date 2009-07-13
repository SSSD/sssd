/*
    ELAPI

    Private header file continaing internal data for the ELAPI interface.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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

#ifndef ELAPI_PRIV_H
#define ELAPI_PRIV_H

/* Classes of the collections used by ELAPI internally */
#define COL_CLASS_ELAPI_BASE        21000
#define COL_CLASS_ELAPI_EVENT       COL_CLASS_ELAPI_BASE + 0
#define COL_CLASS_ELAPI_TEMPLATE    COL_CLASS_ELAPI_BASE + 1

/* Names for the collections */
#define E_TEMPLATE_NAME "template"
#define E_EVENT_NAME "event"

#endif

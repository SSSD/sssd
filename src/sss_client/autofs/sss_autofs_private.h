/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include <errno.h>
#include "util/util.h"

/**
 * Choose an autofs protocol version to be used between autofs and sss_autofs.
 */
unsigned int _sss_auto_protocol_version(unsigned int requested);

/**
 * Selects a map for processing.
 */
errno_t _sss_setautomntent(const char *mapname, void **context);

/**
 * Iterates through key/value pairs in the selected map. The key is usually
 * the mount point, the value is mount information (server:/export)
 */
errno_t _sss_getautomntent_r(char **key, char **value, void *context);

/**
 * Returns value for a specific key
 */
errno_t
_sss_getautomntbyname_r(const char *key, char **value, void *context);

/**
 * Deselect a map, end the processing
 */
errno_t _sss_endautomntent(void **context);


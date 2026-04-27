/*
    SSSD

    Himmelblau Provider - Configuration options

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#ifndef _HIMMELBLAU_OPTS_H_
#define _HIMMELBLAU_OPTS_H_

#include "src/providers/data_provider.h"

enum himmelblau_opts {
    HIMMELBLAU_DOMAIN,
    HIMMELBLAU_DEVICE_STORAGE,
    HIMMELBLAU_OPTS
};

extern struct dp_option default_himmelblau_opts[];

#endif /* _HIMMELBLAU_OPTS_H_ */

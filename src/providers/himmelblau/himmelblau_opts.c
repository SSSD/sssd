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

#include "providers/himmelblau/himmelblau_opts.h"
#include "src/providers/data_provider.h"

struct dp_option default_himmelblau_opts[] = {
    { "himmelblau_domain", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idmap_lower", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    { "idmap_upper", DP_OPT_NUMBER, { .number = 2000200000 }, NULL_NUMBER },
    { "idmap_rangesize", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    DP_OPTION_TERMINATOR
};

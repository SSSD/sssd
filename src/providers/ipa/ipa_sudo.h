/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef _IPA_SUDO_H_
#define _IPA_SUDO_H_

#include "providers/ipa/ipa_common.h"

struct ipa_sudo_ctx {
    struct sdap_id_ctx *id_ctx;
    struct ipa_options *ipa_opts;
    struct sdap_options *sdap_opts;

    /* sudo */
    struct sdap_attr_map *sudocmdgroup_map;
    struct sdap_attr_map *sudorule_map;
    struct sdap_attr_map *sudocmd_map;
    struct sdap_search_base **sudo_sb;
};

#endif /* _IPA_SUDO_H_ */

/*
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

#ifndef __PROBES_H_
#define __PROBES_H_

#ifdef HAVE_SYSTEMTAP

#include "stap_generated_probes.h"

/* Probe expansion inspired by libvirt */
#define PROBE_EXPAND(NAME, ...) NAME(__VA_ARGS__)

#define PROBE(NAME, ...) do {               \
    if (SSSD_ ## NAME ## _ENABLED()) {      \
        PROBE_EXPAND(SSSD_ ## NAME,         \
                     __VA_ARGS__);          \
    }                                       \
} while(0);

/* Systemtap doesn't handle copying NULL strings well */
#define PROBE_SAFE_STR(s) ((s) ? (s) : "")

#else

/* No systemtap, define empty macros */
#define PROBE(NAME, ...) do {         \
} while(0);

#endif

#endif  /* __PROBES_H_ */

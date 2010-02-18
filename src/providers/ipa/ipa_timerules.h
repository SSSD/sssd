/*
   SSSD

   IPA Provider Time Rules Parsing

   Authors:
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#ifndef __IPA_TIMERULES_H_
#define __IPA_TIMERULES_H_

#include <stdbool.h>
#include <talloc.h>

/* Opaque structure given after init */
struct time_rules_ctx;

/*
 * Init the parser. Destroy the allocated resources by simply
 * talloc_free()-ing the time_rules_ctx
 */
int init_time_rules_parser(TALLOC_CTX *mem_ctx,
                           struct time_rules_ctx **_out);

/*
 * This is actually the meat of the library. The function takes a string
 * representation of a time rule in STR and time to check against (usually that
 * would be current time) in NOW.
 *
 * It returns EOK if the rule can be parsed, error code if not. If the time
 * given in the NOW parameter would be accepted by the rule, it stores true in
 * RESULT, false otherwise.
 */
int check_time_rule(TALLOC_CTX *mem_ctx,
                    struct time_rules_ctx *trctx,
                    const char *str,
                    const time_t now,
                    bool *result);

#endif /* __IPA_TIMERULES_H_ */

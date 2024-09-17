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

#ifndef _SSS_TOOLS_H_
#define _SSS_TOOLS_H_

#include <talloc.h>
#include <popt.h>

#include "confdb/confdb.h"

struct sss_tool_ctx {
    struct confdb_ctx *confdb;

    bool print_help;
    char *default_domain;
    struct sss_domain_info *domains;
};

struct sss_cmdline {
    const char *exec; /* argv[0] */
    const char *command; /* command name */
    int argc; /* rest of arguments */
    const char **argv;
};

typedef errno_t
(*sss_route_fn)(struct sss_cmdline *cmdline,
                struct sss_tool_ctx *tool_ctx);

#define SSS_TOOL_COMMAND_FLAGS(cmd, msg, fn, flags) \
    {cmd, _(msg), fn, flags}
#define SSS_TOOL_COMMAND(cmd, msg, fn) \
    {cmd, _(msg), fn, 0}
#define SSS_TOOL_COMMAND_NOMSG(cmd, fn) {cmd, NULL, fn, 0}
#define SSS_TOOL_DELIMITER(message) {"", _(message), NULL, 0}
#define SSS_TOOL_LAST {NULL, NULL, NULL, 0}

#define SSS_TOOL_FLAG_SKIP_CMD_INIT   0x01
#define SSS_TOOL_FLAG_SKIP_ROOT_CHECK 0x02

struct sss_route_cmd {
    const char *command;
    const char *description;
    sss_route_fn fn;
    int flags;
};

typedef errno_t (*sss_popt_fn)(poptContext pc, char option, void *pvt);

enum sss_tool_opt {
    SSS_TOOL_OPT_REQUIRED,
    SSS_TOOL_OPT_OPTIONAL
};

errno_t sss_tool_popt_ex(struct sss_cmdline *cmdline,
                         struct poptOption *options,
                         const char *extended_help,
                         enum sss_tool_opt require_option,
                         sss_popt_fn popt_fn,
                         void *popt_fn_pvt,
                         const char *fopt_name,
                         const char *fopt_help,
                         enum sss_tool_opt fopt_require,
                         const char **_fopt,
                         bool *_opt_set);

errno_t sss_tool_popt(struct sss_cmdline *cmdline,
                      struct poptOption *options,
                      enum sss_tool_opt require_option,
                      sss_popt_fn popt_fn,
                      void *popt_fn_pvt);

int sss_tool_main(int argc, const char **argv,
                  struct sss_route_cmd *commands);

errno_t sss_tool_parse_name(TALLOC_CTX *mem_ctx,
                            struct sss_tool_ctx *tool_ctx,
                            const char *input,
                            const char **_username,
                            struct sss_domain_info **_domain);


errno_t sss_tool_confdb_init(TALLOC_CTX *mem_ctx, struct confdb_ctx **_confdb);

#endif /* SRC_TOOLS_COMMON_SSS_TOOLS_H_ */

/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <popt.h>

#include "util/util.h"
#include "sss_client/autofs/sss_autofs_private.h"

struct automtent {
    const char *mapname;
    size_t cursor;
};

int main(int argc, const char *argv[])
{
    void *ctx;
    errno_t ret;
    const char *mapname;
    char *key = NULL;
    char *value = NULL;
    char *pc_key = NULL;
    int pc_setent = 0;
    int pc_protocol = 1;
    unsigned int protocol;
    unsigned int requested_protocol = 1;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "by-name",  'n', POPT_ARG_STRING, &pc_key, 0, "Request map by name", NULL },
        { "only-setent",  's', POPT_ARG_VAL, &pc_setent, 1, "Run only setent, do not enumerate", NULL },
        { "protocol",  'p', POPT_ARG_INT, &pc_protocol, 0, "Protocol version", NULL },
        POPT_TABLEEND
    };
    poptContext pc = NULL;

    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "MAPNAME");

    while (poptGetNextOpt(pc) > 0)
        ;

    mapname = poptGetArg(pc);
    if (mapname == NULL) {
        poptPrintUsage(pc, stderr, 0);
        fprintf(stderr, "Please specify the automounter map name\n");
        poptFreeContext(pc);
        exit(EXIT_FAILURE);
    }

    requested_protocol = pc_protocol;
    protocol = _sss_auto_protocol_version(requested_protocol);
    if (protocol != requested_protocol) {
        fprintf(stderr, "Unsupported protocol version: %u -> %u\n",
                requested_protocol, protocol);
        poptFreeContext(pc);
        exit(EXIT_FAILURE);
    }

    ret = _sss_setautomntent(mapname, &ctx);
    if (ret) {
        fprintf(stderr, "setautomntent failed [%d]: %s\n",
                ret, strerror(ret));
        poptFreeContext(pc);
        exit(EXIT_FAILURE);
    }
    printf("setautomntent done for %s\n", mapname);

    if (pc_setent) {
        goto end;
    }

    if (!pc_key) {
        do {
            ret = _sss_getautomntent_r(&key, &value, ctx);
            if (ret == 0) {
                if (!key || !value) {
                    fprintf(stderr,
                            "getautomntent returned success but no data?\n");
                    goto end;
                }

                printf("key: %s\t\tvalue: %s\n", key, value);
                free(key);
                key = NULL;
                free(value);
                value = NULL;
            }
        } while(ret == 0);

        if (ret != 0 && ret != ENOENT) {
            fprintf(stderr, "getautomntent_r failed [%d]: %s\n",
                    ret, strerror(ret));
            goto end;
        }
    } else {
        ret = _sss_getautomntbyname_r(pc_key, &value, ctx);
        if (ret == ENOENT) {
            fprintf(stderr, "no such entry in map\n");
        } else if (ret != 0) {
            fprintf(stderr, "getautomntbyname_r failed [%d]: %s\n",
                    ret, strerror(ret));
            goto end;
        } else {
            if (!value) {
                fprintf(stderr, "_sss_getautomntbyname_r "
                        "returned success but no data?\n");
                goto end;
            }

            printf("key: %s\t\tvalue: %s\n", pc_key, value);
            free(value);
        }
    }

end:
    ret = _sss_endautomntent(&ctx);
    if (ret) {
        fprintf(stderr, "endautomntent failed [%d]: %s\n",
                ret, strerror(ret));
        poptFreeContext(pc);
        exit(EXIT_FAILURE);
    }
    printf("endautomntent done for %s\n", mapname);
    poptFreeContext(pc);
    return 0;
}

/*
   SSSD

   nscd.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2010

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

#include "config.h"

#include <ctype.h>

#include "util/util.h"


/* NSCD config file parse and check */
static unsigned int sss_nscd_check_service(char* svc_name)
{
    struct sss_nscd_db {
        const char *svc_type_name;
        unsigned int nscd_service_flag;
    };

    int i;
    unsigned int ret = 0;
    struct sss_nscd_db db[] = {
        { "passwd",   0x0001 },
        { "group",    0x0010 },
        { "netgroup", 0x0100 },
        { "services", 0x1000 },
        { NULL,       0   }
    };

    if (svc_name == NULL) {
        return ret;
    }

    for (i = 0; db[i].svc_type_name != NULL; i++) {
        if (!strcmp(db[i].svc_type_name, svc_name)) {

            ret = db[i].nscd_service_flag;
            break;
        }
    }

    return ret;
}

errno_t sss_nscd_parse_conf(const char *conf_path)
{
    FILE *fp;
    int ret = EOK;
    unsigned int occurred = 0;
    char *line, *entry, *service, *enabled, *pad;
    size_t linelen = 0;

    fp = fopen(conf_path, "r");
    if (fp == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Couldn't open NSCD configuration "
                    "file [%s]\n", conf_path);
        return ENOENT;
    }

    while (getline(&line, &linelen, fp) != -1) {

        pad = strchr(line, '#');
        if (pad != NULL) {
            *pad = '\0';
        }

        if (line[0] == '\n' || line[0] == '\0') continue;

        entry = line;
        while (isspace(*entry) && *entry != '\0') {
            entry++;
        }

        pad = entry;
        while (!isspace(*pad) && *pad != '\0') {
            pad++;
        }

        service = pad;
        while (isspace(*service) && *service != '\0') {
            service++;
        }

        *pad = '\0';
        pad = service;
        while (!isspace(*pad) && *pad != '\0') {
            pad++;
        }

        enabled = pad;
        while (isspace(*enabled) && *enabled != '\0') {
            enabled++;
        }

        *pad = '\0';
        pad = enabled;
        while (!isspace(*pad) && *pad != '\0') {
            pad++;
        }
        *pad = '\0';

        if (!strcmp(entry, "enable-cache") &&
            !strcmp(enabled, "yes")) {

            occurred |= sss_nscd_check_service(service);
        }
    };

    ret = ferror(fp);
    if (ret) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Reading NSCD configuration file [%s] "
              "ended with failure [%d]: %s.\n",
              conf_path, ret, strerror(ret));
        ret = ENOENT;
        goto done;
    }

    ret = EOK;
    if (occurred != 0) {
        ret = EEXIST;
        goto done;
    }

done:
    free(line);
    fclose(fp);

    return ret;
}

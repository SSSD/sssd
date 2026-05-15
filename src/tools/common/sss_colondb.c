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

#include <stdlib.h>

#include "util/util.h"
#include "util/strtonum.h"
#include "tools/common/sss_colondb.h"

#define IS_STD_FILE(db) ((db)->file == stdin || (db)->file == stdout)

static char *read_field_as_string(char *line,
                                  const char **_value)
{
    char *rest;
    char *value;

    if (line == NULL || *line == '\n' || *line == '\0') {
        /* There is nothing else to read. */
        rest = NULL;
        value = NULL;
        goto done;
    }

    if (*line == ':') {
        /* Special case for empty value. */
        *line = '\0';
        rest = line + 1;
        value = NULL;
        goto done;
    }

    /* Value starts at current position. */
    value = line;

    /* Find next field delimiter. */
    rest = strchr(line, ':');
    if (rest == NULL) {
        /* There is no more field. Remove \n from the end. */
        rest = strchr(line, '\n');
        if (rest != NULL) {
            *rest = '\0';
            rest = NULL;
        }
        goto done;
    }

    /* Remove it and step one character further. */
    *rest = '\0';
    rest++;

done:
    *_value = value;

    return rest;
}

static char *read_field_as_uint32(char *line,
                                  uint32_t *_value)
{
    const char *str;
    char *rest;
    errno_t ret;
    char *endptr;

    rest = read_field_as_string(line, &str);
    if (str == NULL) {
        *_value = 0;
        return rest;
    }

    *_value = strtouint32(str, &endptr, 10);
    if ((errno != 0) || *endptr || (str == endptr)) {
        ret = errno ? errno : EINVAL;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse number [%d]: %s\n",
              ret, sss_strerror(ret));

        *_value = 0;
    }

    return rest;
}

struct sss_colondb {
    FILE *file;
    enum sss_colondb_mode mode;
};

errno_t sss_colondb_readline(TALLOC_CTX *mem_ctx,
                             struct sss_colondb *db,
                             struct sss_colondb_read_field *table)
{
    int readchars;
    size_t linelen = 0;
    char *line = NULL;
    char *tcline;
    char *rest;
    errno_t ret;
    int i;

    if (db->mode != SSS_COLONDB_READ) {
        return ERR_INTERNAL;
    }

    readchars = getline(&line, &linelen, db->file);
    if (readchars == -1) {
        /* Nothing was read. */

        free(line);
        line = NULL;

        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to read line [%d]: %s\n",
                  ret, sss_strerror(ret));
            return ret;
        }

        return EOF;
    }

    /* Copy line to mem_ctx. */
    tcline = talloc_strdup(mem_ctx, line);

    free(line);
    line = NULL;

    if (tcline == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
        return ENOMEM;
    }

    rest = tcline;
    for (i = 0; table[i].type != SSS_COLONDB_SENTINEL; i++) {
        switch (table[i].type) {
        case SSS_COLONDB_UINT32:
            rest = read_field_as_uint32(rest, table[i].data.uint32);
            break;
        case SSS_COLONDB_STRING:
            rest = read_field_as_string(rest, table[i].data.str);
            break;
        case SSS_COLONDB_SENTINEL:
            DEBUG(SSSDBG_CRIT_FAILURE, "Trying to process sentinel?!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        if (rest == NULL && table[i + 1].type != SSS_COLONDB_SENTINEL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Line contains less values than expected!\n");
            ret = EINVAL;
            goto done;
        } else if (rest != NULL && table[i + 1].type == SSS_COLONDB_SENTINEL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Line contains more values than expected!\n");
            ret = EINVAL;
            goto done;
        }
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(tcline);
    }

    return ret;
}

errno_t sss_colondb_writeline(struct sss_colondb *db,
                              struct sss_colondb_write_field *table)
{
    TALLOC_CTX *tmp_ctx;
    char *line = NULL;
    errno_t ret;
    int i;

    if (db->mode != SSS_COLONDB_WRITE) {
        return ERR_INTERNAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        return ENOMEM;
    }

    line = talloc_strdup(tmp_ctx, "");
    if (line == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; table[i].type != SSS_COLONDB_SENTINEL; i++) {
        switch (table[i].type) {
        case SSS_COLONDB_UINT32:
            if (table[i].data.uint32 == 0) {
                line = talloc_asprintf_append(line, ":");
            } else {
                line = talloc_asprintf_append(line, ":%u", table[i].data.uint32);
            }
            break;
        case SSS_COLONDB_STRING:
            if (table[i].data.str == NULL) {
                line = talloc_asprintf_append(line, ":");
            } else {
                line = talloc_asprintf_append(line, ":%s", table[i].data.str);
            }
            break;
        case SSS_COLONDB_SENTINEL:
            DEBUG(SSSDBG_CRIT_FAILURE, "Trying to process sentinel?!\n");
            ret = ERR_INTERNAL;
            goto done;
        }

        if (line == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    /* Remove starting : */
    line++;

    fprintf(db->file, "%s\n", line);
    fflush(db->file);

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static int sss_colondb_close(void *pvt)
{
    struct sss_colondb *db = talloc_get_type(pvt, struct sss_colondb);

    if (db->file == NULL || IS_STD_FILE(db)) {
        return 0;
    }

    fclose(db->file);
    db->file = NULL;

    return 0;
}

static FILE *open_db(const char *filename, enum sss_colondb_mode mode)
{
    FILE *fp = NULL;
    errno_t ret;

    errno = 0;

    switch (mode) {
    case SSS_COLONDB_READ:
        fp = filename == NULL ? stdin : fopen(filename, "r");
        break;
    case SSS_COLONDB_WRITE:
        fp = filename == NULL ? stdout : fopen(filename, "w");
        break;
    }

    if (fp == NULL && filename != NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to open file %s [%d]: %s\n",
              filename, ret, sss_strerror(ret));
    }

    return fp;
}

struct sss_colondb *sss_colondb_open(TALLOC_CTX *mem_ctx,
                                     enum sss_colondb_mode mode,
                                     const char *filename)
{
    struct sss_colondb *db;

    db = talloc_zero(mem_ctx, struct sss_colondb);
    if (db == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return NULL;
    }

    db->file = open_db(filename, mode);
    db->mode = mode;

    if (db->file == NULL) {
        talloc_free(db);
        return NULL;
    }

    talloc_set_destructor((TALLOC_CTX *)db, sss_colondb_close);

    return db;
}

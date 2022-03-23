/*
    SSSD

    AD GPO Backend Module -- helpers for a child process

    Copyright (C) 2022 Red Hat

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
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ini_configobj.h>
#include <talloc.h>

#include "util/util_errors.h"
#include "util/debug.h"
#include "util/atomic_io.h"

#define INI_GENERAL_SECTION "General"
#define GPT_INI_VERSION "Version"

static errno_t parse_ini_file_with_libini(struct ini_cfgobj *ini_config,
                                          int *_gpt_version)
{
    int ret;
    struct value_obj *vobj = NULL;
    int gpt_version;

    ret = ini_get_config_valueobj(INI_GENERAL_SECTION, GPT_INI_VERSION,
                                  ini_config, INI_GET_FIRST_VALUE, &vobj);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_config_valueobj failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }
    if (vobj == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "section/name not found: [%s][%s]\n",
              INI_GENERAL_SECTION, GPT_INI_VERSION);
        ret = EINVAL;
        goto done;
    }

    gpt_version = ini_get_int32_config_value(vobj, 0, -1, &ret);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_int32_config_value failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    *_gpt_version = gpt_version;

    ret = EOK;

 done:

    return ret;
}

static errno_t gpo_sanitize_buffer_content(uint8_t *buf, int buflen)
{
    int i;
    int line_start = 0;
    int equal_pos = 0;

    if (!buf) {
        return EINVAL;
    }

    for (i = 0; i < buflen; ++i) {
        if (buf[i] == '\n') {
            line_start = i + 1;
            continue;
        }
        if (buf[i] == '=') {
            equal_pos = i;
            continue;
        }
        if (isascii(buf[i])) {
            continue;
        }

        /* non-ascii */
        if (equal_pos <= line_start) { /* key */
            DEBUG(SSSDBG_OP_FAILURE,
                  "Key or section starting at position %d ('%.*s...') contains"
                  " non-ascii symbol. File is unusable!\n",
                  line_start, i - line_start, buf + line_start);
            return EINVAL;
        }

        buf[i] = '?';
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "Value for key '%.*s' contains non-ascii symbol."
              " Replacing with '?'\n",
              equal_pos - line_start, buf + line_start);
    }

    return EOK;
}

/*
 * This function parses the GPT_INI file stored in the gpo_cache, and uses the
 * results to populate the output parameters ...
 */
errno_t ad_gpo_parse_ini_file(const char *ini_filename, int *_gpt_version)
{
    struct ini_cfgfile *file_ctx = NULL;
    struct ini_cfgobj *ini_config = NULL;
    int ret;
    int gpt_version = -1;
    TALLOC_CTX *tmp_ctx = NULL;
    struct stat st;
    int fd = -1;
    uint8_t *buf = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "ini_filename:%s\n", ini_filename);

    ret = ini_config_create(&ini_config);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_create failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    fd = open(ini_filename, O_RDONLY);
    if (fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "open() failed [%d][%s]\n", ret, strerror(ret));
        ret = EIO;
        goto done;
    }
    ret = fstat(fd, &st);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "stat() failed [%d][%s]\n", ret, strerror(ret));
        ret = EIO;
        goto done;
    }
    buf = talloc_size(tmp_ctx, st.st_size);
    if (buf == NULL) {
        ret = ENOMEM;
        goto done;
    }
    if (sss_atomic_read_s(fd, buf, st.st_size) != st.st_size) {
        ret = EIO;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_atomic_read_s() failed\n");
        goto done;
    }

    /* Windows uses ANSI (extended-ASCII) to encode the GPT.INI file.
     * Practically this might mean any code page, including uncompatible
     * with UTF. Since the only value read by SSSD from GPT.INI is
     * 'Version=...', just get rid of any non-ascii characters to make
     * content compatible with lib_iniconfig.
     */
    ret = gpo_sanitize_buffer_content(buf, st.st_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "gpo_sanitize_buffer_content() failed\n");
        goto done;
    }

    ret = ini_config_file_from_mem(buf, st.st_size, &file_ctx);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_file_from_mem() failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_config_parse(file_ctx, INI_STOP_ON_NONE, 0, 0, ini_config);
    if (ret != 0) {
        int lret;
        char **errors;

        DEBUG(SSSDBG_CRIT_FAILURE,
              "[%s]: ini_config_parse failed [%d][%s]\n",
              ini_filename, ret, strerror(ret));

        /* Now get specific errors if there are any */
        lret = ini_config_get_errors(ini_config, &errors);
        if (lret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to get specific parse error [%d][%s]\n", lret,
                  strerror(lret));
            goto done;
        }

        for (int i = 0; errors[i]; i++) {
             DEBUG(SSSDBG_CRIT_FAILURE, "%s\n", errors[i]);
        }
        ini_config_free_errors(errors);

        goto done;
    }

    ret = parse_ini_file_with_libini(ini_config, &gpt_version);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "parse_ini_file_with_libini failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    *_gpt_version = gpt_version;

 done:

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }

    ini_config_file_destroy(file_ctx);
    ini_config_destroy(ini_config);
    if (fd != -1) close(fd);
    talloc_free(tmp_ctx);
    return ret;
}

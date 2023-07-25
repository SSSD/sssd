/*
    SSSD

    Create uid table

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <talloc.h>
#include <ctype.h>
#include <sys/time.h>
#include <dhash.h>

#include "util/find_uid.h"
#include "util/util.h"
#include "util/strtonum.h"

#ifdef HAVE_SYSTEMD_LOGIN
#include <systemd/sd-login.h>
#endif

#define PATHLEN (NAME_MAX + 14)
#define BUFSIZE 4096

static void *hash_talloc(const size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void hash_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

static errno_t get_uid_from_pid(const pid_t pid, uid_t *uid, bool *is_systemd)
{
    int ret;
    char path[PATHLEN];
    struct stat stat_buf;
    int fd;
    char buf[BUFSIZE];
    char *p;
    char *e;
    char *endptr;
    uint32_t num=0;
    errno_t error;

    ret = snprintf(path, PATHLEN, "/proc/%d/status", pid);
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "snprintf failed\n");
        return EINVAL;
    } else if (ret >= PATHLEN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "path too long?!?!\n");
        return EINVAL;
    }

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        error = errno;
        if (error == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Proc file [%s] is not available anymore.\n",
                      path);
        } else if (error == EPERM) {
            /* case of hidepid=1 mount option for /proc */
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Proc file [%s] is not permissible.\n",
                      path);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "open failed [%s][%d][%s].\n", path, error, strerror(error));
        }
        return error;
    }

    ret = fstat(fd, &stat_buf);
    if (ret == -1) {
        error = errno;
        if (error == ENOENT) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Proc file [%s] is not available anymore.\n",
                      path);
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "fstat failed [%d][%s].\n", error, strerror(error));
        }
        goto fail_fd;
    }

    if (!S_ISREG(stat_buf.st_mode)) {
        DEBUG(SSSDBG_CRIT_FAILURE, "not a regular file\n");
        error = EINVAL;
        goto fail_fd;
    }

    errno = 0;
    ret = sss_atomic_read_s(fd, buf, BUFSIZE);
    if (ret == -1) {
        error = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", error, strerror(error));
        goto fail_fd;
    }

    /* Guarantee NULL-termination in case we read the full BUFSIZE somehow */
    buf[BUFSIZE-1] = '\0';

    ret = close(fd);
    if (ret == -1) {
        error = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "close failed [%d][%s].\n", error, strerror(error));
    }

    /* Get uid */
    p = strstr(buf, "\nUid:\t");
    if (p != NULL) {
        p += 6;
        e = strchr(p,'\t');
        if (e == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "missing delimiter.\n");
            return EINVAL;
        } else {
            *e = '\0';
        }
        num = (uint32_t) strtoint32(p, &endptr, 10);
        error = errno;
        if (error != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "strtol failed [%s].\n", strerror(error));
            return error;
        }
        if (*endptr != '\0') {
            DEBUG(SSSDBG_CRIT_FAILURE, "uid contains extra characters\n");
            return EINVAL;
        }

    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "format error\n");
        return EINVAL;
    }

    /* Get process name. */
    p = strstr(buf, "Name:\t");
    if (p == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "format error\n");
        return EINVAL;
    }
    p += 6;
    e = strchr(p,'\n');
    if (e == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "format error\n");
        return EINVAL;
    }
    if (strncmp(p, "systemd", e-p) == 0 || strncmp(p, "(sd-pam)", e-p) == 0) {
        *is_systemd = true;
    } else {
        *is_systemd = false;
    }

    *uid = num;

    return EOK;

fail_fd:
    close(fd);
    return error;
}

static errno_t name_to_pid(const char *name, pid_t *pid)
{
    long num;
    char *endptr;
    errno_t error;

    errno = 0;
    num = strtol(name, &endptr, 10);
    error = errno;
    if (error == ERANGE) {
        perror("strtol");
        return error;
    }

    if (*endptr != '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "pid string contains extra characters.\n");
        return EINVAL;
    }

    if (num <= 0 || num >= INT_MAX) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pid out of range.\n");
        return ERANGE;
    }

    *pid = num;

    return EOK;
}

static int only_numbers(char *p)
{
    while(*p!='\0' && isdigit(*p)) ++p;
    return *p;
}

static errno_t get_active_uid_linux(hash_table_t *table, uid_t search_uid)
{
    DIR *proc_dir = NULL;
    struct dirent *dirent;
    int ret, err;
    pid_t pid = -1;
    bool is_systemd;
    uid_t uid;

    hash_key_t key;
    hash_value_t value;

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot open proc dir.\n");
        goto done;
    };

    errno = 0;
    while ((dirent = readdir(proc_dir)) != NULL) {
        if (only_numbers(dirent->d_name) != 0) {
            continue;
        }
        ret = name_to_pid(dirent->d_name, &pid);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "name_to_pid failed.\n");
            goto done;
        }

        ret = get_uid_from_pid(pid, &uid, &is_systemd);
        if (ret != EOK) {
            /* Most probably this /proc entry disappeared.
               Anyway, just skip it.
            */
            DEBUG(SSSDBG_TRACE_ALL, "get_uid_from_pid() failed.\n");
            errno = 0;
            continue;
        }

        if (is_systemd) {
            /* Systemd process may linger for a while even when user.
             * is logged out. Lets ignore it and focus only
             * on non-systemd processes. */
            continue;
        }

        if (table != NULL) {
            key.type = HASH_KEY_ULONG;
            key.ul = (unsigned long) uid;
            value.type = HASH_VALUE_ULONG;
            value.ul = (unsigned long) uid;

            ret = hash_enter(table, &key, &value);
            if (ret != HASH_SUCCESS) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "cannot add to table [%s]\n", hash_error_string(ret));
                ret = ENOMEM;
                goto done;
            }
        } else {
            if (uid == search_uid) {
                ret = EOK;
                goto done;
            }
        }

        errno = 0;
    }
    if (errno != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "readdir failed.\n");
        goto done;
    }

    ret = closedir(proc_dir);
    proc_dir = NULL;
    if (ret == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "closedir failed, watch out.\n");
    }

    if (table != NULL) {
        ret = EOK;
    } else {
        ret = ENOENT;
    }

done:
    if (proc_dir != NULL) {
        err = closedir(proc_dir);
        if (err) {
            DEBUG(SSSDBG_CRIT_FAILURE, "closedir failed, bad dirp?\n");
        }
    }
    return ret;
}

errno_t get_uid_table(TALLOC_CTX *mem_ctx, hash_table_t **table)
{
#ifdef __linux__
    int ret;

    ret = hash_create_ex(0, table, 0, 0, 0, 0,
                         hash_talloc, hash_talloc_free, mem_ctx,
                         NULL, NULL);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "hash_create_ex failed [%s]\n", hash_error_string(ret));
        return ENOMEM;
    }

    return get_active_uid_linux(*table, 0);
#else
    return ENOSYS;
#endif
}

errno_t check_if_uid_is_active(uid_t uid, bool *result)
{
    int ret;

#ifdef HAVE_SYSTEMD_LOGIN
    ret = sd_uid_get_sessions(uid, 0, NULL);
    if (ret > 0) {
        *result = true;
        return EOK;
    }
    if (ret == 0) {
        *result = false;
    }
    if (ret < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "systemd-login gave error %d: %s\n",
                                    -ret, strerror(-ret));
    }
    /* fall back to the old method */
#endif

    ret = get_active_uid_linux(NULL, uid);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "get_active_uid_linux() failed.\n");
        return ret;
    }

    if (ret == EOK) {
        *result = true;
    } else {
        *result = false;
    }

    return EOK;
}

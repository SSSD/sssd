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

#include "dhash.h"
#include "util/util.h"

#define INITIAL_TABLE_SIZE 64
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

static errno_t get_uid_from_pid(const pid_t pid, uid_t *uid)
{
    int ret;
    char path[PATHLEN];
    struct stat stat_buf;
    int fd;
    char buf[BUFSIZE];
    char *p;
    char *e;
    char *endptr;
    long num=0;
    errno_t error;

    ret = snprintf(path, PATHLEN, "/proc/%d/status", pid);
    if (ret < 0) {
        DEBUG(1, ("snprintf failed"));
        return EINVAL;
    } else if (ret >= PATHLEN) {
        DEBUG(1, ("path too long?!?!\n"));
        return EINVAL;
    }

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        error = errno;
        if (error == ENOENT) {
            DEBUG(7, ("Proc file [%s] is not available anymore, continuing.\n",
                      path));
            return EOK;
        }
        DEBUG(1, ("open failed [%d][%s].\n", error, strerror(error)));
        return error;
    }

    ret = fstat(fd, &stat_buf);
    if (ret == -1) {
        error = errno;
        if (error == ENOENT) {
            DEBUG(7, ("Proc file [%s] is not available anymore, continuing.\n",
                      path));
            return EOK;
        }
        DEBUG(1, ("fstat failed [%d][%s].\n", error, strerror(error)));
        return error;
    }

    if (!S_ISREG(stat_buf.st_mode)) {
        DEBUG(1, ("not a regular file\n"));
        return EINVAL;
    }

    while ((ret = read(fd, buf, BUFSIZE)) != 0) {
        if (ret == -1) {
            error = errno;
            if (error == EINTR || error == EAGAIN) {
                continue;
            }
            DEBUG(1, ("read failed [%d][%s].\n", error, strerror(error)));
            return error;
        }
    }

    ret = close(fd);
    if (ret == -1) {
        error = errno;
        DEBUG(1, ("close failed [%d][%s].\n", error, strerror(error)));
    }

    p = strstr(buf, "\nUid:\t");
    if (p != NULL) {
        p += 6;
        e = strchr(p,'\t');
        if (e == NULL) {
            DEBUG(1, ("missing delimiter.\n"));
            return EINVAL;
        } else {
            *e = '\0';
        }
        errno = 0;
        num = strtol(p, &endptr, 10);
        error = errno;
        if (error == ERANGE) {
            DEBUG(1, ("strtol failed [%s].\n", strerror(error)));
            return error;
        }
        if (*endptr != '\0') {
            DEBUG(1, ("uid contains extra characters\n"));
            return EINVAL;
        }

        if (num < 0 || num >= INT_MAX) {
            DEBUG(1, ("uid out of range.\n"));
            return ERANGE;
        }

    } else {
        DEBUG(1, ("format error\n"));
        return EINVAL;
    }

    *uid = num;

    return EOK;
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
        DEBUG(1, ("pid string contains extra characters.\n"));
        return EINVAL;
    }

    if (num <= 0 || num >= INT_MAX) {
        DEBUG(1, ("pid out of range.\n"));
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
    uid_t uid;

    hash_key_t key;
    hash_value_t value;

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        ret = errno;
        DEBUG(1, ("Cannot open proc dir.\n"));
        goto done;
    };

    errno = 0;
    while ((dirent = readdir(proc_dir)) != NULL) {
        if (only_numbers(dirent->d_name) != 0) continue;
        ret = name_to_pid(dirent->d_name, &pid);
        if (ret != EOK) {
            DEBUG(1, ("name_to_pid failed.\n"));
            goto done;
        }

        ret = get_uid_from_pid(pid, &uid);
        if (ret != EOK) {
            DEBUG(1, ("get_uid_from_pid failed.\n"));
            goto done;
        }

        if (table != NULL) {
            key.type = HASH_KEY_ULONG;
            key.ul = (unsigned long) uid;
            value.type = HASH_VALUE_ULONG;
            value.ul = (unsigned long) uid;

            ret = hash_enter(table, &key, &value);
            if (ret != HASH_SUCCESS) {
                DEBUG(1, ("cannot add to table [%s]\n", hash_error_string(ret)));
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
    if (errno != 0 && dirent == NULL) {
        ret = errno;
        DEBUG(1, ("readdir failed.\n"));
        goto done;
    }

    ret = closedir(proc_dir);
    proc_dir = NULL;
    if (ret == -1) {
        DEBUG(1, ("closedir failed, watch out.\n"));
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
            DEBUG(1, ("closedir failed, bad dirp?\n"));
        }
    }
    return ret;
}

errno_t get_uid_table(TALLOC_CTX *mem_ctx, hash_table_t **table)
{
#ifdef __linux__
    int ret;

    ret = hash_create_ex(INITIAL_TABLE_SIZE, table, 0, 0, 0, 0,
                         hash_talloc, hash_talloc_free, mem_ctx,
                         NULL, NULL);
    if (ret != HASH_SUCCESS) {
        DEBUG(1, ("hash_create_ex failed [%s]\n", hash_error_string(ret)));
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

    ret = get_active_uid_linux(NULL, uid);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(1, ("get_uid_table failed.\n"));
        return ret;
    }

    if (ret == EOK) {
        *result = true;
    } else {
        *result = false;
    }

    return EOK;
}

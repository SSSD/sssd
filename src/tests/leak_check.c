/*
   SSSD

   Common utilities for check-based tests using talloc.

   Authors:
        Martin Nagy <mnagy@redhat.com>

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

#include <stdio.h>
#include "tests/common.h"
#include "util/util.h"
#include "util/dlinklist.h"

TALLOC_CTX *global_talloc_context = NULL;
char leak_err_msg[256];

struct size_snapshot {
    struct size_snapshot *prev;
    struct size_snapshot *next;

    TALLOC_CTX *ctx;
    size_t bytes_allocated;
};

static struct size_snapshot *snapshot_stack;

#define _set_leak_err_msg(fmt, ...) do {              \
        snprintf(leak_err_msg, sizeof(leak_err_msg),  \
                 fmt, ##__VA_ARGS__);                 \
} while(0);

const char *check_leaks_err_msg(void)
{
    return leak_err_msg;
}

static bool
check_leaks(TALLOC_CTX *ctx, size_t bytes, const char *location)
{
    size_t bytes_allocated;

    if (ctx == NULL) {
        return false;
    }

    bytes_allocated = talloc_total_size(ctx);
    if (bytes_allocated != bytes) {
        fprintf(stderr, "Leak report for %s:\n", location);
        talloc_report_full(ctx, stderr);
        _set_leak_err_msg("%s: memory leaks detected, %zd bytes still allocated",
                          location, bytes_allocated - bytes);
        return false;
    }

    return true;
}

void
check_leaks_push(TALLOC_CTX *ctx)
{
    struct size_snapshot *snapshot;

    snapshot = talloc(NULL, struct size_snapshot);
    snapshot->ctx = ctx;
    snapshot->bytes_allocated = talloc_total_size(ctx);
    DLIST_ADD(snapshot_stack, snapshot);
}

bool
_check_leaks_pop(TALLOC_CTX *ctx, const char *location)
{
    struct size_snapshot *snapshot;
    TALLOC_CTX *old_ctx;
    size_t bytes_allocated;

    if (ctx == NULL) {
        return false;
    }

    if (snapshot_stack == NULL) {
        _set_leak_err_msg("%s: trying to pop an empty stack", location);
        return false;
    }

    snapshot = snapshot_stack;
    DLIST_REMOVE(snapshot_stack, snapshot);

    old_ctx = snapshot->ctx;
    bytes_allocated = snapshot->bytes_allocated;

    if (old_ctx != ctx) {
        _set_leak_err_msg("Bad push/pop order");
        return false;
    }

    talloc_zfree(snapshot);
    return check_leaks(old_ctx, bytes_allocated, location);
}

bool
leak_check_setup(void)
{
    talloc_enable_null_tracking();
    global_talloc_context = talloc_new(NULL);
    if (global_talloc_context == NULL) {
        _set_leak_err_msg("talloc_new failed");
        return false;
    }

    check_leaks_push(global_talloc_context);
    return true;
}

bool
leak_check_teardown(void)
{
    bool res;
    res = check_leaks_pop(global_talloc_context);
    if (!res) {
        _set_leak_err_msg("check_leaks_pop failed in leak_check_teardown");
    }

    if (snapshot_stack != NULL) {
        _set_leak_err_msg("Exiting with a non-empty stack");
        return false;
    }
    res = check_leaks(global_talloc_context, 0, __location__);
    talloc_disable_null_tracking();
    talloc_free(global_talloc_context);
    return res;
}

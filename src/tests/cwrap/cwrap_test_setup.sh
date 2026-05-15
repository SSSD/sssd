#!/bin/bash

pkg-config --exists nss_wrapper || exit 1
pkg-config --exists uid_wrapper || exit 1

nss_wrapper=$(pkg-config --libs nss_wrapper)
uid_wrapper=$(pkg-config --libs uid_wrapper)
if [ -z $nss_wrapper -o -z $uid_wrapper ]; then
    echo "Cannot locate cwrap libraries"
    exit 2
fi

export LD_PRELOAD="$nss_wrapper $uid_wrapper"
export NSS_WRAPPER_PASSWD=$CWRAP_TEST_SRCDIR/passwd
export NSS_WRAPPER_GROUP=$CWRAP_TEST_SRCDIR/group
export UID_WRAPPER=1
export UID_WRAPPER_ROOT=1

export LDB_MODULES_PATH=$ABS_TOP_BUILDDIR/ldb_mod_test_dir

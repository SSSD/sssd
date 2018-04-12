#!/bin/bash

#Exit on failures
set -e

pushd /builddir/

# We have to define the _Float* types as those are not defined by coverity and as result
# the codes linking agains those (pretty much anything linking against stdlib.h and math.h)
# won't be covered.
echo "#define _Float128 long double" > /tmp/coverity.h
echo "#define _Float64x long double" >> /tmp/coverity.h
echo "#define _Float64 double" >> /tmp/coverity.h
echo "#define _Float32x double" >> /tmp/coverity.h
echo "#define _Float32 float" >> /tmp/coverity.h

# The coverity scan script returns an error despite succeeding...
 CFLAGS="${CFLAGS:- -include /tmp/coverity.h}" \
 TRAVIS_BRANCH="${TRAVIS_BRANCH:-master}" \
 COVERITY_SCAN_PROJECT_NAME="${COVERITY_SCAN_PROJECT_NAME:-SSSD/sssd}" \
 COVERITY_SCAN_NOTIFICATION_EMAIL="${COVERITY_SCAN_NOTIFICATION_EMAIL:-sssd-maint@redhat.com}" \
 COVERITY_SCAN_BUILD_COMMAND_PREPEND="${COVERITY_SCAN_BUILD_COMMAND_PREPEND:-source contrib/fedora/bashrc_sssd && reconfig}" \
 COVERITY_SCAN_BUILD_COMMAND="${COVERITY_SCAN_BUILD_COMMAND:-make all check TESTS= }" \
 COVERITY_SCAN_BRANCH_PATTERN=${COVERITY_SCAN_BRANCH_PATTERN:-master} \
 /usr/bin/travisci_build_coverity_scan.sh ||:

popd #builddir

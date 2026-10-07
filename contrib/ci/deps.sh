#
# Dependency management.
#
# Copyright (C) 2014 Red Hat
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

if [ -z ${_DEPS_SH+set} ]; then
declare -r _DEPS_SH=

. distro.sh

# Dependency list
declare -a DEPS_LIST=(
    valgrind
)

if [[ "$DISTRO_BRANCH" == -redhat-* ]]; then
    declare _DEPS_LIST_SPEC
    DEPS_LIST+=(
        libfaketime
        libcmocka-devel
        nss_wrapper
        rpm-build
        uid_wrapper
        curl-devel
        libunistring-devel
        libcap-devel
        systemtap-sdt-dtrace
        python3-requests
        libfido2-devel
    )

    _DEPS_LIST_SPEC=`
        sed -e 's/@PACKAGE_VERSION@/0/g' \
            -e 's/@PACKAGE_NAME@/package-name/g' \
            -e 's/@PRERELEASE_VERSION@//g' contrib/sssd.spec.in |
            rpm-spec-builddeps /dev/stdin`
    readarray -t -O "${#DEPS_LIST[@]}" DEPS_LIST <<<"$_DEPS_LIST_SPEC"
fi

declare -a -r DEPS_LIST

# Install dependencies.
function deps_install()
{
    distro_pkg_install "${DEPS_LIST[@]}"
}

fi # _DEPS_SH

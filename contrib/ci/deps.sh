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
    lcov
    valgrind
)

# "Integration tests dependencies satisfied" flag
declare DEPS_INTGCHECK_SATISFIED=true

if [[ "$DISTRO_BRANCH" == -redhat-* ]]; then
    declare _DEPS_LIST_SPEC
    DEPS_LIST+=(
        clang-analyzer
        fakeroot
        libcmocka-devel
        mock
        nss_wrapper
        openldap-clients
        openldap-servers
        pytest
        python-ldap
        pyldb
        rpm-build
        uid_wrapper
        python-requests
        curl-devel
        krb5-server
        krb5-workstation
    )
    _DEPS_LIST_SPEC=`
        sed -e 's/@PACKAGE_VERSION@/0/g' \
            -e 's/@PACKAGE_NAME@/package-name/g' \
            -e 's/@PRERELEASE_VERSION@//g' contrib/sssd.spec.in |
            rpm-spec-builddeps /dev/stdin`
    readarray -t -O "${#DEPS_LIST[@]}" DEPS_LIST <<<"$_DEPS_LIST_SPEC"
fi

if [[ "$DISTRO_BRANCH" == -debian-* ]]; then
    DEPS_LIST+=(
        autoconf
        automake
        autopoint
        check
        cifs-utils
        clang
        dh-apparmor
        dnsutils
        docbook-xml
        docbook-xsl
        gettext
        krb5-config
        libc-ares-dev
        libcmocka-dev
        libcollection-dev
        libdbus-1-dev
        libdhash-dev
        libglib2.0-dev
        libini-config-dev
        libkeyutils-dev
        libkrb5-dev
        libldap2-dev
        libldb-dev
        libltdl-dev
        libnfsidmap-dev
        libnl-3-dev
        libnl-route-3-dev
        libnspr4-dev
        libnss3-dev
        libpam0g-dev
        libpcre3-dev
        libpopt-dev
        libsasl2-dev
        libselinux1-dev
        libsemanage1-dev
        libsmbclient-dev
        libsystemd-dev
        libtalloc-dev
        libtdb-dev
        libtevent-dev
        libtool
        libtool-bin
        libxml2-utils
        make
        python-dev
        python3-dev
        samba-dev
        systemd
        xml-core
        xsltproc
        libssl-dev
        fakeroot
        libnss-wrapper
        libuid-wrapper
        python-pytest
        python-ldap
        python-ldb
        python-requests
        ldap-utils
        slapd
        systemtap-sdt-dev
        libhttp-parser-dev
        libjansson-dev
        libcurl4-openssl-dev
        krb5-kdc
        krb5-admin-server
        krb5-user
        uuid-dev
    )
    DEPS_INTGCHECK_SATISFIED=true
fi

declare -a -r DEPS_LIST

# Install dependencies.
function deps_install()
{
    distro_pkg_install "${DEPS_LIST[@]}"
}

# Remove dependencies.
function deps_remove()
{
    distro_pkg_remove "${DEPS_LIST[@]}"
}

fi # _DEPS_SH

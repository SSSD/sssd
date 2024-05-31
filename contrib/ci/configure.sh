#
# Configure argument management.
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

if [ -z ${_CONFIGURE_SH+set} ]; then
declare -r _CONFIGURE_SH=

. distro.sh

# List of "configure" arguments.
declare -a CONFIGURE_ARG_LIST=(
    "--disable-dependency-tracking"
    "--disable-rpath"
    "--disable-static"
    "--enable-ldb-version-check"
    "--with-initscript=sysv"
    "--with-syslog=syslog"
    "--enable-systemtap"
)


CONFIGURE_ARG_LIST+=(
    "--without-python2-bindings"
)


# Different versions of Debian might need different versions here but this is
# sufficient to make the CI work
if [[ "$DISTRO_BRANCH" == -debian-* ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-smb-idmap-interface-version=5"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-centos-9*- ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-9.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-libsifp"
        "--with-conf-service-user-support"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-fedora-* ||
      "$DISTRO_BRANCH" == -redhat-centos-9*- ||
      "$DISTRO_BRANCH" == -redhat-centos-10*- ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-9.*- ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-10.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-subid"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-fedora-* ||
      "$DISTRO_BRANCH" == -redhat-centos-9*- ||
      "$DISTRO_BRANCH" == -redhat-centos-10*- ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-9.*- ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-10.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-passkey"
    )
fi

declare -r -a CONFIGURE_ARG_LIST

fi # _CONFIGURE_SH

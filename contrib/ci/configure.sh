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
    "--with-syslog=journald"
    "--enable-systemtap"
    "--with-python2-bindings"
)


if [[ "$DISTRO_BRANCH" == -redhat-redhatenterprise*-6.*- ||
      "$DISTRO_BRANCH" == -redhat-centos-6.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-smb-idmap-interface-version=5"
        "--disable-cifs-idmap-plugin"
        "--with-syslog=syslog"
        "--without-python3-bindings"
        "--without-kcm"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-fedora-2[0-2]* ]]; then
    CONFIGURE_ARG_LIST+=(
        "--without-kcm"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-redhatenterprise*-7.*- ||
      "$DISTRO_BRANCH" == -redhat-centos-7.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--without-python3-bindings"
    )
fi

# Different versions of Debian might need different versions here but this is
# sufficient to make the CI work
if [[ "$DISTRO_BRANCH" == -debian-* ]]; then
    CONFIGURE_ARG_LIST+=(
        "--without-python2-bindings"
        "--with-smb-idmap-interface-version=5"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-fedora-3[2-9]* ||
      "$DISTRO_BRANCH" == -redhat-centos*-9*- ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-9.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--without-python2-bindings"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-fedora-3[5-9]* ||
      "$DISTRO_BRANCH" == -redhat-redhatenterprise*-9.*- ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-subid"
    )
fi

if [[ "$DISTRO_BRANCH" == -redhat-fedora-* ]]; then
    CONFIGURE_ARG_LIST+=(
        "--with-passkey"
    )
fi

declare -r -a CONFIGURE_ARG_LIST

fi # _CONFIGURE_SH

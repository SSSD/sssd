#!/bin/sh

#    Authors:
#        Lukas Slebodnik <lslebodn@redhat.com>
#
#    Copyright (C) 2013 Red Hat
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

PACKAGE_NAME="sssd"

usage(){
    echo "$(basename $0) [OPTIONS]"
    echo "\t-p, --prerelease   Create prerelease SRPM"
    echo "\t-d, --debug        Enable debugging."
    echo "\t-c, --clean        Remove directory rpmbuild and exit."
    echo "\t-h, --help         Print this help and exit."
    echo "\t-?, --usage"

    exit 1
}

for i in "$@"
do
case $i in
    -p|--prerelease)
    PRERELEASE=1
    ;;
    -d|--debug)
    set -x
    ;;
    -c|--clean)
    CLEAN=1
    ;;
    -h|--help|-\?|--usage)
    usage
    ;;
    *)
            # unknown option
    ;;
esac
done

RPMBUILD="$(pwd)/rpmbuild"
if [ -n "$CLEAN" ]; then
   rm -rfv "$RPMBUILD"
   exit 0
fi

SRC_DIR=$(git rev-parse --show-toplevel)
rc=$?
if [ $rc != 0 ]; then
    echo "This script must be run from the $PACKAGE_NAME git repository!"
    exit 1;
fi

if [ "x$SRC_DIR" = x ]; then
    echo "Fatal: Could not find source directory!"
    exit 1;
fi

VERSION_FILE="$SRC_DIR/version.m4"
SPEC_TEMPLATE="$SRC_DIR/contrib/$PACKAGE_NAME.spec.in"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Fatal: Could not find file version.m4 in source directory!"
    exit 1;
fi

if [ ! -f "$SPEC_TEMPLATE" ]; then
    echo "Fatal: Could not find $PACKAGE_NAME.spec.in in contrib subdirectory!"
    exit 1;
fi

PACKAGE_VERSION=$(grep "\[VERSION_NUMBER\]" $VERSION_FILE \
                  | sed -e 's/.*\[//' -e 's/\]).*$//')
if [ "x$PACKAGE_VERSION" = x ]; then
    echo "Fatal: Could parse version from file:$VERSION_FILE!"
    exit 1;
fi

PRERELEASE_VERSION=""
if [ -n "$PRERELEASE" ]; then
    PRERELEASE_VERSION=.$(date +%Y%m%d.%H%M).git$(git log -1 --pretty=format:%h)
fi

mkdir -p $RPMBUILD/BUILD
mkdir -p $RPMBUILD/RPMS
mkdir -p $RPMBUILD/SOURCES
mkdir -p $RPMBUILD/SPECS
mkdir -p $RPMBUILD/SRPMS

sed -e "s/@PACKAGE_NAME@/$PACKAGE_NAME/" \
    -e "s/@PACKAGE_VERSION@/$PACKAGE_VERSION/" \
    -e "s/@PRERELEASE_VERSION@/$PRERELEASE_VERSION/" \
    < "$SPEC_TEMPLATE" \
    > "$RPMBUILD/SPECS/$PACKAGE_NAME.spec"

NAME="$PACKAGE_NAME-$PACKAGE_VERSION"
git archive --format=tar.gz --prefix="$NAME"/ \
            --output "$RPMBUILD/SOURCES/$NAME.tar.gz" \
            --remote="file://$SRC_DIR" \
            HEAD

cp "$SRC_DIR"/contrib/*.patch "$RPMBUILD/SOURCES"

cd $RPMBUILD
rpmbuild --define "_topdir $RPMBUILD" \
         -bs SPECS/$PACKAGE_NAME.spec

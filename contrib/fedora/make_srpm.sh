#!/bin/bash

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
    echo "$(basename $0) [OPTIONS] [-P|--patches <patch>...]"
    echo -e "\t-p, --prerelease   Create prerelease SRPM"
    echo -e "\t-d, --debug        Enable debugging."
    echo -e "\t-c, --clean        Remove directory rpmbuild and exit."
    echo -e "\t-P, --patches      Requires list of patches for SRPM."
    echo -e "\t-o, --output       Moves the created srpm to a specific output directory."
    echo -e "\t-v, --version      Provide package version to set in spec file."
    echo -e "\t-h, --help         Print this help and exit."
    echo -e "\t-?, --usage"

    exit 1
}

add_patches(){
    spec_file=$1
    shift
    source_dir=$1
    shift

    patches=("${@}")

    # These keep track of our spec file substitutions.
    i=1
    prefix="Source0:"
    prepprefix="%setup"

    # If no patches exist, just exit.
    if [ -z "$patches" ]; then
        echo Creating SRPM without extra patches.
        return 0
    fi

    # Add the patches to the specfile.
    for p in "${patches[@]}"; do
        cp "$p" "$source_dir"
        p=$(basename $p)
        echo "Adding patch to spec file - $p"
        sed -i -e "/${prefix}/a Patch${i}: ${p}" \
               -e "/$prepprefix/a %patch${i} -p1" \
               "$spec_file"

        prefix="Patch${i}:"
        prepprefix="%patch${i}"
        i=$(($i+1))
    done
}

for i in "$@"
do
case $i in
    -p|--prerelease)
    PRERELEASE=1
    shift
    ;;
    -d|--debug)
    set -x
    shift
    ;;
    -c|--clean)
    CLEAN=1
    shift
    ;;
    -P|--patches)
    shift
    patches=("$@")
    break
    ;;
    -o|--output)
    shift
    OUTPUT=("$@")
    break
    ;;
    -v|--version)
    shift
    VERSION=("$@")
    break
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
if [ -n "$VERSION" ]; then
    PACKAGE_VERSION="$VERSION"
fi
if [ "x$PACKAGE_VERSION" = x ]; then
    echo "Fatal: Could parse version from file:$VERSION_FILE!"
    exit 1;
fi

PRERELEASE_VERSION=""
if [ -n "$PRERELEASE" ]; then
    PRERELEASE_VERSION=.$(date +%y%m%d.%H%M%S).git$(git log -1 --pretty=format:%h)
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
TARBALL="$RPMBUILD/SOURCES/$NAME.tar.gz"

git archive --format=tar --prefix="$NAME"/ \
            --remote="file://$SRC_DIR" \
            HEAD | gzip > "$TARBALL"

# fallback to tar if git archive failed
# tar may include more files so git archive is preferred
tar -tzf "$TARBALL" &> /dev/null
if [ $? -ne 0 ]; then
    rm -f "$TARBALL"
    pushd "$SRC_DIR"
    tar -cvzf "$TARBALL" --transform "s,^,$NAME/," *
    popd
fi

cp "$SRC_DIR"/contrib/*.patch "$RPMBUILD/SOURCES" 2>/dev/null
add_patches "$RPMBUILD/SPECS/$PACKAGE_NAME.spec" \
            "$RPMBUILD/SOURCES" \
            "${patches[@]}"

cp "$SRC_DIR"/contrib/sssd.sysusers "$RPMBUILD/SOURCES" 2>/dev/null

cd $RPMBUILD
rpmbuild --define "_topdir $RPMBUILD" \
         -bs SPECS/$PACKAGE_NAME.spec

if [ -n "$OUTPUT" ]; then
    mv "$RPMBUILD/SRPMS/"*.src.rpm "$OUTPUT/"
    echo "Package has been moved to the folder: $OUTPUT"
fi

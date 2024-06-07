#!/bin/bash

function config()
{
    autoreconf -i -f || return $?
    ./configure
}

SAVED_PWD=$PWD
version=`grep '\[VERSION_NUMBER], \[.*\]' version.m4 | grep '[0-9]\+\.[0-9]\+\.[0-9]\+\(~[^]]\+\)\?' -o`
tag=${version}

trap "cd $SAVED_PWD; rm -rf sssd-${version} sssd-${version}.tar" EXIT

git archive --format=tar --prefix=sssd-${version}/ ${tag} > sssd-${version}.tar
if [ $? -ne 0 ]; then
    echo "Cannot perform git-archive, check if tag $tag is present in git tree"
    exit 1
fi
tar xf sssd-${version}.tar

pushd sssd-${version}
config || exit 1
make dist-gzip || exit 1  # also builds docs
popd

mv sssd-${version}/sssd-${version}.tar.gz .
gpg2 --default-key C13CD07FFB2DB1408E457A3CD3D21B2910CF6759 --detach-sign --armor sssd-${version}.tar.gz
sha256sum sssd-${version}.tar.gz > sssd-${version}.tar.gz.sha256sum

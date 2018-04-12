#!/bin/bash

set -e

# Create an archive of the current checkout
TARBALL=`mktemp -p . tarball-XXXXXX.tar.bz2`
git ls-files |xargs tar cfj $TARBALL .git

sudo docker build -f Dockerfile.deps -t sssd/sssd-deps .

sudo docker build -t sssd/sssd --build-arg TARBALL=$TARBALL .

rm -f $TARBALL

exit 0

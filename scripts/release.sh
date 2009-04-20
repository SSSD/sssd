#!/bin/bash

version=`grep "^AC_INIT" server/configure.ac | tr -d "AC_INIT(sssd, " | tr -d ")"`
v_=`echo ${version} | tr "." "_"`

git archive --format=tar --prefix=sssd-${version}/ sssd-${v_} | gzip > sssd-${version}.tar.gz
gpg --detach-sign --armor sssd-${version}.tar.gz


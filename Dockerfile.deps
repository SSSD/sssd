FROM fedora:latest

MAINTAINER SSSD Maintainers <sssd-maint@redhat.com>

ARG TARBALL

RUN dnf -y install git openssl sudo curl wget ruby rubygems "rubygem(json)" wget rpm-build dnf-plugins-core libldb-devel && \
    git clone --depth=50 --branch=master https://github.com/SSSD/sssd.git /tmp/sssd && \
    cd /tmp/sssd && \
    ./contrib/fedora/make_srpm.sh && \
    dnf builddep -y rpmbuild/SRPMS/sssd-*.src.rpm && \
    dnf -y clean all

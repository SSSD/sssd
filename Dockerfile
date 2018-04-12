FROM sssd/sssd-deps

MAINTAINER SSSD Maintainers <sssd-maint@redhat.com>

ARG TARBALL

RUN  echo -n | openssl s_client -connect scan.coverity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee -a /etc/ssl/certs/ca- && curl -s https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh -o /usr/bin/travisci_build_coverity_scan.sh && chmod a+x /usr/bin/travisci_build_coverity_scan.sh

ADD $TARBALL /builddir/

ENTRYPOINT /builddir/.travis/travis-tasks.sh

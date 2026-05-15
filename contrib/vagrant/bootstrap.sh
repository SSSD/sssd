#!/bin/bash -x

sed -e "s/@PACKAGE_NAME@/sssd/" \
    -e "s/@PRERELEASE_VERSION@//" \
    -e "s/@PACKAGE_VERSION@/0/" \
    /vagrant/contrib/sssd.spec.in > /vagrant/contrib/sssd_vagrant.spec

dnf clean metadata
dnf install -y @buildsys-build realmd sssd adcli polkit oddjob-mkhomedir
dnf builddep -y /vagrant/contrib/sssd_vagrant.spec

source /usr/share/doc/git/contrib/completion/git-prompt.sh

cat << EOF >> /home/vagrant/.bashrc
source /usr/share/doc/git/contrib/completion/git-prompt.sh
export GIT_PS1_SHOWDIRTYSTATE=1
export PS1='[\u@\h:\W\$(__git_ps1 " (%s)")]\$\[\e[0m\] '

. /vagrant/contrib/fedora/bashrc_sssd

EOF

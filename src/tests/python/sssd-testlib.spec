%if 0%{?rhel} && 0%{?rhel}  >= 8
%global with_python3 1
%else
%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib2: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print (get_python_lib())")}
%endif
%if 0%{?fedora} >= 27
%global with_python3 1
%endif

%define name    sssd-testlib
%define owner   sssd-qe
%define project sssd-testlib
%define version 0.1
%define release 11
%define srcname sssd-testlib

Name:      %{name}
Version:   %{version}
Release:   %{release}%{?dist}
Summary:   System Services Security Daemon (SSSD) PyTest Framework
License:   GPLv3+
Source0:   %{name}.tar.gz

BuildArch:      noarch
%if 0%{?with_python3}
BuildRequires: python3-devel
%else
%if 0%{?fedora}
BuildRequires: python2-devel
%else
BuildRequires: python-devel
%endif
%endif

%if 0%{?fedora}
Requires:   python3-paramiko
Requires:   freeipa-python
Requires:   python3-pytest-multihost >= 1.1
Requires:   python3-PyYAML
Requires:   python3-pytest
Requires:   python-dns
Requires:   python-krbV
Requires:   python-nss
%else
Requires:   python-paramiko
Requires:   python-pytest-multihost >= 1.1
Requires:   PyYAML
Requires:   pytest
Requires:   python-ldap
Requires:   openldap-clients
Requires:   python-dns
Requires:   python-krbV
Requires:   python-nss
%else
%if 0%{?rhel}
Requires: ipa-python
%endif
%endif

%description
A python framework for System Services Security Daemon (SSSD) PyTest Framework.

%prep
%setup -qn %{project}

%if 0%{?with_python3}
echo %{py3dir}
rm -rf %{py3dir}
cp -a . %{py3dir}
%endif

%build
%{__python2} setup.py build
%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py build
popd
%endif

%install
%{__python2} setup.py install -O1 --skip-build --root %{buildroot}
%if 0%{?with_python3}
%py_byte_compile %{__python2} %{buildroot}%{python_sitelib}/%{srcname}
%else
%{__python2} -m compileall %{buildroot}%{python_sitelib}/%{srcname}
%endif

%if 0%{?with_python3}
pushd %{py3dir}
%{__python3} setup.py install --skip-build --root %{buildroot}
%py_byte_compile %{__python3} %{buildroot}%{python3_sitelib}/%{srcname}
popd
%endif

mkdir -p %{buildroot}/etc/sssd_testlib
install -m 644 sssd/testlib/etc/* %{buildroot}/etc/sssd_testlib/

%files
%doc README.rst docs/*
%config /etc/sssd_testlib
%if 0%{?fedora}
%{python2_sitelib}/*
%endif
%if 0%{?with_python3}
%{python3_sitelib}/*
%else:
%{python2_sitelib}/*
%endif

%changelog
* Fri Jul  7 2017 Niranjan MR <mrniranjan@redhat.com> - 0.1-11
- pylint fixes
* Sat Apr 19 2017 Niranjan MR <mrniranjan@redhat.com> - 0.1-10
- Add functions to create POSIX users/groups
- Add libkrb5 module to create kerberos server
- Use paramiko to test ssh logins for non-root users
- Update documentation
* Tue Mar 14 2017 Niranjan MR <mrniranjan@redhat.com> - 0.1-9
- Use adcli with realm to join system to Windows AD
* Mon Feb 20 2017 Niranjan MR <mrniranjan@redhat.com> - 0.1-8
- Fix indetation issues with qe_class.py
* Fri Feb 17 2017 Niranjan MR <mrniranjan@redhat.com> - 0.1-7
- pep8 fixes to sssd.testlib.common
- updated docs on setting up DS instances using multihost
* Wed Nov 30 2016 Niranjan MR <mrniranjan@redhat.com> - 0.1-6
- Add functions related to configuring Directory Server,
- Add functions related to adding, removing, modifying AD users,
  and adding UNIX attributes to Windows AD Users
* Fri Oct 21 2016 Niranjan MR <mrniranjan@redhat.com> - 0.1-5
- Add functions to connect AD and move common fixtures
  as sssdTools module in common
* Sat Sep 10 2016 Niranjan MR <mrniranjan@redhat.com> - 0.1-4
- Add Run time requirement to have pytest-multihost >= 1.1
- Modify spec file to be built on fedora/rhel
- When using fedora 24 and above use python3
* Wed Aug 24 2016 Niranjan MR <mrniranjan@redhat.com> - 0.1-3
- Add functions to start/stop/restart sssd based on RHEL versions
- Use systemctl instead of service command for systemd based versions
* Fri Jul 15 2016 Niranjan MR <mrnirnajan@redhat.com> - 0.1-2
- Modified qe_class.py to make Windows AD details to be in separate domain
- Added ipa-python as a Runtime dependency
* Thu Jun 30 2016 Niranjan MR <mrniranjan@redhat.com> - 0.1-1
- initial version-

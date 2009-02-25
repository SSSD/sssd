# XXX What version to call this?
%define sssd_release 2%{?dist}
%define sssd_version 0.1.0

Name: sssd
Version: %{sssd_version}
Release: %{sssd_release}
Group: Applications/System
Summary: System Security Services Daemon
License: GPLv3+ and LGPLv3+
URL: http://www.freeipa.org/
Source0: sssd-%{sssd_version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

### Patches ###

### Build Dependencies ###

BuildRequires: autoconf
BuildRequires: popt-devel
BuildRequires: libtalloc-devel
BuildRequires: libtevent-devel
BuildRequires: libtdb-devel
BuildRequires: libldb-devel
BuildRequires: dbus-devel
BuildRequires: dbus-libs
BuildRequires: check
BuildRequires: check-devel

%description
Provides a set of daemons to manage access to remote directories and
authentication mechanisms. It provides an NSS and PAM interface toward
the system and a pluggable backend system to connect to multiple different
account sources. It is also the basis to provide client auditing and policy
services for projects like FreeIPA.

%prep
%setup -q

%build

# sssd
cd server
./autogen.sh
%configure --prefix=%{_usr} \
           --sysconfdir=%{_sysconfdir} \
           --without-policykit \
           --with-infopipe

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT

# sssd
cd server
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sbindir}/sssd
%{_libexecdir}/sssd/sssd_nss
%{_libexecdir}/sssd/sssd_dp
%{_libexecdir}/sssd/sssd_be
%{_libdir}/%{name}/
# infopipe files
%{_libexecdir}/sssd/sssd_info
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freeipa.sssd.infopipe.conf

%changelog
* Mon Feb 23 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.1.0-2
- Small cleanup and fixes in the spec file

* Thu Feb 12 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.1.0-1
- Initial release (based on version 0.1.0 upstream code)

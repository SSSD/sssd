Name: sssd
Version: 0.1.0
Release: 4%{dist}
Group: Applications/System
Summary: System Security Services Daemon
# The entire source code is GPLv3+ except replace/ which is LGPLv3+
License: GPLv3+ and LGPLv3+
URL: http://www.freeipa.org/
Source0: sssd-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

### Patches ###

### Dependencies ###

Requires: libldb >= 0.9.3

Requires(preun):  initscripts chkconfig
Requires(postun): /sbin/service

%define servicename sssd

### Build Dependencies ###

BuildRequires: autoconf
BuildRequires: popt-devel
BuildRequires: libtalloc-devel
BuildRequires: libtevent-devel
BuildRequires: libtdb-devel
BuildRequires: libldb-devel
BuildRequires: dbus-devel
BuildRequires: dbus-libs
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: nss-devel
BuildRequires: nspr-devel

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
pushd server
./autogen.sh
%configure --prefix=%{_usr} \
           --sysconfdir=%{_sysconfdir} \
           --without-tests     \
           --without-policykit \
           --with-openldap \
           --with-infopipe \
           --with-initrd-dir=%{_initrddir} \

make %{?_smp_mflags}
popd

pushd sss_client
./autogen.sh
%configure --libdir=/%{_lib}
make %{?_smp_mflags}
popd

%install
rm -rf $RPM_BUILD_ROOT

# sssd
pushd server
make install DESTDIR=$RPM_BUILD_ROOT
popd

pushd sss_client
make install DESTDIR=$RPM_BUILD_ROOT
popd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc COPYING
%{_initrddir}/%{name}
%{_sbindir}/sssd
%{_sbindir}/sss_useradd
%{_sbindir}/sss_userdel
%{_sbindir}/sss_groupadd
%{_libexecdir}/%{servicename}/
%{_libdir}/%{name}/
%{_libdir}/ldb/memberof.so*
%{_sharedstatedir}/sss/
%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.freeipa.sssd.infopipe.conf
%{_datadir}/%{name}/introspect/infopipe/org.freeipa.sssd.infopipe.Introspect.xml
/%{_lib}/libnss_sss.so.0.0.1
/%{_lib}/libnss_sss.so.2
/%{_lib}/security/pam_sss.so

%post -p /sbin/ldconfig

%preun
if [ $1 = 0 ]; then
    /sbin/service %{servicename} stop 2>&1 > /dev/null
    /sbin/chkconfig --del %{servicename}
fi

%postun
/sbin/ldconfig
if [ $1 -ge 1 ] ; then
    /sbin/service %{servicename} condrestart 2>&1 > /dev/null
fi

%changelog
* Fri Mar 06 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.1.0-4
- fixed items found during review
- added initscript

* Thu Mar 05 2009 Sumit Bose <sbose@redhat.com> - 0.1.0-3
- added sss_client

* Mon Feb 23 2009 Jakub Hrozek <jhrozek@redhat.com> - 0.1.0-2
- Small cleanup and fixes in the spec file

* Thu Feb 12 2009 Stephen Gallagher <sgallagh@redhat.com> - 0.1.0-1
- Initial release (based on version 0.1.0 upstream code)

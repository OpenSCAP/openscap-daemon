%global debug_package %{nil}
%if 0%{?fedora} <= 22 || (0%{?rhel} != 0 && 0%{?rhel} <= 7)
%global pypkg python
%global pysitelib %{python_sitelib}
%global __python %{__python}
%global pgobject pygobject2
%else
%global pypkg python3
%global pysitelib %{python3_sitelib}
%global __python %{__python3}
%global pgobject python3-gobject-base
%endif

Name:           openscap-daemon
Version:        0.1.4
Release:        1%{?dist}
Summary:        Manages continuous SCAP scans of your infrastructure

License:        LGPLv2+
URL:            http://open-scap.org
Source0:        https://github.com/OpenSCAP/openscap-daemon/releases/download/%{version}/openscap_daemon-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  systemd-units
BuildRequires:  %{pypkg}-devel
Requires:       %{pypkg}
Requires:       %{pgobject}
Requires:       dbus
Requires:       dbus-python

# for the oscap tool
Requires:       openscap-scanner
# for oscap-ssh, oscap-docker, oscap-vm
Requires:       openscap-utils

%description
OpenSCAP-daemon is a service that performs SCAP scans of bare-metal machines,
virtual machines and containers. These scans can be either one-shot or
continuous according to a schedule. You can interact with the service
using the provided oscapd-cli tool or via the DBus interface.

%prep
%setup -q -n openscap_daemon-%{version}

%build
%{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root $RPM_BUILD_ROOT

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/LICENSE

%dir %{pysitelib}/openscap_daemon
%{pysitelib}/openscap_daemon/*

%{pysitelib}/*egg-info

%{_bindir}/oscapd
%{_mandir}/man8/oscapd.8.gz
%{_bindir}/oscapd-cli
%{_mandir}/man8/oscapd-cli.8.gz
%{_bindir}/oscapd-evaluate
%{_mandir}/man8/oscapd-evaluate.8.gz

%config(noreplace) %{_sysconfdir}/dbus-1/system.d/org.oscapd.conf
%{_unitdir}/oscapd.service

%changelog
* Mon Mar 28 2016 Martin Preisler <mpreisle@redhat.com> - 0.1.4-1
- upgrade to the latest upstream release

* Thu Feb 11 2016 Šimon Lukašík <slukasik@redhat.com> - 0.1.3-1
- upgrade to the latest upstream release

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 0.1.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Thu Jan 28 2016 Martin Preisler <mpreisle@redhat.com> - 0.1.2-1
- updated to 0.1.2
- dropped dependency on python-requests

* Thu Jan 21 2016 Šimon Lukašík <slukasik@redhat.com> - 0.1.1-4
- Add dependency on python requests

* Wed Jan 20 2016 Šimon Lukašík <slukasik@redhat.com> - 0.1.1-3
- Add dependency on python gobject

* Tue Jan 12 2016 Martin Preisler <mpreisle@redhat.com> - 0.1.1-2
- dropped the atomic requirement, it's an optional dependency

* Mon Jan 11 2016 Martin Preisler <mpreisle@redhat.com> - 0.1.1-1
- updated to 0.1.1

* Tue Dec 01 2015 Šimon Lukašík <slukasik@redhat.com> - 0.1.0-5
- build on all platforms where atomic is available

* Fri Nov 27 2015 Šimon Lukašík <slukasik@redhat.com> - 0.1.0-4
- install openscap-daemon in python3 directories on F23+

* Fri Nov 27 2015 Šimon Lukašík <slukasik@redhat.com> - 0.1.0-3
- openscap-daemon is now exlusively on x86_64

* Fri Nov 20 2015 Martin Preisler <mpreisle@redhat.com> - 0.1.0-2
- require dbus
- fixed license
- added config(noreplace) for org.oscapd.conf

* Mon Oct 26 2015 Martin Preisler <mpreisle@redhat.com> - 0.1.0-1
- initial version

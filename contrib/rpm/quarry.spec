# Copyright (C) 2026 Amutable GmbH

%bcond_without http
%bcond_with insecure

%define buildtags %{?with_http:http} %{?with_insecure:insecure} %{nil}

%if %{with http}
%{!?client_http_port: %global client_http_port 555}
%endif

Name:           quarry
Version:        0.0.1
Release:        %autorelease
Summary:        TUF Repository Scheme for AmutableOS
License:        Proprietary
URL:            https://github.com/amutable-systems/quarry
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  go >= 1.25
# This is currently installed on the host machine in a somewhat dodgy way.
#BuildRequires:  libpathrs-devel >= 0.2.4
BuildRequires:  just
BuildRequires:  systemd-rpm-macros
BuildRequires:  systemd-sysusers

%description

%package hardhat
Summary:        Management Tool for Quarry Repositories
Requires:       %{name} = %{version}

%description hardhat
A fairly minimal CLI management tool for Quarry repositories. It provides the
low-level primitives necessary to manage (i.e., create and publish) a TUF
repository containing arbitrary package contents.

%package client
Summary:        Client for Quarry Repositories
Requires:       %{name} = %{version}

%description client
A custom TUF client that supports Quarry-specific extensions. In addition to
working as a very minimal downloader for data stored in TUF repositories, it
also provides a "source" of updates for sysupdate.
%if %{with http}

At the moment this is done via a HTTP-based "bridge" that translates TUF
metadata to a sysupdate-compatible SHA256SUMS-based local HTTP server. By
modifying the necessary transfer files to point to the local quarry-client-http
server, sysupdate can pull from TUF repositories completely transparently
without needing any changes to sysupdate.
%endif

%if %{with http}
%package client-http
Summary:        sysupdate-compatible HTTP Server Frontend for Quarry Repositories
Requires:       %{name} = %{version}
Requires:       %{name}-client = %{version}

%description client-http
This is a HTTP-based "bridge" that translates TUF metadata to a
sysupdate-compatible SHA256SUMS-based local HTTP server using %{name}-client as
a backend. By modifying the necessary transfer files to point to the local
quarry-client-http server, sysupdate can pull from TUF repositories completely
transparently without needing any changes to sysupdate.
%endif

%prep
%autosetup

%build
export BUILDTAGS="%{buildtags}"
just build_all

%install
export DESTDIR=%{buildroot}
export SYSCONFDIR=%{_sysconfdir}
%if %{with http}
export CLIENT_HTTP_PORT=%{client_http_port}
%endif

just install
# Also install the config to /var/lib/...
install -Dm0644 ./contrib/quarry-client.toml %{buildroot}%{_sharedstatedir}/%{name}-client/config.toml

%if %{with http}
just install_client_http_service
%endif

#install -dm0755 %{buildroot}%{_rundir}/%{name}
#install -dm0700 %{buildroot}%{_rundir}/%{name}/keys
install -Dm0644 ./contrib/systemd/hardhat.sysusers %{buildroot}%{_sysusersdir}/%{name}-hardhat.conf
install -Dm0644 ./contrib/systemd/hardhat.tmpfiles %{buildroot}%{_tmpfilesdir}/%{name}-hardhat.conf

#install -dm0755 %{buildroot}%{_rundir}/%{name}-client/cache
install -Dm0644 ./contrib/systemd/quarry-client.tmpfiles %{buildroot}%{_tmpfilesdir}/%{name}-client.conf
install -Dm0644 ./contrib/systemd/quarry-client-http.sysusers %{buildroot}%{_sysusersdir}/%{name}-client-http.conf
# Directory for bundled trust roots.
install -dm0755 %{buildroot}%{_datarootdir}/amutable/%{name}/bundled

%if %{with http}
%post client
%systemd_post %{name}-client-http.socket %{name}-client-http.service

%preun client
%systemd_preun %{name}-client-http.socket %{name}-client-http.service

%postun client
%systemd_postun_with_restart %{name}-client-http.socket %{name}-client-http.service
%endif

%files
%defattr(-,root,root)
%doc README.md

%files hardhat
%defattr(-,root,root)
%{_bindir}/%{name}-hardhat
#%dir %{_rundir}/%{name}
%{_tmpfilesdir}/%{name}-hardhat.conf
%{_sysusersdir}/%{name}-hardhat.conf

%files client
%defattr(-,root,root)
%{_bindir}/%{name}-client
%{_unitdir}/%{name}-client*
%dir %{_datarootdir}/amutable/%{name}
%config(noreplace) %{_sysconfdir}/%{name}-client.toml
%config %{_sharedstatedir}/%{name}-client/config.toml
%if !0%{with http}
#%attr(-,quarry,quarry) %dir %{_rundir}/%{name}-client
%{_tmpfilesdir}/%{name}-client.conf
%{_sysusersdir}/%{name}-client-http.conf
%endif

%if %{with http}
%files client-http
%{_unitdir}/%{name}-client-http.*
#%attr(-,quarry,quarry) %dir %{_rundir}/%{name}-client
%{_tmpfilesdir}/%{name}-client.conf
%{_sysusersdir}/%{name}-client-http.conf
%endif

%changelog
%autochangelog

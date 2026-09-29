# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Amutable GmbH

%bcond sysupdate 1
%bcond insecure  0

%define buildtags %{?with_sysupdate:http} %{?with_insecure:insecure} %{nil}

%if %{with sysupdate}
%{!?client_http_port: %global client_http_port 555}
%endif

Name:           quarry
Version:        0.0.1
Release:        %autorelease
Summary:        TUF Repository Scheme for AmutableOS
License:        Apache-2.0
URL:            https://github.com/amutable-systems/quarry
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  go >= 1.26.4
BuildRequires:  libpathrs-devel >= 0.2.5
BuildRequires:  just
BuildRequires:  systemd-rpm-macros
BuildRequires:  systemd-sysusers

%description
A custom TUF [1] client that supports extensions used by Amutable OS for
distributing updates and provisioning nodes.
%if %{with sysupdate}

This build of the quarry client includes support for driving system updates
through sysupdate, making use of a HTTP-based bridge. If the system has
compatible transfer files with (a [Source] with Path=http://localhost:%{client_http_port}/)
then sysupdate can natively pull from TUF repositories. However for complete
Quarry support, updates should be driven using the quarry-sysupdate helper.
%endif

[1]: https://theupdateframework.io/

%package hardhat
Summary:        Management Tool for Quarry Repositories

%description hardhat
A fairly minimal CLI management tool for Quarry repositories. It provides the
low-level primitives necessary to manage (i.e., create and publish) a TUF
repository containing arbitrary package contents.

%prep
%autosetup -C

%build
export BUILDTAGS="%{buildtags}"
just build-all

%install
export DESTDIR=%{buildroot}
export SYSCONFDIR=%{_sysconfdir}
%if %{with sysupdate}
export CLIENT_HTTP_PORT=%{client_http_port}
%endif

just install

%if %{with sysupdate}
just install-sysupdate
just install-client-http-service
%endif

#install -dm0755 %{buildroot}%{_sharedstatedir}/%{name}
#install -dm0700 %{buildroot}%{_sharedstatedir}/%{name}/keys
install -Dm0644 ./contrib/systemd/hardhat.sysusers %{buildroot}%{_sysusersdir}/%{name}-hardhat.conf
install -Dm0644 ./contrib/systemd/hardhat.tmpfiles %{buildroot}%{_tmpfilesdir}/%{name}-hardhat.conf

install -dm0750 %{buildroot}%{_sharedstatedir}/%{name}-client/latest-metadata
install -Dm0644 ./contrib/systemd/quarry-client.sysusers %{buildroot}%{_sysusersdir}/%{name}-client.conf
install -Dm0644 ./contrib/systemd/quarry-client.tmpfiles %{buildroot}%{_tmpfilesdir}/%{name}-client.conf
# Directory for bundled trust roots.
install -dm0755 %{buildroot}%{_datarootdir}/amutable/%{name}/bundled

%if %{with sysupdate}
%post
%systemd_post %{name}-client-http.socket %{name}-client-http.service
%systemd_post %{name}-sysupdate.timer %{name}-sysupdate.service

%preun
%systemd_preun %{name}-client-http.socket %{name}-client-http.service
%systemd_preun %{name}-sysupdate.timer %{name}-sysupdate.service

%postun
%systemd_postun_with_restart %{name}-client-http.socket %{name}-client-http.service
%systemd_postun_with_restart %{name}-sysupdate.timer %{name}-sysupdate.service
%endif

%files
# quarry is the multi-call binary containing all of the quarry-* commands. We
# currently build the sysupdate applet regardless of the conditional here, so
# disabling it only skips installing the symlink and units.
%{_bindir}/%{name}
%{_bindir}/%{name}-client
%if %{with sysupdate}
# quarry-sysupdate
%{_bindir}/%{name}-sysupdate
%{_unitdir}/%{name}-sysupdate*
# quarry-client http
%{_unitdir}/%{name}-client-http*
%endif
# For Amutable-bundled root.jsons.
%dir %{_datarootdir}/amutable/%{name}
%dir %{_datarootdir}/amutable/%{name}/bundled
# Vendor configs.
%dir %{_prefix}/lib/%{name}-client
%{_prefix}/lib/%{name}-client/config.toml
%dir %{_prefix}/lib/%{name}-client/config.toml.d
%{_prefix}/lib/%{name}-client/config.toml.d/*.toml
# User configs.
%dir %{_sysconfdir}/%{name}-client
%dir %{_sysconfdir}/%{name}-client/config.toml.d
# Metadata cache directory.
%attr(0750,quarry,quarry) %dir %{_sharedstatedir}/%{name}-client
%{_tmpfilesdir}/%{name}-client.conf
%{_sysusersdir}/%{name}-client.conf

%files hardhat
%{_bindir}/%{name}-hardhat
#%%dir %%{_rundir}/%{name}
%{_tmpfilesdir}/%{name}-hardhat.conf
%{_sysusersdir}/%{name}-hardhat.conf

%changelog
%autochangelog

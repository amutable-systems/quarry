# Copyright (C) 2026 Amutable GmbH

destdir := env("DESTDIR", "")
prefix := "/usr"
sysconfdir := env("SYSCONFDIR", "/etc")
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
client_http_port := env("CLIENT_HTTP_PORT", "555")
buildtags := env("BUILDTAGS", "http insecure")

default: build_all

build_all: \
		(build "hardhat" buildtags) \
		(build "quarry-client" buildtags) \
		(build "quarry-sysupdate" buildtags)

install: install_hardhat install_client install_client_config

install_hardhat:
	install -Dm0755 ./hardhat {{destdir}}{{bindir}}/quarry-hardhat

install_client:
	install -Dm0755 ./quarry-client {{destdir}}{{bindir}}/quarry-client
	install -dm0755 {{destdir}}{{unitdir}}

install_sysupdate:
	install -Dm0755 ./quarry-sysupdate {{destdir}}{{bindir}}/quarry-sysupdate
	install -Dm0644 -t {{destdir}}{{unitdir}} ./contrib/systemd/quarry-sysupdate*

install_client_http_service:
	sed 's|@bindir@|{{bindir}}|g;s|@client_http_port@|{{client_http_port}}|g' contrib/systemd/quarry-client-http.service.in >{{destdir}}{{unitdir}}/quarry-client-http.service
	sed 's|@bindir@|{{bindir}}|g;s|@client_http_port@|{{client_http_port}}|g' contrib/systemd/quarry-client-http.socket.in >{{destdir}}{{unitdir}}/quarry-client-http.socket

install_client_config:
	install -Dm0644 ./contrib/quarry-client.toml {{destdir}}{{sysconfdir}}/quarry-client.toml

[private]
build cmd tags="":
	go build -o "{{cmd}}" -tags "{{tags}}" "./cmd/{{cmd}}"

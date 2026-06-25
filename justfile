# Copyright (C) 2026 Amutable GmbH

outdir := env("OUTDIR", ".")
destdir := env("DESTDIR", "")
prefix := "/usr"
sysconfdir := env("SYSCONFDIR", "/etc")
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
client_http_port := env("CLIENT_HTTP_PORT", "555")
buildtags := env("BUILDTAGS", "http insecure")

container_engine := env("CONTAINER_ENGINE", "docker")

default: build-all

build-all: \
		(build "hardhat" buildtags) \
		(build "quarry-client" buildtags) \
		(build "quarry-sysupdate" buildtags)

build-all-in-container:
	{{container_engine}} buildx build -f Dockerfile --target export \
		--build-arg BUILDTAGS="{{buildtags}}" \
		-o type=local,dest="{{outdir}}" \
		.

install: install-hardhat install-client install-client-config

install-hardhat:
	install -Dm0755 {{outdir}}/hardhat {{destdir}}{{bindir}}/quarry-hardhat

install-client:
	install -Dm0755 {{outdir}}/quarry-client {{destdir}}{{bindir}}/quarry-client
	install -dm0755 {{destdir}}{{unitdir}}

install-sysupdate:
	install -Dm0755 {{outdir}}/quarry-sysupdate {{destdir}}{{bindir}}/quarry-sysupdate
	install -Dm0644 -t {{destdir}}{{unitdir}} ./contrib/systemd/quarry-sysupdate*

install-client-http-service:
	sed 's|@bindir@|{{bindir}}|g;s|@client_http_port@|{{client_http_port}}|g' contrib/systemd/quarry-client-http.service.in >{{destdir}}{{unitdir}}/quarry-client-http.service
	sed 's|@bindir@|{{bindir}}|g;s|@client_http_port@|{{client_http_port}}|g' contrib/systemd/quarry-client-http.socket.in >{{destdir}}{{unitdir}}/quarry-client-http.socket

install-client-config:
	install -Dm0644 ./contrib/quarry-client.toml {{destdir}}{{sysconfdir}}/quarry-client.toml

[private]
build cmd tags="":
	go build -o "{{outdir}}/{{cmd}}" -tags "{{tags}}" "./cmd/{{cmd}}"

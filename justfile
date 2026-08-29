# Copyright (C) 2026 Amutable GmbH

outdir := env("OUTDIR", ".")
destdir := env("DESTDIR", "")
prefix := "/usr"
sysconfdir := env("SYSCONFDIR", "/etc")
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
vendorconfdir := prefix / "lib"
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

sd_binaries := env("SD_BINARIES", "systemd-hostnamed")

build-systemd:
	{{ container_engine }} buildx build -f Dockerfile --target systemd-export \
		--build-arg SD_BINARIES="{{ sd_binaries }}" \
		-o type=local,dest="{{ outdir }}/systemd" \
		.

test:
	go test -race -tags "{{buildtags}}" ./...

lint: lint-go lint-gomod lint-shell lint-gha vuln

lint-go:
	golangci-lint run

lint-gomod:
	go mod tidy -diff

lint-shell:
	git ls-files -z \
		| xargs -0 file --mime-type -- \
		| grep 'text/x-shellscript$' \
		| cut -d: -f1 \
		| xargs -d'\n' -r shellcheck --

lint-gha:
	zizmor .github/
	go run github.com/rhysd/actionlint/cmd/actionlint@latest

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest -tags "{{ replace(buildtags, ' ', ',') }}" ./...

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
	install -dm0755 \
		{{destdir}}{{vendorconfdir}}/quarry-client{,/config.toml.d} \
		{{destdir}}{{sysconfdir}}/quarry-client{,/config.toml.d}
	install -m0644 ./contrib/quarry-client.toml {{destdir}}{{vendorconfdir}}/quarry-client/config.toml

[private]
build cmd tags="":
	go build -o "{{outdir}}/{{cmd}}" -tags "{{tags}}" "./cmd/{{cmd}}"

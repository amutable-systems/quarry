# Copyright (C) 2026 Amutable GmbH

destdir := env("DESTDIR", "")
prefix := "/usr"
sysconfdir := env("SYSCONFDIR", "/etc")
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"

default: (build "quarry-client") (build "hardhat" "insecure")

install: install_hardhat install_client

install_hardhat: (build "hardhat" "insecure")
	install -Dm0755 ./hardhat {{destdir}}{{bindir}}/quarry-hardhat

install_client: (build "quarry-client")
	install -Dm0755 ./quarry-client {{destdir}}{{bindir}}/quarry-client

[private]
build cmd tags="":
	go build -o "{{cmd}}" -tags "{{tags}}" "./cmd/{{cmd}}"

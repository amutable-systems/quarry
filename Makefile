# Copyright (C) 2026 Amutable GmbH

.PHONY: all
all: hardhat quarry-client

.PHONY: hardhat
hardhat:
	go build -tags insecure -o $@ ./cmd/$@

.PHONY: quarry-client
quarry-client:
	go build -o $@ ./cmd/$@

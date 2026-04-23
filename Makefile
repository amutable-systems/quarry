# Copyright (C) 2026 Amutable GmbH

.PHONY: hardhat
hardhat:
	go build -tags insecure -o hardhat ./cmd/hardhat

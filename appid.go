// Copyright (C) 2026 Amutable GmbH

package quarry

import (
	"github.com/google/uuid"
)

// ApplicationID is the UUID used by all Amutable applications, used with
// systemd-id128 to produce application-specific machine IDs. Represented
// traditionally, this UUID is "04ec60eb-87dd-434a-9733-1009bb5c4b34".
var ApplicationID = uuid.MustParse("04ec60eb-87dd-434a-9733-1009bb5c4b34")

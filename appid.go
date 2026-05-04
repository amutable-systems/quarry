// Copyright (C) 2026 Amutable GmbH

package quarry

import (
	"github.com/google/uuid"
)

// ApplicationID is the UUID of quarry as an application, used with
// systemd-id128 to produce application-specific machine IDs. Represented
// traditionally, this UUID is "7ad9c7cd-e1e1-4188-a43f-10dc889df417".
var ApplicationID = uuid.MustParse("7ad9c7cd-e1e1-4188-a43f-10dc889df417")

package securityevent

import "webtyp.com/fmt"

// Errors of this package; compare with ==.
var (
	ErrNoBroker           = fmt.Err("no events broker was given")
	ErrNoHandler          = fmt.Err("no function was given to receive security events")
	ErrReporterNotCreated = fmt.Err("the reporter was not created with New")
	ErrUnknownKind        = fmt.Err("the event has no known kind")
)

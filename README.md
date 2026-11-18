# securityevent
<img src="docs/img/badges.svg">

Security event vocabulary for webtyp: one contract every layer publishes through (OWASP names, fields, never secrets).

## Why This Exists

If someone tries to sign in by force, probes identifiers or injects a script, someone must find out. Each layer sees a different part of an attack — the sign-in, the permission gate, the data validation, the browser — so they need one shared [vocabulary](kind.go) and one [way to report](securityevent.go), or every layer invents its own and nothing can be counted together.

**Without this vs. With this**
* Without this: each layer defines its own event type or prints a text line; nobody can count failures across layers or alert.
* With this: every layer reports a typed `Event`; one subscriber writes, counts and alerts. Details: [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Before You Start

```bash
go get webtyp.com/securityevent@latest
```

## Step-by-Step Guide

### Step 1: Report from a layer

```go
package signin

import (
	"webtyp.com/events"
	"webtyp.com/securityevent"
)

const reasonUnknownID securityevent.Reason = "unknown identifier"

func refuse(broker events.Publisher, ip string) error {
	reporter, err := securityevent.New(broker)
	if err != nil {
		return err
	}
	return reporter.Report(securityevent.Event{Kind: securityevent.LoginFailed, IP: ip, Reason: reasonUnknownID})
}
```

### Step 2: Listen once, in the composition root

```go
package app

import (
	"webtyp.com/events"
	"webtyp.com/securityevent"
)

func watch(broker events.Subscriber, log func(...any)) error {
	_, err := securityevent.Listen(broker, func(e securityevent.Event) {
		log(e.Kind.Level().String(), e.Kind.Name(), e.IP, e.UserID, string(e.Reason))
	})
	return err
}
```

## Documentation Map

| Document | What it answers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | pieces, flow, what an event may never carry |
| [docs/TESTS.md](docs/TESTS.md) | every rule the tests prove |
| [kind.go](kind.go) | every kind, its OWASP name and level |

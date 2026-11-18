// Package securityevent is the one vocabulary of security events in webtyp. Every layer reports through it — the
// sign-in modes, the HTTP permission gate, crud's validation, the browser's blocked-content reports — and one
// subscriber, wired by the composition root, writes, counts and alerts. Names follow the OWASP Logging Vocabulary.
//
//	reporter, err := securityevent.New(broker)
//	err = reporter.Report(securityevent.Event{Kind: securityevent.LoginFailed, IP: ip, Mode: auth.ProviderTrustedIP})
package securityevent

import (
	"webtyp.com/events"
	"webtyp.com/model"
	"webtyp.com/time"
)

// Topic is the events topic every security event travels on; subscribe with Listen, never with this string.
const Topic = "security.event"

// Reason says why something was refused, as a named constant of the package that reports it
// (const reasonUnknownRUT securityevent.Reason = "unknown RUT"). It is never what the person typed, a password,
// a token or a session id: a log line must not carry a secret.
type Reason string

// Event is one security event. Fill only what you know; Report stamps At.
//
//	securityevent.Event{Kind: securityevent.AccessDenied, UserID: uid, Resource: "patient"}
type Event struct {
	Kind     Kind
	UserID   string    // who, when known; empty before the person is identified
	IP       string    // the caller's address, when known
	Mode     string    // the sign-in mode that reported it (its auth.Authenticator Name); empty in other layers
	Resource string    // the resource refused (AccessDenied)
	Reason   Reason    // why, as a named constant of the reporter
	At       time.Unix // seconds; set by Report
}

// IsNil lets an Event travel as an events payload.
func (e *Event) IsNil() bool { return e == nil }

// EncodeFields writes the event with its OWASP name and level, so a log line or a wire copy reads on its own.
func (e *Event) EncodeFields(w model.FieldWriter) {
	w.String(fieldEvent, e.Kind.Name())
	w.String(fieldLevel, e.Kind.Level().String())
	w.String(fieldUserID, e.UserID)
	w.String(fieldIP, e.IP)
	w.String(fieldMode, e.Mode)
	w.String(fieldResource, e.Resource)
	w.String(fieldReason, string(e.Reason))
	w.Int(fieldAt, int64(e.At))
}

const (
	fieldEvent    = "event"
	fieldLevel    = "level"
	fieldUserID   = "user_id"
	fieldIP       = "ip"
	fieldMode     = "mode"
	fieldResource = "resource"
	fieldReason   = "reason"
	fieldAt       = "at"
)

// Reporter publishes security events. Create it with New; its zero value refuses every report.
type Reporter struct{ pub events.Publisher }

// New is the reporter over the app's broker; a nil broker is refused at startup, never ignored later.
//
//	reporter, err := securityevent.New(broker)
func New(pub events.Publisher) (Reporter, error) {
	if pub == nil {
		return Reporter{}, ErrNoBroker
	}
	return Reporter{pub: pub}, nil
}

// Report stamps the event with the current time and publishes it on Topic.
//
//	err := reporter.Report(securityevent.Event{Kind: securityevent.RateLimited, IP: ip})
func (r Reporter) Report(e Event) error {
	if r.pub == nil {
		return ErrReporterNotCreated
	}
	if e.Kind.Name() == "" {
		return ErrUnknownKind
	}
	e.At = time.NowUnix()
	r.pub.Publish(events.Event{Topic: Topic, Payload: &e})
	return nil
}

// Listen calls h with every security event published on the broker; it is the one place that knows the payload type.
//
//	_, err := securityevent.Listen(broker, func(e securityevent.Event) { log(e.Kind.Name(), e.IP) })
func Listen(sub events.Subscriber, h func(Event)) (events.Subscription, error) {
	if sub == nil {
		return nil, ErrNoBroker
	}
	if h == nil {
		return nil, ErrNoHandler
	}
	return sub.Subscribe(Topic, func(ev events.Event) {
		// Only Report publishes on Topic, always with *Event.
		if e, ok := ev.Payload.(*Event); ok && e != nil {
			h(*e)
		}
	}), nil
}

package tests

import (
	"testing"

	"webtyp.com/events/inprocess"
	"webtyp.com/json"
	"webtyp.com/msgtype"
	"webtyp.com/securityevent"
)

func TestReport_DeliversToListener(t *testing.T) {
	broker := &inprocess.Broker{}
	var got []securityevent.Event
	if _, err := securityevent.Listen(broker, func(e securityevent.Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	reporter, err := securityevent.New(broker)
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Report(securityevent.Event{Kind: securityevent.LoginFailed, IP: "10.0.0.7", Mode: "trusted_ip", Reason: "unknown RUT"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("delivered %d events, want 1", len(got))
	}
	e := got[0]
	if e.Kind != securityevent.LoginFailed || e.IP != "10.0.0.7" || e.Mode != "trusted_ip" || e.Reason != "unknown RUT" {
		t.Fatalf("delivered %+v", e)
	}
	if e.At <= 0 {
		t.Fatalf("At = %d, want the time Report stamped", e.At)
	}
}

func TestReport_RefusesZeroKind(t *testing.T) {
	broker := &inprocess.Broker{}
	delivered := 0
	if _, err := securityevent.Listen(broker, func(securityevent.Event) { delivered++ }); err != nil {
		t.Fatal(err)
	}
	reporter, _ := securityevent.New(broker)
	if err := reporter.Report(securityevent.Event{IP: "10.0.0.7"}); err != securityevent.ErrUnknownKind {
		t.Fatalf("err = %v, want ErrUnknownKind", err)
	}
	if delivered != 0 {
		t.Fatalf("delivered %d events, want 0", delivered)
	}
}

func TestReporter_ZeroValueRefuses(t *testing.T) {
	var reporter securityevent.Reporter
	if err := reporter.Report(securityevent.Event{Kind: securityevent.LoginFailed}); err != securityevent.ErrReporterNotCreated {
		t.Fatalf("err = %v, want ErrReporterNotCreated", err)
	}
}

func TestNew_RefusesNilBroker(t *testing.T) {
	if _, err := securityevent.New(nil); err != securityevent.ErrNoBroker {
		t.Fatalf("err = %v, want ErrNoBroker", err)
	}
}

func TestListen_RefusesNilBrokerOrHandler(t *testing.T) {
	if _, err := securityevent.Listen(nil, func(securityevent.Event) {}); err != securityevent.ErrNoBroker {
		t.Fatalf("nil broker: err = %v, want ErrNoBroker", err)
	}
	if _, err := securityevent.Listen(&inprocess.Broker{}, nil); err != securityevent.ErrNoHandler {
		t.Fatalf("nil handler: err = %v, want ErrNoHandler", err)
	}
}

func TestKind_EveryKindHasNameAndLevel(t *testing.T) {
	kinds := []securityevent.Kind{
		securityevent.LoginSucceeded, securityevent.LoginFailed, securityevent.LoginLocked, securityevent.RateLimited,
		securityevent.SessionInvalid, securityevent.TokenForged, securityevent.TokenReused, securityevent.AccessDenied,
		securityevent.InputRejected, securityevent.RequestTooLarge, securityevent.ContentBlocked, securityevent.AdminCreated,
		securityevent.SetupRejected, securityevent.SecurityStoreFailed, securityevent.CredentialAdded, securityevent.CredentialRemoved,
	}
	seen := []string{}
	for _, k := range kinds {
		name := k.Name()
		if name == "" {
			t.Fatalf("kind %d has no name", k)
		}
		for _, s := range seen {
			if s == name {
				t.Fatalf("name %q used twice", name)
			}
		}
		seen = append(seen, name)
		if l := k.Level(); l != msgtype.Info && l != msgtype.Warning && l != msgtype.Error {
			t.Fatalf("kind %s has level %s, want Info, Warning or Error", name, l)
		}
	}
	if securityevent.Kind(0).Name() != "" {
		t.Fatal("the zero Kind must have no name")
	}
}

func TestKind_NamesFollowOWASP(t *testing.T) {
	cases := []struct {
		kind securityevent.Kind
		name string
	}{
		{securityevent.LoginSucceeded, "authn_login_success"},
		{securityevent.LoginFailed, "authn_login_fail"},
		{securityevent.LoginLocked, "authn_login_lock"},
		{securityevent.AccessDenied, "authz_fail"},
		{securityevent.RateLimited, "excess_rate_limit_exceeded"},
		{securityevent.InputRejected, "input_validation_fail"},
		{securityevent.TokenReused, "authn_token_reuse"},
	}
	for _, c := range cases {
		if got := c.kind.Name(); got != c.name {
			t.Fatalf("Name() = %q, want %q", got, c.name)
		}
	}
}

func TestEvent_EncodesNameLevelAndFields(t *testing.T) {
	e := &securityevent.Event{Kind: securityevent.AccessDenied, UserID: "u1", Resource: "patient", At: 1700000000}
	var out []byte
	if err := json.Encode(e, &out); err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"event":"authz_fail"`, `"level":"Error"`, `"user_id":"u1"`, `"resource":"patient"`, `"at":1700000000`} {
		if !contains(s, want) {
			t.Fatalf("encoded %s, missing %s", s, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

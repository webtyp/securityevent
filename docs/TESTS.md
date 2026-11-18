| Test | Rule |
|---|---|
| [TestReport_DeliversToListener](../tests/securityevent_test.go) | `Listen` + `Report(LoginFailed, IP, Mode, Reason)` → the handler receives the same fields and `At > 0` |
| [TestReport_RefusesZeroKind](../tests/securityevent_test.go) | `Report` with no `Kind` → `ErrUnknownKind`, nothing delivered |
| [TestReporter_ZeroValueRefuses](../tests/securityevent_test.go) | a zero `Reporter` → `ErrReporterNotCreated` |
| [TestNew_RefusesNilBroker](../tests/securityevent_test.go) | `New(nil)` → `ErrNoBroker` |
| [TestListen_RefusesNilBrokerOrHandler](../tests/securityevent_test.go) | `Listen(nil, h)` → `ErrNoBroker`; `Listen(broker, nil)` → `ErrNoHandler` |
| [TestKind_EveryKindHasNameAndLevel](../tests/securityevent_test.go) | every declared `Kind` has a unique name and a level of Info, Warning or Error; the zero `Kind` has none |
| [TestKind_NamesFollowOWASP](../tests/securityevent_test.go) | `LoginFailed` → `authn_login_fail`, `AccessDenied` → `authz_fail`, `RateLimited` → `excess_rate_limit_exceeded`… |
| [TestEvent_EncodesNameLevelAndFields](../tests/securityevent_test.go) | encoding an `AccessDenied` event writes `event`, `level`, `user_id`, `resource`, `at` |

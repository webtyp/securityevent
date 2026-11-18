## 1. Overview in One Minute

`securityevent` is the one vocabulary of security events in webtyp. A layer that sees something suspicious (a refused sign-in, a denied permission, a request too large, a script the browser blocked) reports an `Event` through a `Reporter`; the composition root listens once with `Listen` and decides what to do with it (write a line, count, block, alert).

## 2. Repository Pieces & On-Disk Layout

| File | Holds |
|---|---|
| `securityevent.go` | `Topic`, `Event`, `Reason`, `Reporter`, `New`, `Report`, `Listen` |
| `kind.go` | `Kind`, its constants, `Name` (OWASP Logging Vocabulary) and `Level` |
| `errors.go` | the errors, compared with `==` |
| `tests/` | the contract through the real in-process broker (`events/inprocess`) |

## 3. Step-by-Step Flows

1. At startup the composition root creates the reporter over its broker: `securityevent.New(broker)`; a nil broker fails there.
2. It listens once: `securityevent.Listen(broker, handle)`.
3. A layer reports: `reporter.Report(securityevent.Event{Kind: securityevent.LoginFailed, IP: ip, Mode: mode})`; `Report` stamps `At` and publishes on `Topic`.
4. `handle` receives the event and writes, counts or alerts.

## 4. Security Boundaries & Contracts

- An event never carries a secret: no password, token, session id or typed input. `Reason` is a constant of the reporter.
- Names follow the [OWASP Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html); kinds it lacks use its prefixes (`authn_`, `authz_`, `excess_`, `malicious_`, `sys_`).
- `Kind` numbers never change; new kinds are appended.
- Zero values refuse: a zero `Reporter`, a zero `Kind`, a nil broker or handler each return an error.

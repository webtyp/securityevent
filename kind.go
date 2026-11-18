package securityevent

import "webtyp.com/msgtype"

// Kind is what happened. The numbers are stable: append new kinds at the end, never reorder. The zero value is not a
// kind and Report refuses it.
type Kind uint8

const (
	_                   Kind = iota
	LoginSucceeded           // a person signed in
	LoginFailed              // a sign-in was refused: bad or unknown credential, untrusted device, inactive account
	LoginLocked              // too many failures: sign-in from this address or for this person is blocked for a while
	RateLimited              // a request was refused before any work because of too many attempts
	SessionInvalid           // a session credential was presented but is expired, revoked or altered
	TokenForged              // a signed token did not verify: someone altered or invented it
	TokenReused              // a one-time token was presented a second time
	AccessDenied             // a signed-in person asked for something their permissions do not allow
	InputRejected            // a request broke the declared shape of the data (a field, a size, a type)
	RequestTooLarge          // a request body was over the allowed size
	ContentBlocked           // the browser blocked a script or style the page did not sign (a content-policy report)
	AdminCreated             // the first administrator was created
	SetupRejected            // the first-run setup was attempted after an administrator already existed
	SecurityStoreFailed      // the store that answers a security question could not be read, so the door stayed shut
	CredentialAdded          // a person enrolled a credential (a passkey)
	CredentialRemoved        // a credential was removed
)

// Name is the OWASP Logging Vocabulary name of the kind ("authn_login_fail"); "" for a value that is not a kind.
func (k Kind) Name() string {
	switch k {
	case LoginSucceeded:
		return "authn_login_success"
	case LoginFailed:
		return "authn_login_fail"
	case LoginLocked:
		return "authn_login_lock"
	case RateLimited:
		return "excess_rate_limit_exceeded"
	case SessionInvalid:
		return "session_use_after_expire"
	case TokenForged:
		return "authn_token_forged"
	case TokenReused:
		return "authn_token_reuse"
	case AccessDenied:
		return "authz_fail"
	case InputRejected:
		return "input_validation_fail"
	case RequestTooLarge:
		return "excess_request_size"
	case ContentBlocked:
		return "malicious_content_blocked"
	case AdminCreated:
		return "authz_admin_created"
	case SetupRejected:
		return "authz_setup_rejected"
	case SecurityStoreFailed:
		return "sys_security_store_failed"
	case CredentialAdded:
		return "authn_credential_added"
	case CredentialRemoved:
		return "authn_credential_removed"
	}
	return ""
}

// Level is how serious the kind is for a log line or an alert: Info, Warning or Error.
func (k Kind) Level() msgtype.Type {
	switch k {
	case LoginSucceeded, CredentialAdded:
		return msgtype.Info
	case TokenForged, TokenReused, AccessDenied, ContentBlocked, SecurityStoreFailed:
		return msgtype.Error
	}
	return msgtype.Warning
}

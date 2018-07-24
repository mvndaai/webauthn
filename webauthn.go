package webauthn

import (
	"crypto/rand"
)

// NewChallenge creates a challenge that gets sent with every new registation and authentication
func NewChallenge() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return b, err
	}
	return b, nil
}

// These are types help know what kind of strings should be used in structs
type (
	// Base64EncodedString should be a string that can be decoded from Base64
	Base64EncodedString string

	// Domain
	Domain string
)

type (
	/// ToArrayBuffer are keys that need to be turned into an ArrayBuffer before passing the other object to navigator.credentials.create
	ToArrayBuffter struct {
		KeyPath string `json:"keyPath"`
		value   string `json:"value"`
	}

	RegistrationParts struct {
		ToArrayBuffter []ToArrayBuffter           `json:"toArrayBuffer"`
		PublicKey      PublicKeyCredentialOptions `json:"publicKey"`
	}

	// PublicKeyCredentialOptions credentails needed for
	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
	PublicKeyCredentialOptions struct {
	}

	//RpEntity is the Relying Party entity
	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
	// The ID is the hosts domain name - https://w3c.github.io/webauthn/#relying-party-identifier
	RpEntity struct {
		ID string `json:"id"`
	}
)

// TokenBindingStatus is an enum for TokenBindingStatus values
type TokenBindingStatus string

// Enum values of TokenBindingStatus
const (
	StatusPresent  TokenBindingStatus = "present"
	tatusSupported TokenBindingStatus = "supported"
)

type (
	// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party and the client platform
	// https://w3c.github.io/webauthn/#dictdef-collectedclientdata
	CollectedClientData struct {
		Type         string       `json:"type"`
		Challenge    string       `json:"challenge"`
		Origin       string       `json:"origin"`
		TokenBinding TokenBinding `json:"tokenBinding"`
	}

	// TokenBinding is an OPTIONAL member that contains information about the state of the Token Binding protocol used when communicating with the Relying Party. Its absence indicates that the client doesn’t support token binding.
	// https://w3c.github.io/webauthn/#dictdef-tokenbinding
	TokenBinding struct {
		ID     string             `json:"id"`
		Status TokenBindingStatus `json:"status"`
	}
)

package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"

	"github.com/ugorji/go/codec"
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
)

type (
	// Attestation Object that can be decoded from the response from `navigator.credentials.create()`
	// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/attestationObject
	Attestation struct {
		Fmt      string  `json:"fmt"`
		AuthData []byte  `json:"authData"`
		AttStmt  AttStmt `json:"attStmt"`
	}

	// AttStmt attestation statement
	AttStmt struct {
		Sig []uint8       `json:"sig"`
		X5c []interface{} `json:"x5c"`
	}
)

func base64Decode(s Base64EncodedString) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return data, err
	}
	return data, nil
}

// DecodeAttestation decodes a base64 CBOR encoded Attestation
func DecodeAttestation(s Base64EncodedString) (Attestation, error) {
	cbor := codec.CborHandle{}
	a := Attestation{}

	b, err := base64Decode(s)
	if err != nil {
		return a, err
	}

	err = codec.NewDecoder(bytes.NewReader(b), &cbor).Decode(&a)
	if err != nil {
		return a, err
	}
	return a, nil
}

type (
	// https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorResponse/clientDataJSON
	ClientData struct {
		Type      string `json:"type"`      // "webauthn.create" or "webauthn.get"
		Challenge string `json:"challenge"` // base64 encoded String containing the original challenge
		Origin    string `json:"origin"`    // the window.origin
	}
)

// DecodeClientData decode a client data from base64
func DecodeClientData(s Base64EncodedString) (ClientData, error) {
	c := ClientData{}
	b, err := base64Decode(s)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}

// IsValidRegistration checks to see if the information sent back was valid
// https://w3c.github.io/webauthn/#registering-a-new-credential
func IsValidRegistration() (bool, error) {
	return true, nil
}

type (
	// ToArrayBuffter are keys that need to be turned into an ArrayBuffer before passing the other object to navigator.credentials.create
	ToArrayBuffter struct {
		KeyPath []string `json:"keyPath"`
		Value   string   `json:"value"`
	}

	// RegistrationParts is the object sent back to the Javascript
	// The objects in ToArrayBuffer need to be decoded from base64 and and given as a buffered int array
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

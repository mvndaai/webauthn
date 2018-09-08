package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"

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

// Base64EncodedString should be a string that can be decoded from Base64
type Base64EncodedString string

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

// DecodeAttestation decodes a base64 CBOR encoded Attestation
func DecodeAttestation(s Base64EncodedString) (Attestation, error) {
	cbor := codec.CborHandle{}
	a := Attestation{}

	b, err := base64.StdEncoding.DecodeString(string(s))
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

	// TokenBindingStatus is an enum for TokenBindingStatus values
	TokenBindingStatus string
)

// Enum values of TokenBindingStatus
const (
	StatusPresent   TokenBindingStatus = "present"
	StatusSupported TokenBindingStatus = "supported"
)

// DecodeClientData decode client data from base64
func DecodeClientData(s Base64EncodedString) (CollectedClientData, error) {
	c := CollectedClientData{}
	b, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	return c, nil
}

// ParsedRegistrationResponse TODO
//{
// 	type: r.type,
// 	credentialId: webauthn.binToStr(r.rawId),
// 	clientDataJSON: webauthn.binToStr(r.response.clientDataJSON),
// 	attestationObject: webauthn.binToStr(r.response.attestationObject)
// }
type ParsedRegistrationResponse struct {
	Type              string              `json:"type"`
	CredentialID      Base64EncodedString `json:"credentialId"`
	ClientDataJSON    Base64EncodedString `json:"clientDataJSON"`
	AttestationObject Base64EncodedString `json:"attestationObject"`
}

// IsValidRegistration checks to see if the information sent back was valid
// https://w3c.github.io/webauthn/#registering-a-new-credential
func IsValidRegistration(p ParsedRegistrationResponse, originalChallenge []byte, relyingPartyOrigin string) (bool, error) {
	// log.Printf("\nParsedRegistrationResponse:\n%#v\n\n", p)
	// log.Printf("\noriginalChallenge:\n%#v\n\n", originalChallenge)

	c, err := DecodeClientData(p.ClientDataJSON)
	if err != nil {
		return false, err
	}
	log.Printf("ClientData:\n%#v\n\n", c)

	if err := ValidRegistrationClientData(c, originalChallenge, relyingPartyOrigin); err != nil {
		// return false, err
	}

	a, err := DecodeAttestation(p.AttestationObject)
	if err != nil {
		return false, err
	}
	log.Printf("AttestationObject:\n\n%#v\n", a)

	if err := ValidRegistartionAttestation(a, relyingPartyOrigin); err != nil {
		return false, err
	}

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
	//
	// dictionary PublicKeyCredentialCreationOptions {
	// 	required PublicKeyCredentialRpEntity         rp;
	// 	required PublicKeyCredentialUserEntity       user;
	//
	// 	required BufferSource                             challenge;
	// 	required sequence<PublicKeyCredentialParameters>  pubKeyCredParams;
	//
	// 	unsigned long                                timeout;
	// 	sequence<PublicKeyCredentialDescriptor>      excludeCredentials = [];
	// 	AuthenticatorSelectionCriteria               authenticatorSelection;
	// 	AttestationConveyancePreference              attestation = "none";
	// 	AuthenticationExtensionsClientInputs         extensions;
	// };
	PublicKeyCredentialOptions struct {
		RP               RpEntity     `json:"rp"`
		User             UserEntity   `json:"user"`
		PubKeyCredParams []Parameters `json:"pubKeyCredParams"`
		Timeout          uint         `json:"timeout"`
		// Exclude Credentials
		// authenticatorSelection - https://w3c.github.io/webauthn/#dictdef-authenticatorselectioncriteria
		Attestation AttestationConveyancePreference `json:"attestation"`
		// extensions
	}

	//RpEntity is the Relying Party entity
	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialrpentity
	RpEntity struct {
		// The ID is the hosts domain name - https://w3c.github.io/webauthn/#relying-party-identifier
		ID   string `json:"id,omitempty"` // In Spec, but not required in chrome
		Name string `json:"name"`         // Not in spec, but required in chrome

	}

	// UserEntity TODO
	UserEntity struct {
		ID          string `json:"id"`          // In Spec, but not required in chrome
		Name        string `json:"name"`        // Not in spec, but required in chrome
		DisplayName string `json:"displayName"` // Not in spec, but required in chrome

	}

	// Parameters TODO
	Parameters struct {
		// https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
		Type PublicKeyCredentialType `json:"type"`
		//https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
		Alg int `json:"alg"`
	}

	// PublicKeyCredentialType emun - https://w3c.github.io/webauthn/#enumdef-publickeycredentialtype
	PublicKeyCredentialType string

	// AttestationConveyancePreference enum - https://w3c.github.io/webauthn/#enumdef-attestationconveyancepreference
	AttestationConveyancePreference string
)

// PublicKeyCredentialType enumeration
const (
	PublicKeyCredentialTypePublicKey = "public-key"
)

// AttestationConveyancePreference enumeration
const (
	AttestationConveyancePreferenceNone     = "none"
	AttestationConveyancePreferenceIndirect = "indirect"
	AttestationConveyancePreferenceDirect   = "direct"
)

// BuildToArrayBuffer is a helper because there are keys in in the PublicKeyCredentionOptions that need to be of the type Buffer Source
// This is an array that includes the path for the variables and encodes the values as base64
// The values can be decoded in javascript by: Uint8Array.from(atob(value),c => c.charCodeAt(0)).buffer;
// https://heycam.github.io/webidl/#BufferSource
func BuildToArrayBuffer(challenge []byte, userID string) []ToArrayBuffter {
	return []ToArrayBuffter{
		ToArrayBuffter{
			KeyPath: []string{"publicKey", "user", "id"},
			Value:   base64.StdEncoding.EncodeToString(challenge),
		},
		ToArrayBuffter{
			KeyPath: []string{"publicKey", "challenge"},
			Value:   base64.StdEncoding.EncodeToString([]byte(userID)),
		},
	}
}

// ValidRegistrationClientData validates that the client data returned from authentication
// https://w3c.github.io/webauthn/#registering-a-new-credential
func ValidRegistrationClientData(c CollectedClientData, originalChallenge []byte, relyingPartyOrigin string) error {

	if c.Type != "webauthn.create" {
		return fmt.Errorf("Client Data Type '%s' was not '%s'", c.Type, "webauthn.create")
	}

	chal := base64.StdEncoding.EncodeToString(originalChallenge)
	if c.Challenge != chal {
		return fmt.Errorf("Base64 encoded Client Data Challenge was '%s' not '%s'", c.Challenge, chal)
	}

	if c.Origin != relyingPartyOrigin {
		return fmt.Errorf("Client Data Origin was '%s' not '%s'", c.Origin, relyingPartyOrigin)
	}

	// TODO
	// Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.
	// If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

	// TODO, but why?
	//Compute the hash of response.clientDataJSON using SHA-256.

	return nil
}

// ValidRegistartionAttestation TODO
func ValidRegistartionAttestation(a Attestation, relyingPartyOrigin string) error {
	// a.
	pad := ParseAuthData(a.AuthData)
	log.Printf("Parsed Auth Data %#v", pad)

	// Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.

	// Verify that the User Present bit of the flags in authData is set.

	// If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.

	return nil
}

/*
0 0000
1 0001
2 0010
3 0011
4 0100
5 0101
6 0110
7 0111
8 1000
9 1001
A 1010
B 1011
C 1100
D 1101
E 1110
F 1111
*/

type (
	// AuthenticatorData TODO
	AuthenticatorData struct {
		rpIDHash  string
		flags     AuthenticatorDataFlags
		signCount uint32
		//attestedCredentialData
		// extensions
	}

	// AuthenticatorDataFlags TODO
	AuthenticatorDataFlags struct {
		userPresent               bool
		userVerified              bool
		hasAttestedCredentialData bool
		hasExtensions             bool
	}
)

// Bit masks for authenticator data
const (
	AuthenticatorDataFlagBitMaskUserPresent       = 0x01 // 0000 0001
	AuthenticatorDataFlagBitMaskUserVerified      = 0x02 // 0000 0010
	AuthenticatorDataFlagBitMaskHasCredentialData = 0x40 // 0100 0000
	AuthenticatorDataFlagBitMaskHasExtension      = 0x80 // 1000 0000
)

// ParseAuthData takes the attestation auth data and gives back a what is needed to parse it
// https://w3c.github.io/webauthn/#sec-authenticator-data
func ParseAuthData(authData []byte) AuthenticatorData {
	log.Println("AuthData len", len(authData))

	d := AuthenticatorData{}
	d.rpIDHash = string(authData[0:31])

	f := AuthenticatorDataFlags{}
	fb := authData[32]
	fmt.Printf("%08b", byte(fb))

	f.userPresent = (fb & AuthenticatorDataFlagBitMaskUserPresent) == AuthenticatorDataFlagBitMaskUserPresent
	f.userVerified = (fb & AuthenticatorDataFlagBitMaskUserVerified) == AuthenticatorDataFlagBitMaskUserVerified
	f.hasAttestedCredentialData = (fb & AuthenticatorDataFlagBitMaskHasCredentialData) == AuthenticatorDataFlagBitMaskHasCredentialData
	f.hasExtensions = (fb & AuthenticatorDataFlagBitMaskHasExtension) == AuthenticatorDataFlagBitMaskHasExtension

	log.Println("signCount len", len(authData[33:37]))

	d.signCount = binary.BigEndian.Uint32(authData[33:37])
	// d.attestedCredentialData
	// d.extensions

	return d
}

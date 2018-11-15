package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/ugorji/go/codec"
)

// Base64EncodedString should be a string that can be decoded from Base64
type Base64EncodedString string

// Enum values of TokenBindingStatus
const (
	StatusPresent   TokenBindingStatus = "present"
	StatusSupported TokenBindingStatus = "supported"
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

// Bit masks for authenticator data
const (
	AuthenticatorDataFlagBitMaskUserPresent       = 0x01 // 0000 0001
	AuthenticatorDataFlagBitMaskUserVerified      = 0x04 // 0000 0100
	AuthenticatorDataFlagBitMaskHasCredentialData = 0x40 // 0100 0000
	AuthenticatorDataFlagBitMaskHasExtension      = 0x80 // 1000 0000
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

// ParseAuthData takes the attestation auth data and gives back a what is needed to parse it
// https://w3c.github.io/webauthn/#sec-authenticator-data
func ParseAuthData(authData []byte) AuthenticatorData {
	d := AuthenticatorData{}
	d.rpIDHash = string(authData[0:31])

	fb := authData[32]
	d.flags.userPresent = (fb & AuthenticatorDataFlagBitMaskUserPresent) == AuthenticatorDataFlagBitMaskUserPresent
	d.flags.userVerified = (fb & AuthenticatorDataFlagBitMaskUserVerified) == AuthenticatorDataFlagBitMaskUserVerified
	d.flags.hasAttestedCredentialData = (fb & AuthenticatorDataFlagBitMaskHasCredentialData) == AuthenticatorDataFlagBitMaskHasCredentialData
	d.flags.hasExtensions = (fb & AuthenticatorDataFlagBitMaskHasExtension) == AuthenticatorDataFlagBitMaskHasExtension

	d.signCount = binary.BigEndian.Uint32(authData[33:37])
	// d.attestedCredentialData //TODO
	// d.extensions //TODO
	return d
}

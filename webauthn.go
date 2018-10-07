package webauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
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

type (
	// ToArrayBuffter are keys that need to be turned into an ArrayBuffer before passing the other object to navigator.credentials.create
	ToArrayBuffter struct {
		KeyPath []string `json:"keyPath"`
		Value   string   `json:"value"`
	}

	// RegistrationParts is the object sent back to the Javascript
	// The objects in ToArrayBuffer need to be decoded from base64 and and given as a buffered int array
	RegistrationParts struct {
		// ToArrayBuffter []ToArrayBuffter           `json:"toArrayBuffer"`
		PublicKey PublicKeyCredentialOptions `json:"publicKey"`
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

		// This will need to be changed to an ArrayBuffer in JavaScript
		Challenge []byte `json:"challenge"`
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
		ID          []byte `json:"id"`          // In Spec, but not required in chrome
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
	AuthenticatorDataFlagBitMaskUserVerified      = 0x04 // 0000 0100
	AuthenticatorDataFlagBitMaskHasCredentialData = 0x40 // 0100 0000
	AuthenticatorDataFlagBitMaskHasExtension      = 0x80 // 1000 0000
)

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

// PublicKeyCredentialResponse from the response of a navigator.credentials.create/navigator.credentials.get;
type (
	PublicKeyCredentialResponse struct {
		// Used in registration
		ClientDataJSON    Base64EncodedString `json:"clientDataJSON"`
		AttestationObject Base64EncodedString `json:"attestationObject"`

		// Used in authentication
		AuthenticatorData Base64EncodedString `json:"authenticatorData"`
		Signature         Base64EncodedString `json:"signature"`
		UserHandle        Base64EncodedString `json:"userHandle"`
	}

	//PublicKeyCredential - https://w3c.github.io/webauthn/#publickeycredential
	PublicKeyCredential struct {
		ID       string                      `json:"id"`
		RawID    Base64EncodedString         `json:"rawId"`
		Response PublicKeyCredentialResponse `json:"response"`
		Type     string                      `json:"type"`
	}
)

// ValidateRegistration checks to see if the information sent back was valid vial 19 steps
// https://w3c.github.io/webauthn/#registering-a-new-credential
func ValidateRegistration(p PublicKeyCredential, originalChallenge []byte, relyingPartyOrigin string, userVerificationRequired bool) error {
	log.Println("*WARNING* WebAuthN registration validation is not yet complete")

	// Steps 1 & 2
	// Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
	// Note: Using any implementation of UTF-8 decode is acceptable as long as it yields the same result as that yielded by the UTF-8 decode algorithm. In particular, any leading byte order mark (BOM) MUST be stripped.
	// Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
	// Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
	c, err := DecodeClientData(p.Response.ClientDataJSON)
	if err != nil {
		return err
	}

	// Step 3
	// Verify that the value of C.type is webauthn.create.
	if c.Type != "webauthn.create" {
		return fmt.Errorf("Client Data Type '%s' was not '%s'", c.Type, "webauthn.create")
	}

	// Step 4
	// Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.
	chal := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(originalChallenge)
	if c.Challenge != chal {
		return fmt.Errorf("base64url encoded challenge did not match - ClientData '%s' - original '%s'", c.Challenge, chal)
	}

	// Step 5
	// Verify that the value of C.origin matches the Relying Party's origin.
	if c.Origin != relyingPartyOrigin {
		return fmt.Errorf("Client Data Origin was '%s' not '%s'", c.Origin, relyingPartyOrigin)
	}

	//TODO
	// Step 6
	// Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.
	// If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

	// Step 7
	// Compute the hash of response.clientDataJSON using SHA-256.
	// h := sha256.New()
	// h.Write([]byte(p.Response.ClientDataJSON))
	// clientDataSha256 := fmt.Sprintf("%x", h.Sum(nil))
	// log.Println("clientDataSha256", clientDataSha256)
	//TODO figure out what to do with this

	// Step 8
	// Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
	a, err := DecodeAttestation(p.Response.AttestationObject)
	if err != nil {
		return err
	}

	// Step 9
	// Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the Relying Party.
	// parsedAuthData.rpIDHash

	// Step 10
	parsedAuthData := ParseAuthData(a.AuthData)
	if !parsedAuthData.flags.userPresent {
		return errors.New("the User Present bit of the flags in authData is not set")
	}

	// Step 11
	// Verify that the User Present bit of the flags in authData is set.
	if userVerificationRequired {
		if !parsedAuthData.flags.userVerified {
			return errors.New("user verification is required for this registration and the User Verified bit of the flags in authData is not set")
		}
	}

	// TODO
	// Step 12
	// Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	// Note: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST be prepared to handle cases where none or not all of the requested extensions were acted upon.

	// TODO
	// Step 13
	// Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].

	// TODO
	// Step 14
	// Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.

	// TODO
	// Step 15
	// If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.

	// TODO
	// Step 16
	//Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:
	//	If self attestation was used, check if self attestation is acceptable under Relying Party policy.
	//	If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.
	//	Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.

	// TODO
	// Step 17
	// Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.

	// TODO
	// Step 18
	// If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.

	// TODO
	// Step 19
	// If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.
	// NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.4.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.

	// Verification of attestation objects requires that the Relying Party has a trusted method of determining acceptable trust anchors in step 15 above. Also, if certificates are being used, the Relying Party MUST have access to certificate status information for the intermediate CA certificates. The Relying Party MUST also be able to build the attestation certificate chain if the client did not provide this chain in the attestation information.

	return nil
}

// ValidateAuthentication performs the 18 step validation on on a parse response from navigator.credentials.get
// https://w3c.github.io/webauthn/#verifying-assertion
func ValidateAuthentication(p PublicKeyCredential, originalChallenge []byte, relyingPartyOrigin, userID string) error {
	log.Println("*WARNING* WebAuthN athentication validation is not yet complete")

	// Step 1
	// If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.
	// log.Println("p.ID", p.ID)

	// Step 2
	// If credential.response.userHandle is present, verify that the user identified by this value is the owner of the public key credential identified by credential.id.
	if userID != "" {
		userHandle, err := base64.StdEncoding.DecodeString(string(p.Response.UserHandle))
		if err != nil {
			return err
		}
		if userID != string(userHandle) {
			return fmt.Errorf("user handle decoded to '%v' when '%v' was expected", string(userHandle), userID)
		}
	}

	// Step 3
	//Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.

	// a, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(p.ID)
	// if err != nil {
	// 	return err
	// }
	// log.Println("abc", string(a))

	// Step 4
	// Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.

	// Step 5
	// Let JSONtext be the result of running UTF-8 decode on the value of cData.
	// Note: Using any implementation of UTF-8 decode is acceptable as long as it yields the same result as that yielded by the UTF-8 decode algorithm. In particular, any leading byte order mark (BOM) MUST be stripped.

	// Step 6
	// Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
	// Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
	c, err := DecodeClientData(p.Response.ClientDataJSON)
	if err != nil {
		return err
	}

	// Step 7
	// Verify that the value of C.type is the string webauthn.get.
	if c.Type != "webauthn.get" {
		return fmt.Errorf("Client Data Type '%s' was not '%s'", c.Type, "webauthn.get")
	}

	// Step 8
	// Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
	chal := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(originalChallenge)
	if c.Challenge != chal {
		return fmt.Errorf("base64url encoded challenge did not match - ClientData '%s' - original '%s'", c.Challenge, chal)
	}

	// Step 9
	// Verify that the value of C.origin matches the Relying Party's origin.
	if c.Origin != relyingPartyOrigin {
		return fmt.Errorf("Client Data Origin was '%s' not '%s'", c.Origin, relyingPartyOrigin)
	}

	// Step 10
	// Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

	// Step 11
	// Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.

	// Step 12
	// Verify that the User Present bit of the flags in authData is set.

	// Step 13
	// If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.

	// Step 14
	// Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the clientExtensionResults and the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
	// Note: Since all extensions are OPTIONAL for both the client and the authenticator, the Relying Party MUST be prepared to handle cases where none or not all of the requested extensions were acted upon.

	// Step 15
	// Let hash be the result of computing a hash over the cData using SHA-256.

	// Step 16
	// Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of authData and hash.
	// Note: This verification step is compatible with signatures generated by FIDO U2F authenticators. See §6.1.2 FIDO U2F Signature Format Compatibility.

	// Step 17
	// If the signature counter value authData.signCount is nonzero or the value stored in conjunction with credential’s id attribute is nonzero, then run the following sub-step:
	// If the signature counter value authData.signCount is greater than the signature counter value stored in conjunction with credential’s id attribute.
	// Update the stored signature counter value, associated with credential’s id attribute, to be the value of authData.signCount.
	// less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
	// This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in parallel. Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates the stored signature counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.

	// Step 18
	// If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.

	return nil
}

package webauthn

type (
	// RegistrationParts is the object sent back to the Javascript
	RegistrationParts struct {
		PublicKey PublicKeyCredentialOptions `json:"publicKey"`
	}

	// PublicKeyCredentialOptions credentails needed for
	// https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptions
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

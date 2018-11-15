package webauthn

import (
	"encoding/base64"
	"fmt"
	"log"
)

// ValidateAuthentication performs the 18 step validation on on a parse response from navigator.credentials.get
// https://w3c.github.io/webauthn/#verifying-assertion
func ValidateAuthentication(p PublicKeyCredential, originalChallenge []byte, relyingPartyOrigin, userID string) error {
	log.Println("*WARNING* WebAuthn athentication validation is not yet complete")

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
		if string(userHandle) != "" {
			if userID != string(userHandle) {
				return fmt.Errorf("user handle decoded to '%v' when '%v' was expected", string(userHandle), userID)
			}
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

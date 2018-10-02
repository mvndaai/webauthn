package webauthn_test

import (
	"testing"

	"github.com/mvndaai/webauthn"
)

func TestValidateRegistration(t *testing.T) {

	orginialPK := webauthn.RegistrationParts{
		PublicKey: webauthn.PublicKeyCredentialOptions{
			RP: webauthn.RpEntity{
				ID:   "",
				Name: "mvndaai-webauth-demo",
			},
			User: webauthn.UserEntity{
				ID:          []uint8{0x66, 0x37, 0x35, 0x39, 0x62, 0x63, 0x62, 0x39, 0x2d, 0x64, 0x32, 0x36, 0x37, 0x2d, 0x34, 0x35, 0x38, 0x34, 0x2d, 0x38, 0x33, 0x38, 0x34, 0x2d, 0x37, 0x64, 0x32, 0x31, 0x33, 0x30, 0x61, 0x62, 0x62, 0x62, 0x38, 0x30},
				Name:        "mvndaai",
				DisplayName: "Jason",
			},
			PubKeyCredParams: []webauthn.Parameters{
				webauthn.Parameters{
					Type: "public-key",
					Alg:  -7,
				},
			},
			Timeout:     0xc350,
			Attestation: "direct",
			Challenge:   []uint8{0x55, 0x7d, 0x4a, 0xb8, 0xf4, 0x7d, 0xb3, 0xea, 0xdf, 0xcb, 0xb2, 0x60, 0xa9, 0xb, 0xee, 0x84, 0x59, 0xfd, 0x63, 0x23, 0xaf, 0x32, 0xca, 0x54, 0x52, 0x9b, 0x68, 0xd, 0x6a, 0x5f, 0xbf, 0x16},
		},
	}

	afterPKC := webauthn.PublicKeyCredential{
		ID:    "AJztaPxN3I_DCw30edzNrYIcTlOzh0WG59Qp-sZXDkBu2qU_BgvQb3tpT_XKX1ab_Pl-m7uFiOTFAjmHt37ABlkaIQvVnlF8-W2KwcsknIyLQA",
		RawID: "AJztaPxN3I/DCw30edzNrYIcTlOzh0WG59Qp+sZXDkBu2qU/BgvQb3tpT/XKX1ab/Pl+m7uFiOTFAjmHt37ABlkaIQvVnlF8+W2KwcsknIyLQA==",
		Response: webauthn.PublicKeyCredentialResponse{
			ClientDataJSON:    "eyJjaGFsbGVuZ2UiOiJWWDFLdVBSOXMtcmZ5N0pncVF2dWhGbjlZeU92TXNwVVVwdG9EV3BmdnhZIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
			AttestationObject: "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEYwRAIgBnylNnbjHtaCgXvhEdhs+B7Cx1ZAOAvJWbGA86ODjuYCICfEIzIff0gIEMGdfVTidDD6El+XPbpeN2Yrj8MAPyKKaGF1dGhEYXRhWNZJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0VbsufKrc4AAjW8xgpkiwsl8fBVAwBSAJztaPxN3I/DCw30edzNrYIcTlOzh0WG59Qp+sZXDkBu2qU/BgvQb3tpT/XKX1ab/Pl+m7uFiOTFAjmHt37ABlkaIQvVnlF8+W2KwcsknIyLQKUBAgMmIAEhWCB8Sc9mlD/qPEjXi/ZlH+A7NVXRyFW4tvBr0CrqQ7WmOyJYIFLJaFoUaxeezPhkQHVsfXeZoDJdjFEEcuMabXu2l4uJ",
			AuthenticatorData: "",
			Signature:         "",
			UserHandle:        "",
		},
		Type: "public-key",
	}

	err := webauthn.ValidateRegistration(afterPKC, orginialPK.PublicKey.Challenge, "http://localhost:8080", true)
	if err != nil {
		t.Error(err)
		// t.Error("Hello", orginialPK, afterPKC)
	}
}

package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVAPID(t *testing.T) {
	s := getStandardEncodedTestSubscription()
	sub := "test@test.com"

	// Generate vapid keys
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	// Get authentication header
	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		sub,
		vapidKeys,
		time.Now().Add(time.Hour*12),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Validate the token in the Authorization header
	tokenString := getTokenFromAuthorizationHeader(vapidAuthHeader, t)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatal("Wrong validation method need ECDSA!")
		}

		// To decode the token it needs the VAPID public key
		return vapidKeys.privateKey.Public(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Check the claims on the token
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expectedSub := fmt.Sprintf("mailto:%s", sub)
		if expectedSub != claims["sub"] {
			t.Fatalf(
				"Incorrect mailto, expected=%s, got=%s",
				expectedSub,
				claims["sub"],
			)
		}

		if claims["aud"] == "" {
			t.Fatal("Audience should not be empty")
		}
	} else {
		t.Fatal(err)
	}

}

func TestVAPIDKeys(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	j, err := json.Marshal(vapidKeys)
	if err != nil {
		t.Fatal(err)
	}

	vapidKeys2 := new(VAPIDKeys)
	if err := json.Unmarshal(j, vapidKeys2); err != nil {
		t.Fatal(err)
	}

	if !vapidKeys.privateKey.Equal(vapidKeys2.privateKey) {
		t.Fatalf("could not round-trip private key")
	}

	if vapidKeys.publicKey != vapidKeys2.publicKey {
		t.Fatalf("could not round-trip public key")
	}
}

// Helper function for extracting the token from the Authorization header
func getTokenFromAuthorizationHeader(tokenHeader string, t *testing.T) string {
	hsplit := strings.Split(tokenHeader, " ")
	if len(hsplit) < 3 {
		t.Fatal("Failed to auth split header")
	}

	tsplit := strings.Split(hsplit[1], "=")
	if len(tsplit) < 2 {
		t.Fatal("Failed to t split header on =")
	}

	return tsplit[1][:len(tsplit[1])-1]
}

func TestVAPIDKeyFromECDSA(t *testing.T) {
	v, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	privKey := v.PrivateKey()
	v2, err := ECDSAToVAPIDKeys(privKey)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Equal(v2) {
		t.Fatal("ECDSAToVAPIDKeys failed round-trip")
	}
}

func TestVAPIDKeysEqual_NilSafety(t *testing.T) {
	var nilKeys *VAPIDKeys
	if !nilKeys.Equal(nil) {
		t.Fatalf("expected nil keys to compare equal to nil")
	}

	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	if nilKeys.Equal(keys) {
		t.Fatalf("expected nil keys to compare unequal to non-nil keys")
	}
	if keys.Equal(nil) {
		t.Fatalf("expected non-nil keys to compare unequal to nil")
	}

	var zeroA, zeroB VAPIDKeys
	if !zeroA.Equal(&zeroB) {
		t.Fatalf("expected zero-value keys to compare equal")
	}
	if zeroA.Equal(keys) {
		t.Fatalf("expected zero-value keys to compare unequal to initialized keys")
	}
}

func TestVAPID_UnmarshalJSONErrors(t *testing.T) {
	cases := []struct {
		name    string
		jsonStr string
		errSub  string
	}{
		{
			name:    "missingPrivateKey",
			jsonStr: `{"publicKey":"abc"}`,
			errSub:  "privateKey is required",
		},
		{
			name:    "invalidBase64",
			jsonStr: `{"privateKey":"??not-base64??"}`,
			errSub:  "invalid privateKey encoding",
		},
		{
			name: "invalidLength",
			jsonStr: func() string {
				short := base64.RawURLEncoding.EncodeToString([]byte{1, 2}) // len=2, needs 32
				return `{"privateKey":"` + short + `"}`
			}(),
			errSub: "invalid privateKey length",
		},
	}
	for _, tc := range cases {
		c := tc
		t.Run(c.name, func(t *testing.T) {
			var v VAPIDKeys
			err := json.Unmarshal([]byte(c.jsonStr), &v)
			if err == nil || !strings.Contains(err.Error(), c.errSub) {
				t.Fatalf("expected error containing %q, got: %v", c.errSub, err)
			}
		})
	}

	// Mismatched public key case requires a valid 32-byte scalar
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	d := keys.PrivateKey().D.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(d):], d)
	privB64 := base64.RawURLEncoding.EncodeToString(padded)
	badPub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	payload := `{"publicKey":"` + badPub + `","privateKey":"` + privB64 + `"}`
	var v VAPIDKeys
	if err := json.Unmarshal([]byte(payload), &v); err == nil || !strings.Contains(err.Error(), "publicKey does not match") {
		t.Fatalf("expected mismatched publicKey error, got: %v", err)
	}
}

func TestVAPID_MarshalJSON_NilReceiver(t *testing.T) {
	var v *VAPIDKeys
	if _, err := v.MarshalJSON(); err == nil {
		t.Fatalf("expected error when marshaling nil VAPIDKeys via method")
	}
}

func TestVAPID_GetAuthorizationHeader(t *testing.T) {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	// invalid URL
	if _, err := getVAPIDAuthorizationHeader(":// malformed", "user@example.com", keys, time.Now()); err == nil {
		t.Fatalf("expected error for invalid endpoint URL")
	}
	// HTTPS subscriber should be accepted and produce a header
	hdr, err := getVAPIDAuthorizationHeader("https://push.example/v2/token", "https://application.server", keys, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if hdr == "" || !strings.HasPrefix(hdr, "vapid ") {
		t.Fatalf("expected non-empty vapid header, got: %q", hdr)
	}
}

func TestVAPID_PEMExportLoad(t *testing.T) {
	// Nil receiver export
	var nilKeys *VAPIDKeys
	if _, err := nilKeys.ExportVAPIDPrivateKeyPEM(); err == nil {
		t.Fatalf("expected error when exporting nil keys")
	}

	// Round-trip export/load
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := keys.ExportVAPIDPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadVAPIDPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Equal(loaded) {
		t.Fatalf("PEM round-trip did not preserve keys")
	}

	// Error cases for LoadVAPIDPrivateKeyPEM
	t.Run("invalidPEM", func(t *testing.T) {
		if _, err := LoadVAPIDPrivateKeyPEM([]byte("not pem")); err == nil {
			t.Fatalf("expected error for invalid PEM input")
		}
	})

	t.Run("rsaKey", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		if _, err := LoadVAPIDPrivateKeyPEM(pemBytes); err == nil {
			t.Fatalf("expected error for non-ECDSA private key")
		}
	})

	t.Run("wrongCurveP384", func(t *testing.T) {
		p384key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(p384key)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		if _, err := LoadVAPIDPrivateKeyPEM(pemBytes); err == nil {
			t.Fatalf("expected error for wrong ECDSA curve")
		}
	})
}

func TestECDSAToVAPIDKeys_InvalidCurve(t *testing.T) {
	if _, err := ECDSAToVAPIDKeys(nil); err == nil {
		t.Fatalf("expected error for nil private key in ECDSAToVAPIDKeys")
	}

	p384key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ECDSAToVAPIDKeys(p384key); err == nil {
		t.Fatalf("expected error for invalid curve in ECDSAToVAPIDKeys")
	}
}

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
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVAPID(t *testing.T) {
	s := getStandardEncodedTestSubscription()
	subject := "test@test.com"

	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		subject,
		vapidKeys,
		time.Now().Add(12*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}

	tokenString := getTokenFromAuthorizationHeader(vapidAuthHeader, t)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			t.Fatal("wrong validation method need ECDSA")
		}
		return vapidKeys.privateKey.Public(), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expectedSub := fmt.Sprintf("mailto:%s", subject)
		if expectedSub != claims["sub"] {
			t.Fatalf("incorrect mailto, expected=%s, got=%s", expectedSub, claims["sub"])
		}
		if claims["aud"] == "" {
			t.Fatal("audience should not be empty")
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

func getTokenFromAuthorizationHeader(tokenHeader string, t *testing.T) string {
	hsplit := strings.Split(tokenHeader, " ")
	if len(hsplit) < 3 {
		t.Fatal("failed to auth split header")
	}

	tsplit := strings.Split(hsplit[1], "=")
	if len(tsplit) < 2 {
		t.Fatal("failed to t split header on =")
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
				short := base64.RawURLEncoding.EncodeToString([]byte{1, 2})
				return `{"privateKey":"` + short + `"}`
			}(),
			errSub: "invalid privateKey length",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var v VAPIDKeys
			err := json.Unmarshal([]byte(tc.jsonStr), &v)
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("expected error containing %q, got: %v", tc.errSub, err)
			}
		})
	}

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
	if _, err := getVAPIDAuthorizationHeader(":// malformed", "user@example.com", keys, time.Now()); err == nil {
		t.Fatalf("expected error for invalid endpoint URL")
	}
	hdr, err := getVAPIDAuthorizationHeader("https://push.example/v2/token", "https://application.server", keys, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if hdr == "" || !strings.HasPrefix(hdr, "vapid ") {
		t.Fatalf("expected non-empty vapid header, got: %q", hdr)
	}
}

func TestVAPID_SubjectValidation(t *testing.T) {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		subject string
		wantErr error
	}{
		{name: "empty", subject: "", wantErr: ErrInvalidSubject},
		{name: "mailtoMissingAddress", subject: "mailto:", wantErr: ErrInvalidSubject},
		{name: "httpURL", subject: "http://example.com", wantErr: ErrInvalidSubject},
		{name: "nonsense", subject: "not a subject", wantErr: ErrInvalidSubject},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := getVAPIDAuthorizationHeader("https://push.example/v2/token", tc.subject, keys, time.Now().Add(time.Hour))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestVAPID_SubjectNormalization(t *testing.T) {
	got, err := normalizeSubject("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "mailto:user@example.com" {
		t.Fatalf("expected mailto normalization, got %q", got)
	}

	got, err = normalizeSubject("mailto:user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "mailto:user@example.com" {
		t.Fatalf("expected mailto subject, got %q", got)
	}

	got, err = normalizeSubject("https://example.com/contact")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/contact" {
		t.Fatalf("expected https subject, got %q", got)
	}
}

func TestVAPID_ExpirationValidation(t *testing.T) {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, err = getVAPIDAuthorizationHeader("https://push.example/v2/token", "user@example.com", keys, time.Now().Add(-time.Minute))
	if !errors.Is(err, ErrInvalidExpiration) {
		t.Fatalf("expected invalid expiration error, got: %v", err)
	}

	_, err = getVAPIDAuthorizationHeader("https://push.example/v2/token", "user@example.com", keys, time.Now().Add(25*time.Hour))
	if !errors.Is(err, ErrInvalidExpiration) {
		t.Fatalf("expected invalid expiration error, got: %v", err)
	}

	_, err = getVAPIDAuthorizationHeader("https://push.example/v2/token", "user@example.com", keys, time.Time{})
	if err != nil {
		t.Fatalf("expected zero expiration default to succeed, got: %v", err)
	}
}

func TestVAPID_MissingKeys(t *testing.T) {
	_, err := getVAPIDAuthorizationHeader("https://push.example/v2/token", "user@example.com", nil, time.Now().Add(time.Hour))
	if !errors.Is(err, ErrMissingVAPIDKeys) {
		t.Fatalf("expected missing keys error, got: %v", err)
	}
}

func TestVAPID_PEMExportLoad(t *testing.T) {
	var nilKeys *VAPIDKeys
	if _, err := nilKeys.ExportVAPIDPrivateKeyPEM(); err == nil {
		t.Fatalf("expected error when exporting nil keys")
	}

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
		_, err = LoadVAPIDPrivateKeyPEM(pemBytes)
		if err == nil || !strings.Contains(err.Error(), "*rsa.PrivateKey") {
			t.Fatalf("expected real key type in error, got: %v", err)
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

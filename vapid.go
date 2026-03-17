package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VAPIDKeys is a public-private keypair for use in VAPID.
type VAPIDKeys struct {
	privateKey *ecdsa.PrivateKey
	publicKey  string // raw bytes encoding in urlsafe base64, as per RFC
}

// PublicKeyString returns the base64url-encoded uncompressed public key of the keypair, as defined in RFC8292.
func (v *VAPIDKeys) PublicKeyString() string {
	return v.publicKey
}

// PrivateKey returns the private key of the keypair.
func (v *VAPIDKeys) PrivateKey() *ecdsa.PrivateKey {
	return v.privateKey
}

// Equal compares two VAPIDKeys for equality.
func (v *VAPIDKeys) Equal(o *VAPIDKeys) bool {
	if v == nil || o == nil {
		return v == nil && o == nil
	}
	if v.privateKey == nil || o.privateKey == nil {
		return v.privateKey == nil && o.privateKey == nil && v.publicKey == o.publicKey
	}
	return v.privateKey.Equal(o.privateKey)
}

// MarshalJSON implements json.Marshaler producing Web-push–style JSON:
//
//	{"publicKey":"<base64url>", "privateKey":"<base64url>"}
//
// The publicKey is the uncompressed EC point (65 bytes) base64url-encoded.
// The privateKey is the 32-byte big-endian scalar base64url-encoded.
func (v *VAPIDKeys) MarshalJSON() ([]byte, error) {
	if v == nil || v.privateKey == nil {
		return nil, fmt.Errorf("vapid keys are nil")
	}
	// 32-byte big-endian private scalar
	d := v.privateKey.D.Bytes()
	if len(d) > 32 {
		return nil, fmt.Errorf("invalid private key size: %d", len(d))
	}
	padded := make([]byte, 32)
	copy(padded[32-len(d):], d)
	privB64 := base64.RawURLEncoding.EncodeToString(padded)
	payload := struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}{
		PublicKey:  v.publicKey,
		PrivateKey: privB64,
	}
	return json.Marshal(payload)
}

// UnmarshalJSON implements json.Unmarshaler accepting only Web-push–style JSON
// ({"publicKey":"...","privateKey":"..."}). PublicKey is ignored if present.
func (v *VAPIDKeys) UnmarshalJSON(b []byte) error {
	type vapidJSON struct {
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
	}
	var obj vapidJSON
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	if obj.PrivateKey == "" {
		return fmt.Errorf("privateKey is required")
	}
	// Decode the private key (base64url)
	privBytes, err := base64.RawURLEncoding.DecodeString(obj.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid privateKey encoding: %w", err)
	}
	if len(privBytes) != 32 {
		return fmt.Errorf("invalid privateKey length: %d", len(privBytes))
	}
	// Build ecdsa.PrivateKey on P-256
	curve := elliptic.P256()
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = new(big.Int).SetBytes(privBytes)
	x, y := curve.ScalarBaseMult(privBytes)
	priv.PublicKey = ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	pubStr, err := makePublicKeyString(priv)
	if err != nil {
		return err
	}
	if obj.PublicKey != "" && obj.PublicKey != pubStr {
		return fmt.Errorf("publicKey does not match privateKey")
	}
	v.privateKey = priv
	v.publicKey = pubStr
	return nil
}

// GenerateVAPIDKeys generates a VAPID keypair (an ECDSA keypair on the P-256 curve).
func GenerateVAPIDKeys() (result *VAPIDKeys, err error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	pubKeyECDH, err := private.PublicKey.ECDH()
	if err != nil {
		return
	}
	publicKey := base64.RawURLEncoding.EncodeToString(pubKeyECDH.Bytes())

	return &VAPIDKeys{
		privateKey: private,
		publicKey:  publicKey,
	}, nil
}

// ECDSAToVAPIDKeys wraps an existing ecdsa.PrivateKey in VAPIDKeys for use in VAPID header signing.
func ECDSAToVAPIDKeys(privKey *ecdsa.PrivateKey) (result *VAPIDKeys, err error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if privKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("invalid curve for private key %v", privKey.Curve)
	}
	publicKeyString, err := makePublicKeyString(privKey)
	if err != nil {
		return nil, err
	}
	return &VAPIDKeys{
		privateKey: privKey,
		publicKey:  publicKeyString,
	}, nil
}

func makePublicKeyString(privKey *ecdsa.PrivateKey) (result string, err error) {
	// to get the raw bytes, we have to convert the public key to *ecdh.PublicKey
	// this type assertion (from the crypto.PublicKey returned by (*ecdsa.PrivateKey).Public()
	// to *ecdsa.PublicKey) cannot fail:
	publicKey, err := privKey.Public().(*ecdsa.PublicKey).ECDH()
	if err != nil {
		return // should not be possible if we confirmed P256 already
	}
	return base64.RawURLEncoding.EncodeToString(publicKey.Bytes()), nil
}

func getVAPIDAuthorizationHeader(
	endpoint string,
	subject string,
	vapidKeys *VAPIDKeys,
	expiration time.Time,
) (string, error) {
	if vapidKeys == nil || vapidKeys.privateKey == nil {
		return "", ErrMissingVAPIDKeys
	}
	if expiration.IsZero() {
		expiration = time.Now().Add(time.Hour * 12)
	}
	now := time.Now()
	if expiration.Before(now) {
		return "", fmt.Errorf("%w: must not be in the past", ErrInvalidExpiration)
	}
	if expiration.After(now.Add(24 * time.Hour)) {
		return "", fmt.Errorf("%w: must be within 24 hours", ErrInvalidExpiration)
	}

	// Create the JWT token
	subURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	normalizedSubject, err := normalizeSubject(subject)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": subURL.Scheme + "://" + subURL.Host,
		"exp": expiration.Unix(),
		"sub": normalizedSubject,
	})

	jwtString, err := token.SignedString(vapidKeys.privateKey)
	if err != nil {
		return "", err
	}

	return "vapid t=" + jwtString + ", k=" + vapidKeys.publicKey, nil
}

// ExportVAPIDPrivateKeyPEM writes the private key in PKCS#8 PEM format to the specified file.
// The public key can be obtained later via PublicKeyString.
func (v *VAPIDKeys) ExportVAPIDPrivateKeyPEM() ([]byte, error) {
	if v == nil || v.privateKey == nil {
		return nil, fmt.Errorf("vapid keys are nil")
	}
	pkcs8bytes, err := x509.MarshalPKCS8PrivateKey(v.privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal VAPID keys to PKCS#8: %w", err)
	}
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8bytes}
	pemBytes := pem.EncodeToMemory(pemBlock)
	if pemBytes == nil {
		return nil, fmt.Errorf("could not encode VAPID keys as PEM")
	}
	return pemBytes, nil
}

// LoadVAPIDPrivateKeyPEM reads a PKCS#8 PEM-encoded private key returns VAPIDKeys.
func LoadVAPIDPrivateKeyPEM(pemBytes []byte) (*VAPIDKeys, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("could not decode PEM block with VAPID keys")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid type of private key %T", privKey)
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("invalid curve for private key %v", privateKey.Curve)
	}
	pub, err := makePublicKeyString(privateKey)
	if err != nil {
		return nil, err
	}
	return &VAPIDKeys{privateKey: privateKey, publicKey: pub}, nil
}

func normalizeSubject(subject string) (string, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", fmt.Errorf("%w: subject is required", ErrInvalidSubject)
	}
	if strings.HasPrefix(subject, "mailto:") {
		addr := strings.TrimPrefix(subject, "mailto:")
		if _, err := mail.ParseAddress(addr); err != nil {
			return "", fmt.Errorf("%w: invalid mailto address", ErrInvalidSubject)
		}
		return "mailto:" + addr, nil
	}
	if strings.Contains(subject, "://") {
		u, err := url.Parse(subject)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return "", fmt.Errorf("%w: must be an https URL", ErrInvalidSubject)
		}
		return u.String(), nil
	}
	if _, err := mail.ParseAddress(subject); err == nil {
		return "mailto:" + subject, nil
	}
	return "", fmt.Errorf("%w: must be an email, mailto: URI, or https URL", ErrInvalidSubject)
}

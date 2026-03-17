package webpush

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const MaxRecordSize uint32 = 4096

var (
	ErrRecordSizeTooSmall = errors.New("record size too small for message")
	ErrInvalidSubject     = errors.New("invalid subject")
	ErrInvalidTopic       = errors.New("invalid topic")
	ErrInvalidExpiration  = errors.New("invalid VAPID expiration")
	ErrMissingVAPIDKeys   = errors.New("missing VAPID keys")

	invalidAuthKeyLength = errors.New("invalid auth key length (must be 16)")

	defaultHTTPClient HTTPClient = &http.Client{}
)

// HTTPClient is an interface for sending the notification HTTP request / testing
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Options are config and extra params needed to send a notification
type Options struct {
	HTTPClient      HTTPClient // Will replace it with *http.Client by default if not included
	RecordSize      uint32     // Limit the record size
	Subject         string     // Subject for the VAPID JWT token: email, mailto: URL, or HTTPS URL
	Topic           string     // Set the Topic header to collapse pending messages (Optional)
	TTL             int        // Set the TTL on the endpoint POST request, in seconds
	Urgency         Urgency    // Set the Urgency header to change a message priority (Optional)
	VAPIDKeys       *VAPIDKeys // VAPID public-private keypair to generate the VAPID Authorization header
	VAPIDExpiration time.Time  // Optional expiration for the VAPID JWT token (defaults to now + 12 hours)
}

// Keys represent a subscription's keys (its ECDH public key on the P-256 curve
// and its 16-byte authentication secret).
type Keys struct {
	Auth   [16]byte
	P256dh *ecdh.PublicKey
}

// Equal compares two Keys for equality.
func (k *Keys) Equal(o Keys) bool {
	if k.Auth != o.Auth {
		return false
	}
	if k.P256dh == nil || o.P256dh == nil {
		return k.P256dh == nil && o.P256dh == nil
	}
	return k.P256dh.Equal(o.P256dh)
}

var _ json.Marshaler = (*Keys)(nil)
var _ json.Unmarshaler = (*Keys)(nil)

type marshaledKeys struct {
	Auth   string `json:"auth"`
	P256dh string `json:"p256dh"`
}

// MarshalJSON implements json.Marshaler, allowing serialization to JSON.
func (k *Keys) MarshalJSON() ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("keys are nil")
	}
	if k.P256dh == nil {
		return nil, fmt.Errorf("keys.p256dh is nil")
	}
	m := marshaledKeys{
		Auth:   base64.RawStdEncoding.EncodeToString(k.Auth[:]),
		P256dh: base64.RawStdEncoding.EncodeToString(k.P256dh.Bytes()),
	}
	return json.Marshal(&m)
}

// UnmarshalJSON implements json.Unmarshaler, allowing deserialization from JSON.
func (k *Keys) UnmarshalJSON(b []byte) (err error) {
	var m marshaledKeys
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	authBytes, err := decodeSubscriptionKey(m.Auth)
	if err != nil {
		return err
	}
	if len(authBytes) != 16 {
		return fmt.Errorf("invalid auth bytes length %d (must be 16)", len(authBytes))
	}
	copy(k.Auth[:], authBytes)
	rawDHKey, err := decodeSubscriptionKey(m.P256dh)
	if err != nil {
		return err
	}
	k.P256dh, err = ecdh.P256().NewPublicKey(rawDHKey)
	return err
}

// DecodeSubscriptionKeys decodes and validates a base64-encoded pair of subscription keys
// (the authentication secret and ECDH public key).
func DecodeSubscriptionKeys(auth, p256dh string) (keys Keys, err error) {
	authBytes, err := decodeSubscriptionKey(auth)
	if err != nil {
		return
	}
	if len(authBytes) != 16 {
		err = invalidAuthKeyLength
		return
	}
	copy(keys.Auth[:], authBytes)
	dhBytes, err := decodeSubscriptionKey(p256dh)
	if err != nil {
		return
	}
	keys.P256dh, err = ecdh.P256().NewPublicKey(dhBytes)
	if err != nil {
		return
	}
	return
}

// Subscription represents a PushSubscription object from the Push API
type Subscription struct {
	Endpoint       string     `json:"endpoint"`
	Keys           Keys       `json:"keys"`
	ExpirationTime *time.Time `json:"expirationTime"`
}

// SendNotification sends a push notification to a subscription's endpoint,
// applying encryption (RFC 8291) and adding a VAPID header (RFC 8292).
func SendNotification(ctx context.Context, message []byte, s *Subscription, options *Options) (*http.Response, error) {
	if s == nil || s.Endpoint == "" {
		return nil, fmt.Errorf("subscription endpoint is required")
	}
	if s.Keys.P256dh == nil {
		return nil, fmt.Errorf("subscription keys.p256dh is required")
	}
	var opts Options
	if options != nil {
		opts = *options
	}
	if opts.TTL < 0 {
		return nil, fmt.Errorf("TTL must be >= 0")
	}
	if opts.RecordSize == 0 {
		opts.RecordSize = MaxRecordSize
	}
	if opts.VAPIDKeys == nil {
		return nil, ErrMissingVAPIDKeys
	}
	if err := validateTopic(opts.Topic); err != nil {
		return nil, err
	}

	// Compose message body (RFC8291 encryption of the message)
	body, err := EncryptNotification(message, s.Keys, opts.RecordSize)
	if err != nil {
		return nil, err
	}

	vapidAuthHeader, err := getVAPIDAuthorizationHeader(
		s.Endpoint,
		opts.Subject,
		opts.VAPIDKeys,
		opts.VAPIDExpiration,
	)
	if err != nil {
		return nil, err
	}

	return sendNotification(ctx, s.Endpoint, &opts, vapidAuthHeader, body)
}

// EncryptNotification implements the encryption algorithm specified by RFC 8291 for web push
// (RFC 8188's aes128gcm content-encoding, with the key material derived from
// elliptic curve Diffie-Hellman over the P-256 curve).
func EncryptNotification(message []byte, keys Keys, recordSize uint32) ([]byte, error) {
	// Get the record size
	if recordSize == 0 {
		recordSize = MaxRecordSize
	} else if recordSize < 128 {
		return nil, ErrRecordSizeTooSmall
	}

	// Validate subscription keys to avoid nil dereference
	if keys.P256dh == nil {
		return nil, fmt.Errorf("invalid subscription: missing keys.p256dh")
	}

	// Allocate buffer to hold the eventual message
	// [ header block ] [ ciphertext ] [ 16 byte AEAD tag ], totaling RecordSize bytes
	// the ciphertext is the encryption of: [ message ] [ \x02 ] [ 0 or more \x00 as needed ]
	recordBuf := make([]byte, recordSize)
	// remainingBuf tracks our current writing position in recordBuf:
	remainingBuf := recordBuf

	// Application server key pairs (single use)
	localPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	localPublicKey := localPrivateKey.PublicKey()

	// Encryption Content-Coding Header
	// +-----------+--------+-----------+---------------+
	// | salt (16) | rs (4) | idlen (1) | keyid (idlen) |
	// +-----------+--------+-----------+---------------+
	// in our case the keyid is localPublicKey.Bytes(), so 65 bytes
	// First, generate the salt
	_, err = rand.Read(remainingBuf[:16])
	if err != nil {
		return nil, err
	}
	salt := remainingBuf[:16]
	remainingBuf = remainingBuf[16:]
	binary.BigEndian.PutUint32(remainingBuf[:], recordSize)
	remainingBuf = remainingBuf[4:]
	localPublicKeyBytes := localPublicKey.Bytes()
	remainingBuf[0] = byte(len(localPublicKeyBytes))
	remainingBuf = remainingBuf[1:]
	copy(remainingBuf[:], localPublicKeyBytes)
	remainingBuf = remainingBuf[len(localPublicKeyBytes):]

	// Combine application keys with receiver's EC public key to derive ECDH shared secret
	sharedECDHSecret, err := localPrivateKey.ECDH(keys.P256dh)
	if err != nil {
		return nil, fmt.Errorf("deriving shared secret: %w", err)
	}

	// ikm
	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(keys.P256dh.Bytes())
	prkInfoBuf.Write(localPublicKey.Bytes())

	ikm, err := hkdf.Key(sha256.New, sharedECDHSecret, keys.Auth[:], prkInfoBuf.String(), 32)
	if err != nil {
		return nil, fmt.Errorf("deriving ikm: %w", err)
	}

	// Derive Content Encryption Key
	contentEncryptionKeyInfo := "Content-Encoding: aes128gcm\x00"
	contentEncryptionKey, err := hkdf.Key(sha256.New, ikm, salt, contentEncryptionKeyInfo, 16)
	if err != nil {
		return nil, fmt.Errorf("deriving content encryption key: %w", err)
	}
	// Derive the Nonce
	nonceInfo := "Content-Encoding: nonce\x00"
	nonce, err := hkdf.Key(sha256.New, ikm, salt, nonceInfo, 12)
	if err != nil {
		return nil, fmt.Errorf("deriving nonce: %w", err)
	}

	// Cipher
	c, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	// need 1 byte for the 0x02 delimiter, 16 bytes for the AEAD tag
	if len(remainingBuf) < len(message)+17 {
		return nil, ErrRecordSizeTooSmall
	}
	// Copy the message plaintext into the buffer
	copy(remainingBuf[:], message[:])
	// The plaintext to be encrypted will include the padding delimiter and the padding;
	// cut off the final 16 bytes that are reserved for the AEAD tag
	plaintext := remainingBuf[:len(remainingBuf)-16]
	remainingBuf = remainingBuf[len(message):]
	// Add padding delimiter
	remainingBuf[0] = '\x02'
	remainingBuf = remainingBuf[1:]
	// The rest of the buffer is already zero-padded

	// Encipher the plaintext in place, then add the AEAD tag at the end.
	// "To reuse plaintext's storage for the encrypted output, use plaintext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext."
	gcm.Seal(plaintext[:0], nonce, plaintext, nil)

	return recordBuf, nil
}

func sendNotification(ctx context.Context, endpoint string, options *Options, vapidAuthHeader string, body []byte) (*http.Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.Itoa(options.TTL))

	// Check the optional headers
	if len(options.Topic) > 0 {
		req.Header.Set("Topic", options.Topic)
	}

	if isValidUrgency(options.Urgency) {
		req.Header.Set("Urgency", string(options.Urgency))
	}

	req.Header.Set("Authorization", vapidAuthHeader)

	// Send the request
	var client HTTPClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	} else {
		client = defaultHTTPClient
	}

	return client.Do(req)
}

func validateTopic(topic string) error {
	if topic == "" {
		return nil
	}
	if len(topic) > 32 {
		return fmt.Errorf("%w: must be 32 characters or fewer", ErrInvalidTopic)
	}
	for _, r := range topic {
		if r > 127 || !isTopicChar(byte(r)) {
			return fmt.Errorf("%w: contains invalid character %q", ErrInvalidTopic, r)
		}
	}
	return nil
}

func isTopicChar(ch byte) bool {
	switch ch {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z'
}

// decodeSubscriptionKey decodes a base64 subscription key.
func decodeSubscriptionKey(key string) ([]byte, error) {
	key = strings.TrimRight(key, "=")

	if strings.IndexByte(key, '+') != -1 || strings.IndexByte(key, '/') != -1 {
		return base64.RawStdEncoding.DecodeString(key)
	}
	return base64.RawURLEncoding.DecodeString(key)
}

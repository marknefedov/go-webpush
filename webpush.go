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
	"hash"
	"net/http"
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
	defaultClient                = NewClient(Config{})

	randomRead             = rand.Read
	newECDHPublicKey       = func(key []byte) (*ecdh.PublicKey, error) { return ecdh.P256().NewPublicKey(key) }
	generateECDHPrivateKey = func() (*ecdh.PrivateKey, error) { return ecdh.P256().GenerateKey(rand.Reader) }
	hkdfKey                = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
		return hkdf.Key(h, secret, salt, info, keyLength)
	}
	newAESCipher = aes.NewCipher
	newGCM       = cipher.NewGCM
)

// HTTPClient is an interface for sending the notification HTTP request / testing.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// SendOptions are the parameters used to send a notification.
type SendOptions struct {
	Subject             string     // Subject for the VAPID JWT token: email, mailto: URL, or HTTPS URL.
	TTL                 int        // TTL on the endpoint POST request, in seconds.
	Urgency             Urgency    // Optional urgency header.
	Topic               string     // Optional topic header.
	VAPIDKeys           *VAPIDKeys // VAPID public-private keypair for the Authorization header.
	VAPIDExpiration     time.Time  // Optional VAPID JWT expiration (defaults to now + 12 hours).
	RecordSize          uint32     // Per-record encrypted payload size.
	RequestReceipt      bool       // Request push receipt metadata from the push service.
	ReceiptSubscription string     // Optional receipt subscription URI to send as a Link relation.
}

// Keys represent a subscription's keys (its ECDH public key on the P-256 curve
// and its 16-byte authentication secret).
type Keys struct {
	Auth   [16]byte
	P256dh *ecdh.PublicKey
}

// Equal compares two Keys for equality.
func (k *Keys) Equal(o Keys) bool {
	if k == nil {
		return o.P256dh == nil && o.Auth == [16]byte{}
	}
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
	k.P256dh, err = newECDHPublicKey(rawDHKey)
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
	keys.P256dh, err = newECDHPublicKey(dhBytes)
	if err != nil {
		return
	}
	return
}

// Subscription represents a PushSubscription object from the Push API.
type Subscription struct {
	Endpoint       string     `json:"endpoint"`
	Keys           Keys       `json:"keys"`
	ExpirationTime *time.Time `json:"expirationTime"`
}

// SendNotification sends a push notification using the package default client.
func SendNotification(ctx context.Context, message []byte, s *Subscription, options *SendOptions) (*http.Response, error) {
	var opts SendOptions
	if options != nil {
		opts = *options
	}
	result, err := defaultClient.Send(ctx, message, s, opts)
	if result != nil {
		return result.Response, err
	}
	return nil, err
}

// EncryptNotification implements the encryption algorithm specified by RFC 8291 for web push
// using RFC 8188 aes128gcm content encoding.
func EncryptNotification(message []byte, keys Keys, recordSize uint32) ([]byte, error) {
	body, _, err := encryptNotificationRecords(message, keys, recordSize)
	return body, err
}

func encryptNotificationRecords(message []byte, keys Keys, recordSize uint32) ([]byte, int, error) {
	if recordSize == 0 {
		recordSize = MaxRecordSize
	}
	if recordSize < 18 {
		return nil, 0, ErrRecordSizeTooSmall
	}
	if keys.P256dh == nil {
		return nil, 0, fmt.Errorf("invalid subscription: missing keys.p256dh")
	}

	localPrivateKey, err := generateECDHPrivateKey()
	if err != nil {
		return nil, 0, err
	}
	localPublicKey := localPrivateKey.PublicKey()
	localPublicKeyBytes := localPublicKey.Bytes()

	salt := make([]byte, 16)
	if _, err := randomRead(salt); err != nil {
		return nil, 0, err
	}

	sharedECDHSecret, err := localPrivateKey.ECDH(keys.P256dh)
	if err != nil {
		return nil, 0, fmt.Errorf("deriving shared secret: %w", err)
	}

	prkInfoBuf := bytes.NewBuffer([]byte("WebPush: info\x00"))
	prkInfoBuf.Write(keys.P256dh.Bytes())
	prkInfoBuf.Write(localPublicKeyBytes)

	ikm, err := hkdfKey(sha256.New, sharedECDHSecret, keys.Auth[:], prkInfoBuf.String(), 32)
	if err != nil {
		return nil, 0, fmt.Errorf("deriving ikm: %w", err)
	}

	contentEncryptionKeyInfo := "Content-Encoding: aes128gcm\x00"
	contentEncryptionKey, err := hkdfKey(sha256.New, ikm, salt, contentEncryptionKeyInfo, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("deriving content encryption key: %w", err)
	}
	nonceInfo := "Content-Encoding: nonce\x00"
	baseNonce, err := hkdfKey(sha256.New, ikm, salt, nonceInfo, 12)
	if err != nil {
		return nil, 0, fmt.Errorf("deriving nonce: %w", err)
	}

	c, err := newAESCipher(contentEncryptionKey)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := newGCM(c)
	if err != nil {
		return nil, 0, err
	}

	header := make([]byte, 16+4+1+len(localPublicKeyBytes))
	copy(header[:16], salt)
	binary.BigEndian.PutUint32(header[16:20], recordSize)
	header[20] = byte(len(localPublicKeyBytes))
	copy(header[21:], localPublicKeyBytes)

	maxChunk := int(recordSize) - 17
	if maxChunk <= 0 {
		return nil, 0, ErrRecordSizeTooSmall
	}

	totalRecords := 1
	if len(message) > 0 {
		totalRecords = (len(message) + maxChunk - 1) / maxChunk
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(header)+len(message)+totalRecords*17))
	buf.Write(header)

	offset := 0
	for recordIndex := 0; recordIndex < totalRecords; recordIndex++ {
		end := offset + maxChunk
		if end > len(message) {
			end = len(message)
		}
		delimiter := byte(1)
		if recordIndex == totalRecords-1 {
			delimiter = 2
		}

		plaintext := make([]byte, end-offset+1)
		copy(plaintext, message[offset:end])
		plaintext[len(plaintext)-1] = delimiter

		nonce := deriveRecordNonce(baseNonce, uint64(recordIndex))
		ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
		buf.Write(ciphertext)
		offset = end
	}

	return buf.Bytes(), totalRecords, nil
}

func deriveRecordNonce(baseNonce []byte, recordIndex uint64) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)

	var sequence [12]byte
	binary.BigEndian.PutUint64(sequence[4:], recordIndex)
	for i := range nonce {
		nonce[i] ^= sequence[i]
	}
	return nonce
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

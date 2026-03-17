package webpush

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testHTTPClient struct {
	req      *http.Request
	response *http.Response
	err      error
}

type errReadCloser struct {
	closeErr error
}

type testAEAD struct{}

func (e errReadCloser) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (e errReadCloser) Close() error {
	return e.closeErr
}

func (testAEAD) NonceSize() int { return 12 }
func (testAEAD) Overhead() int  { return 16 }
func (testAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}
func (testAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}

func (c *testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.req = req
	if c.err != nil {
		return nil, c.err
	}
	if c.response != nil {
		if c.response.Body == nil {
			c.response.Body = io.NopCloser(bytes.NewReader(nil))
		}
		return c.response, nil
	}
	return &http.Response{
		StatusCode: http.StatusCreated,
		Status:     "201 Created",
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil
}

func getURLEncodedTestSubscription() *Subscription {
	subJSON := `{
		"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"keys": {
			"p256dh": "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			"auth":   "zqbxT6JKstKSY9JKibZLSQ"
		}
	}`
	sub := new(Subscription)
	if err := json.Unmarshal([]byte(subJSON), sub); err != nil {
		panic(err)
	}
	return sub
}

func getStandardEncodedTestSubscription() *Subscription {
	subJSON := `{
		"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"keys": {
			"p256dh": "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=",
			"auth":   "zqbxT6JKstKSY9JKibZLSQ=="
		}
	}`
	sub := new(Subscription)
	if err := json.Unmarshal([]byte(subJSON), sub); err != nil {
		panic(err)
	}
	return sub
}

func newTestClient(resp *http.Response) *Client {
	return NewClient(Config{
		HTTPClient: &testHTTPClient{response: resp},
		Clock: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
	})
}

func okResponse(status int) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}
}

func TestClientSendSingleRecord(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	respClient := client.httpClient.(*testHTTPClient)

	result, err := client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		Topic:     "test_topic",
		Urgency:   UrgencyLow,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status: %d", result.StatusCode)
	}
	if result.RecordCount != 1 {
		t.Fatalf("expected single record, got %d", result.RecordCount)
	}
	if result.NoPayload {
		t.Fatalf("expected payload send")
	}
	if respClient.req == nil {
		t.Fatal("expected request to be captured")
	}
	if got := respClient.req.Header.Get("Content-Encoding"); got != "aes128gcm" {
		t.Fatalf("expected aes128gcm content encoding, got %q", got)
	}
	if got := respClient.req.Header.Get("Topic"); got != "test_topic" {
		t.Fatalf("unexpected topic header %q", got)
	}
	if got := respClient.req.Header.Get("TTL"); got != "60" {
		t.Fatalf("unexpected ttl header %q", got)
	}
	if got := respClient.req.Header.Get("Urgency"); got != string(UrgencyLow) {
		t.Fatalf("unexpected urgency header %q", got)
	}
	if got := respClient.req.Header.Get("Authorization"); !strings.HasPrefix(got, "vapid ") {
		t.Fatalf("expected vapid authorization header, got %q", got)
	}
}

func TestClientSendMultiRecord(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("abcd"), 2000)

	result, err := client.Send(context.Background(), payload, getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RecordCount <= 1 {
		t.Fatalf("expected multiple records, got %d", result.RecordCount)
	}
	if result.NoPayload {
		t.Fatalf("expected payload send")
	}
}

func TestClientSendNoPayload(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	respClient := client.httpClient.(*testHTTPClient)

	result, err := client.Send(context.Background(), nil, getStandardEncodedTestSubscription(), SendOptions{
		Subject:             "email@example.com",
		TTL:                 60,
		VAPIDKeys:           keys,
		RequestReceipt:      true,
		ReceiptSubscription: "https://app.example/receipts",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.NoPayload {
		t.Fatalf("expected no-payload result")
	}
	if result.RecordCount != 0 {
		t.Fatalf("expected zero record count, got %d", result.RecordCount)
	}
	if got := respClient.req.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("expected no content-encoding header, got %q", got)
	}
	if got := respClient.req.Header.Get("Content-Type"); got != "" {
		t.Fatalf("expected no content-type header, got %q", got)
	}
	if got := respClient.req.Header.Get("Prefer"); got != "respond-async" {
		t.Fatalf("expected receipt preference header, got %q", got)
	}
	if got := respClient.req.Header.Values("Link"); len(got) != 1 || !strings.Contains(got[0], "urn:ietf:params:push:receipt") {
		t.Fatalf("expected receipt subscription link, got %v", got)
	}
}

func TestClientSendReceiptMetadata(t *testing.T) {
	resp := okResponse(http.StatusAccepted)
	resp.Header.Set("Location", "/messages/abc")
	resp.Header.Add("Link", `<https://app.example/receipts/123>; rel="urn:ietf:params:push:receipt"`)
	client := newTestClient(resp)
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	result, err := client.Send(context.Background(), nil, getStandardEncodedTestSubscription(), SendOptions{
		Subject:             "email@example.com",
		TTL:                 60,
		VAPIDKeys:           keys,
		RequestReceipt:      true,
		ReceiptSubscription: "https://app.example/receipts",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.MessageURL == "" || !strings.Contains(result.MessageURL, "/messages/abc") {
		t.Fatalf("expected resolved message url, got %q", result.MessageURL)
	}
	if result.ReceiptSubscription == "" || !strings.Contains(result.ReceiptSubscription, "/receipts/123") {
		t.Fatalf("expected resolved receipt subscription, got %q", result.ReceiptSubscription)
	}
}

func TestClientSendReceiptMetadataMissingLink(t *testing.T) {
	client := newTestClient(okResponse(http.StatusAccepted))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), nil, getStandardEncodedTestSubscription(), SendOptions{
		Subject:        "email@example.com",
		TTL:            60,
		VAPIDKeys:      keys,
		RequestReceipt: true,
	})
	if err == nil || !strings.Contains(err.Error(), "protocol error") {
		t.Fatalf("expected protocol error, got %v", err)
	}
}

func TestClientSendTypedServiceError(t *testing.T) {
	resp := okResponse(http.StatusTooManyRequests)
	resp.Header.Set("Retry-After", "120")
	resp.Body = io.NopCloser(strings.NewReader("slow down"))
	client := newTestClient(resp)
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	var serviceErr *PushServiceError
	if !errors.As(err, &serviceErr) {
		t.Fatalf("expected PushServiceError, got %T %v", err, err)
	}
	if !serviceErr.Temporary {
		t.Fatalf("expected temporary service error")
	}
	if serviceErr.SubscriptionExpired {
		t.Fatalf("expected non-expired service error")
	}
	if got := serviceErr.RetryAfter.Sub(time.Unix(1_700_000_000, 0).UTC()); got != 120*time.Second {
		t.Fatalf("expected retry-after +120s, got %s", got)
	}
	if !strings.Contains(serviceErr.Error(), "slow down") {
		t.Fatalf("expected body text in error, got %q", serviceErr.Error())
	}
}

func TestClientSendSubscriptionExpired(t *testing.T) {
	resp := okResponse(http.StatusGone)
	resp.Body = io.NopCloser(strings.NewReader("gone"))
	client := newTestClient(resp)
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	var serviceErr *PushServiceError
	if !errors.As(err, &serviceErr) {
		t.Fatalf("expected PushServiceError, got %T %v", err, err)
	}
	if !serviceErr.SubscriptionExpired {
		t.Fatalf("expected subscription-expired error")
	}
}

func TestVAPIDCacheReuse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	fakeClock := func() time.Time { return now }
	client := NewClient(Config{
		HTTPClient: &testHTTPClient{response: okResponse(http.StatusCreated)},
		Clock:      fakeClock,
	})
	signCount := 0
	client.signVAPID = func(endpoint, normalizedSubject string, vapidKeys *VAPIDKeys, expiration time.Time) (string, error) {
		signCount++
		return buildVAPIDAuthorizationHeader(endpoint, normalizedSubject, vapidKeys, expiration)
	}
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signCount != 1 {
		t.Fatalf("expected cached VAPID header reuse, signed %d times", signCount)
	}

	now = now.Add(2 * time.Minute)
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signCount != 2 {
		t.Fatalf("expected refreshed VAPID header after cache staleness, signed %d times", signCount)
	}
}

func TestSendBatch(t *testing.T) {
	client := NewClient(Config{
		HTTPClient: &testHTTPClient{response: okResponse(http.StatusCreated)},
	})
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	subs := []*Subscription{getStandardEncodedTestSubscription(), getStandardEncodedTestSubscription()}

	attempts := client.SendBatch(context.Background(), []byte("Hello"), subs, SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if len(attempts) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(attempts))
	}
	for _, attempt := range attempts {
		if attempt.Err != nil {
			t.Fatalf("expected successful attempt, got %v", attempt.Err)
		}
		if attempt.Result == nil || attempt.Result.StatusCode != http.StatusCreated {
			t.Fatalf("unexpected batch result: %#v", attempt.Result)
		}
	}
}

func TestSendNotificationWrapper(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	origDefault := defaultClient
	defaultClient = client
	defer func() { defaultClient = origDefault }()

	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := SendNotification(context.Background(), []byte("Hello"), getStandardEncodedTestSubscription(), &SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected wrapper status %d", resp.StatusCode)
	}
}

func TestKeysMarshalJSON_NilSafety(t *testing.T) {
	var nilKeys *Keys
	if _, err := nilKeys.MarshalJSON(); err == nil {
		t.Fatalf("expected error when marshaling nil Keys")
	}

	var keys Keys
	if _, err := keys.MarshalJSON(); err == nil || !strings.Contains(err.Error(), "keys.p256dh is nil") {
		t.Fatalf("expected nil p256dh error, got: %v", err)
	}
}

func TestClientSendUsesContext(t *testing.T) {
	client := NewClient(Config{
		HTTPClient: &testHTTPClient{response: okResponse(http.StatusCreated)},
	})
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Send(ctx, []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientSendInvalidTopic(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		Topic:     strings.Repeat("a", 33),
		VAPIDKeys: keys,
	})
	if !errors.Is(err, ErrInvalidTopic) {
		t.Fatalf("expected invalid topic error, got %v", err)
	}
}

func TestClientSendAcceptsNilPayload(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Send(context.Background(), nil, getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.NoPayload {
		t.Fatalf("expected no-payload result")
	}
}

func TestClientSendInvalidSubject(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "http://example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("expected invalid subject error, got %v", err)
	}
}

func TestClientSendMissingVAPIDKeys(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	_, err := client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject: "email@example.com",
		TTL:     60,
	})
	if !errors.Is(err, ErrMissingVAPIDKeys) {
		t.Fatalf("expected missing VAPID keys error, got %v", err)
	}
}

func TestClientSendRequestReceiptLinkValidation(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:             "email@example.com",
		TTL:                 60,
		VAPIDKeys:           keys,
		RequestReceipt:      true,
		ReceiptSubscription: "https://app.example/receipts",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientSendBuildRequest(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	req, err := client.buildRequest(context.Background(), "https://push.example/v2/abc", nil, SendOptions{
		TTL:                 30,
		Topic:               "topic",
		Urgency:             UrgencyHigh,
		RequestReceipt:      true,
		ReceiptSubscription: "https://app.example/receipts",
	}, "vapid t=abc, k=def", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Prefer"); got != "respond-async" {
		t.Fatalf("unexpected prefer header %q", got)
	}
	if got := req.Header.Values("Link"); len(got) != 1 {
		t.Fatalf("expected link header, got %v", got)
	}
}

func TestThinWrapperUsesDefaultClient(t *testing.T) {
	orig := defaultClient
	defaultClient = NewClient(Config{HTTPClient: &testHTTPClient{response: okResponse(http.StatusCreated)}})
	defer func() { defaultClient = orig }()

	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification(context.Background(), []byte("Hello"), getStandardEncodedTestSubscription(), &SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected wrapper response %d", resp.StatusCode)
	}
}

func TestClientSendStatus404(t *testing.T) {
	resp := okResponse(http.StatusNotFound)
	resp.Body = io.NopCloser(strings.NewReader("missing"))
	client := newTestClient(resp)
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	var serviceErr *PushServiceError
	if !errors.As(err, &serviceErr) {
		t.Fatalf("expected PushServiceError, got %T %v", err, err)
	}
	if !serviceErr.SubscriptionExpired {
		t.Fatalf("expected expired subscription flag")
	}
}

func TestClientSendResponseBodyPreserved(t *testing.T) {
	resp := okResponse(http.StatusTooManyRequests)
	resp.Body = io.NopCloser(strings.NewReader("retry later"))
	client := newTestClient(resp)
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err == nil {
		t.Fatalf("expected service error")
	}
}

func TestClientSendUsesHTTPResponseBody(t *testing.T) {
	rr := httptest.NewRecorder()
	rr.WriteHeader(http.StatusCreated)
	client := newTestClient(&http.Response{
		StatusCode: http.StatusCreated,
		Status:     "201 Created",
		Header:     rr.Header(),
		Body:       io.NopCloser(bytes.NewReader(nil)),
	})
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Send(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       60,
		VAPIDKeys: keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Response == nil {
		t.Fatal("expected response on result")
	}
}

func TestKeysEqualAndDecodeSubscriptionKeys(t *testing.T) {
	sub := getStandardEncodedTestSubscription()
	keys, err := DecodeSubscriptionKeys("zqbxT6JKstKSY9JKibZLSQ==", "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=")
	if err != nil {
		t.Fatal(err)
	}
	var nilKeys *Keys
	if !nilKeys.Equal(Keys{}) {
		t.Fatalf("expected nil receiver to equal zero-value keys")
	}
	if nilKeys.Equal(sub.Keys) {
		t.Fatalf("expected nil receiver to compare unequal to populated keys")
	}
	if !sub.Keys.Equal(keys) {
		t.Fatalf("expected decoded keys to equal subscription keys")
	}
	if keys.Equal(Keys{}) {
		t.Fatalf("expected unequal zero-value keys")
	}
	if _, err := DecodeSubscriptionKeys("bad", "also-bad"); err == nil {
		t.Fatalf("expected decode error")
	}
	if _, err := DecodeSubscriptionKeys("aGVsbG8=", "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk="); !errors.Is(err, invalidAuthKeyLength) {
		t.Fatalf("expected invalid auth key length, got %v", err)
	}
}

func TestKeysJSONRoundTrip(t *testing.T) {
	original := getStandardEncodedTestSubscription().Keys
	data, err := json.Marshal(&original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Keys
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !original.Equal(decoded) {
		t.Fatalf("expected round-tripped keys to match")
	}
	if err := json.Unmarshal([]byte(`{"auth":"AA","p256dh":"AA"}`), &decoded); err == nil {
		t.Fatalf("expected invalid key error")
	}
}

func TestEncryptNotificationWrapper(t *testing.T) {
	sub := getStandardEncodedTestSubscription()
	body, err := EncryptNotification([]byte("hello"), sub.Keys, 128)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatalf("expected encrypted body")
	}
	if _, err := EncryptNotification([]byte("x"), Keys{}, 128); err == nil {
		t.Fatalf("expected missing p256dh error")
	}
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 17); !errors.Is(err, ErrRecordSizeTooSmall) {
		t.Fatalf("expected record size error, got %v", err)
	}
}

func TestClientSendValidationPaths(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), []byte("x"), nil, SendOptions{}); err == nil {
		t.Fatalf("expected nil subscription error")
	}
	if _, err := client.Send(context.Background(), []byte("x"), &Subscription{}, SendOptions{}); err == nil {
		t.Fatalf("expected missing endpoint error")
	}
	if _, err := client.Send(context.Background(), []byte("x"), &Subscription{Endpoint: "https://push.example"}, SendOptions{}); err == nil {
		t.Fatalf("expected missing p256dh error")
	}
	if _, err := client.Send(context.Background(), []byte("x"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       -1,
		VAPIDKeys: keys,
	}); err == nil {
		t.Fatalf("expected negative ttl error")
	}
	if _, err := client.Send(context.Background(), []byte("x"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:             "email@example.com",
		TTL:                 10,
		VAPIDKeys:           keys,
		ReceiptSubscription: "://bad-uri",
	}); err == nil {
		t.Fatalf("expected invalid receipt subscription error")
	}
}

func TestSendBatchHandlesNilAndInvalidSubscriptions(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	attempts := client.SendBatch(context.Background(), []byte("x"), []*Subscription{
		nil,
		{Endpoint: "://bad"},
		getStandardEncodedTestSubscription(),
	}, SendOptions{Subject: "email@example.com", TTL: 10, VAPIDKeys: keys})
	if len(attempts) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(attempts))
	}
	if attempts[0].Err == nil || attempts[1].Err == nil {
		t.Fatalf("expected errors for nil and invalid subscriptions")
	}
	if attempts[2].Err != nil || attempts[2].Result == nil {
		t.Fatalf("expected valid third attempt")
	}
}

func TestPushServiceErrorErrorWithoutBody(t *testing.T) {
	err := (&PushServiceError{StatusCode: http.StatusBadGateway}).Error()
	if !strings.Contains(err, "502") {
		t.Fatalf("expected status in error, got %q", err)
	}
}

func TestParseRetryAfterVariants(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	if got := parseRetryAfter(now, "5"); !got.Equal(now.Add(5 * time.Second)) {
		t.Fatalf("unexpected delta retry-after: %v", got)
	}
	httpDate := now.Add(10 * time.Minute).Format(http.TimeFormat)
	if got := parseRetryAfter(now, httpDate); got.IsZero() {
		t.Fatalf("expected parsed http-date")
	}
	if got := parseRetryAfter(now, "not-valid"); !got.IsZero() {
		t.Fatalf("expected zero time for invalid retry-after, got %v", got)
	}
}

func TestReadLimitedBodyAndCloseError(t *testing.T) {
	resp := &http.Response{Body: nil}
	body, err := readLimitedBody(resp)
	if err != nil || body != nil {
		t.Fatalf("expected nil body without error, got %q %v", body, err)
	}

	resp = &http.Response{Body: errReadCloser{closeErr: fmt.Errorf("close failed")}}
	_, err = readLimitedBody(resp)
	if err == nil || !strings.Contains(err.Error(), "close failed") {
		t.Fatalf("expected close error, got %v", err)
	}
}

func TestReceiptParsingHelpers(t *testing.T) {
	base, _ := url.Parse("https://push.example/send/123")
	linkValues := splitLinkHeader(`<relative>; rel="urn:ietf:params:push:receipt", <https://other.example/x>; rel="other"`)
	if len(linkValues) != 2 {
		t.Fatalf("expected 2 link values, got %d", len(linkValues))
	}
	target, rel := parseLinkValue(linkValues[0])
	if target != "relative" || rel != receiptRelation {
		t.Fatalf("unexpected parsed link value: %q %q", target, rel)
	}
	receipt := parseReceiptSubscription([]string{`<relative>; rel="urn:ietf:params:push:receipt"`}, base)
	if receipt != "https://push.example/send/relative" {
		t.Fatalf("unexpected resolved receipt subscription %q", receipt)
	}
	if got := parseReceiptSubscription([]string{`not-a-link`}, base); got != "" {
		t.Fatalf("expected empty receipt subscription, got %q", got)
	}
}

func TestResolveReferenceAndValidateReceiptSubscription(t *testing.T) {
	base, _ := url.Parse("https://push.example/root")
	if got, err := resolveReference(base, "/x"); err != nil || got != "https://push.example/x" {
		t.Fatalf("unexpected resolved ref %q err=%v", got, err)
	}
	if _, err := resolveReference(base, "://bad"); err == nil {
		t.Fatalf("expected bad reference error")
	}
	if err := validateReceiptSubscription("https://app.example/receipts"); err != nil {
		t.Fatalf("expected valid receipt subscription, got %v", err)
	}
}

func TestBuildRequestWithPayloadSetsHeaders(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	req, err := client.buildRequest(context.Background(), "https://push.example/v2/abc", []byte("body"), SendOptions{
		TTL:     30,
		Topic:   "topic",
		Urgency: "",
	}, "vapid t=abc, k=def", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Content-Encoding"); got != "aes128gcm" {
		t.Fatalf("unexpected content encoding %q", got)
	}
	if got := req.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("unexpected content type %q", got)
	}
	if got := req.Header.Get("Urgency"); got != "" {
		t.Fatalf("expected no urgency header, got %q", got)
	}
}

func TestParseSendResponseHelpers(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	req, err := http.NewRequest(http.MethodPost, "https://push.example/send/abc", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := okResponse(http.StatusCreated)
	resp.Header.Set("Location", "https://push.example/messages/id")
	result, err := client.parseSendResponse(resp, req, SendOptions{}, time.Now(), 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.MessageURL == "" {
		t.Fatalf("expected message url")
	}
}

func TestVAPIDCacheEviction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	client := NewClient(Config{
		HTTPClient:     &testHTTPClient{response: okResponse(http.StatusCreated)},
		Clock:          func() time.Time { return now },
		VAPIDCacheSize: 1,
	})
	client.vapidCache[vapidCacheKey{audience: "https://expired", expUnix: now.Add(-time.Hour).Unix()}] = cachedVAPIDHeader{
		header: "expired",
		exp:    now.Add(-time.Hour),
		seq:    1,
	}
	client.vapidCache[vapidCacheKey{audience: "https://old", expUnix: now.Add(time.Hour).Unix()}] = cachedVAPIDHeader{
		header: "old",
		exp:    now.Add(time.Hour),
		seq:    2,
	}
	client.vapidCache[vapidCacheKey{audience: "https://new", expUnix: now.Add(2 * time.Hour).Unix()}] = cachedVAPIDHeader{
		header: "new",
		exp:    now.Add(2 * time.Hour),
		seq:    3,
	}
	client.evictVAPIDCacheLocked()
	if len(client.vapidCache) != 1 {
		t.Fatalf("expected cache trimmed to 1 entry, got %d", len(client.vapidCache))
	}
	for key := range client.vapidCache {
		if key.audience != "https://new" {
			t.Fatalf("expected newest cache entry to remain, got %q", key.audience)
		}
	}
}

func TestEncryptNotificationInjectedFailures(t *testing.T) {
	sub := getStandardEncodedTestSubscription()

	origGenerate := generateECDHPrivateKey
	origRead := randomRead
	origHKDF := hkdfKey
	origCipher := newAESCipher
	origGCM := newGCM
	defer func() {
		generateECDHPrivateKey = origGenerate
		randomRead = origRead
		hkdfKey = origHKDF
		newAESCipher = origCipher
		newGCM = origGCM
	}()

	generateECDHPrivateKey = func() (*ecdh.PrivateKey, error) {
		return nil, fmt.Errorf("generate failed")
	}
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "generate failed") {
		t.Fatalf("expected generate key error, got %v", err)
	}

	generateECDHPrivateKey = origGenerate
	randomRead = func([]byte) (int, error) { return 0, fmt.Errorf("rand failed") }
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "rand failed") {
		t.Fatalf("expected random read error, got %v", err)
	}

	randomRead = origRead
	hkdfCalls := 0
	hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
		hkdfCalls++
		if hkdfCalls == 1 {
			return nil, fmt.Errorf("ikm failed")
		}
		return origHKDF(h, secret, salt, info, keyLength)
	}
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "ikm failed") {
		t.Fatalf("expected hkdf ikm error, got %v", err)
	}

	hkdfCalls = 0
	hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
		hkdfCalls++
		if hkdfCalls == 2 {
			return nil, fmt.Errorf("cek failed")
		}
		return origHKDF(h, secret, salt, info, keyLength)
	}
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "cek failed") {
		t.Fatalf("expected hkdf cek error, got %v", err)
	}

	hkdfCalls = 0
	hkdfKey = func(h func() hash.Hash, secret, salt []byte, info string, keyLength int) ([]byte, error) {
		hkdfCalls++
		if hkdfCalls == 3 {
			return nil, fmt.Errorf("nonce failed")
		}
		return origHKDF(h, secret, salt, info, keyLength)
	}
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "nonce failed") {
		t.Fatalf("expected hkdf nonce error, got %v", err)
	}

	hkdfKey = origHKDF
	newAESCipher = func([]byte) (cipher.Block, error) { return nil, fmt.Errorf("cipher failed") }
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "cipher failed") {
		t.Fatalf("expected cipher error, got %v", err)
	}

	newAESCipher = origCipher
	newGCM = func(cipher.Block) (cipher.AEAD, error) { return nil, fmt.Errorf("gcm failed") }
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err == nil || !strings.Contains(err.Error(), "gcm failed") {
		t.Fatalf("expected gcm error, got %v", err)
	}

	newGCM = func(cipher.Block) (cipher.AEAD, error) { return testAEAD{}, nil }
	if _, err := EncryptNotification([]byte("x"), sub.Keys, 128); err != nil {
		t.Fatalf("expected success with injected AEAD, got %v", err)
	}
}

func TestDecodeAndUnmarshalInjectedPublicKeyErrors(t *testing.T) {
	origNewPublicKey := newECDHPublicKey
	defer func() { newECDHPublicKey = origNewPublicKey }()

	newECDHPublicKey = func([]byte) (*ecdh.PublicKey, error) {
		return nil, fmt.Errorf("public key failed")
	}

	if _, err := DecodeSubscriptionKeys("zqbxT6JKstKSY9JKibZLSQ==", "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk="); err == nil || !strings.Contains(err.Error(), "public key failed") {
		t.Fatalf("expected injected public key error, got %v", err)
	}

	var keys Keys
	err := json.Unmarshal([]byte(`{"auth":"zqbxT6JKstKSY9JKibZLSQ","p256dh":"BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk"}`), &keys)
	if err == nil || !strings.Contains(err.Error(), "public key failed") {
		t.Fatalf("expected injected unmarshal public key error, got %v", err)
	}
}

func TestClientSendAndCacheInjectedFailures(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}

	client.signVAPID = func(endpoint, normalizedSubject string, vapidKeys *VAPIDKeys, expiration time.Time) (string, error) {
		return "", fmt.Errorf("sign failed")
	}
	if _, err := client.Send(context.Background(), []byte("x"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       10,
		VAPIDKeys: keys,
	}); err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("expected signer error, got %v", err)
	}

	client = NewClient(Config{HTTPClient: &testHTTPClient{err: fmt.Errorf("http failed")}})
	if _, err := client.Send(context.Background(), []byte("x"), getStandardEncodedTestSubscription(), SendOptions{
		Subject:   "email@example.com",
		TTL:       10,
		VAPIDKeys: keys,
	}); err == nil || !strings.Contains(err.Error(), "http failed") {
		t.Fatalf("expected http client error, got %v", err)
	}
}

func TestParseSendResponseAdditionalBranches(t *testing.T) {
	client := newTestClient(okResponse(http.StatusCreated))
	req, err := http.NewRequest(http.MethodPost, "https://push.example/send/abc", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp := okResponse(http.StatusAccepted)
	resp.Header.Add("Link", `</receipts/abc>; rel="urn:ietf:params:push:receipt"`)
	result, err := client.parseSendResponse(resp, req, SendOptions{RequestReceipt: true}, time.Now(), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReceiptSubscription != "https://push.example/receipts/abc" {
		t.Fatalf("unexpected relative receipt subscription %q", result.ReceiptSubscription)
	}

	resp = okResponse(http.StatusInternalServerError)
	resp.Header.Set("Retry-After", time.Now().Add(time.Minute).Format(http.TimeFormat))
	resp.Body = io.NopCloser(strings.NewReader("server blew up"))
	_, err = client.parseSendResponse(resp, req, SendOptions{}, time.Now(), 0, false)
	var serviceErr *PushServiceError
	if !errors.As(err, &serviceErr) || !serviceErr.Temporary || serviceErr.RetryAfter.IsZero() {
		t.Fatalf("expected temporary service error with retry-after, got %v", err)
	}
}

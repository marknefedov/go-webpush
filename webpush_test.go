package webpush

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type testHTTPClient struct {
	req *http.Request
}

func (c *testHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: 201}, nil
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

func TestSendNotificationToURLEncodedSubscription(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification(context.Background(), []byte("Test"), getURLEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		RecordSize: 3070,
		Subject:    "email@example.com",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("incorrect status code, expected=%d, got=%d", 201, resp.StatusCode)
	}
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subject:    "email@example.com",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("incorrect status code, expected=%d, got=%d", 201, resp.StatusCode)
	}
}

func TestSendNotificationToNilContext(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	client := &testHTTPClient{}
	_, err = SendNotification(nil, []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: client,
		Subject:    "email@example.com",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if client.req == nil || client.req.Context() == nil {
		t.Fatalf("expected request context to be set")
	}
}

func TestSendTooLargeNotification(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SendNotification(context.Background(), []byte(strings.Repeat("Test", int(MaxRecordSize))), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subject:    "email@example.com",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if !errors.Is(err, ErrRecordSizeTooSmall) {
		t.Fatalf("expected record size error, got: %v", err)
	}
}

func TestSendNotificationDoesNotMutateOptions(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	opts := &Options{
		HTTPClient: &testHTTPClient{},
		Subject:    "email@example.com",
		TTL:        0,
		VAPIDKeys:  vapidKeys,
	}
	_, err = SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if opts.RecordSize != 0 {
		t.Fatalf("expected RecordSize to remain unchanged, got %d", opts.RecordSize)
	}
}

func TestSendNotificationValidatesTopic(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		topic string
	}{
		{name: "spaces", topic: "bad topic"},
		{name: "slash", topic: "bad/topic"},
		{name: "tooLong", topic: strings.Repeat("a", 33)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
				HTTPClient: &testHTTPClient{},
				Subject:    "email@example.com",
				Topic:      tc.topic,
				TTL:        0,
				VAPIDKeys:  vapidKeys,
			})
			if !errors.Is(err, ErrInvalidTopic) {
				t.Fatalf("expected invalid topic error, got: %v", err)
			}
		})
	}
}

func TestSendNotificationAcceptsValidTopic(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subject:    "email@example.com",
		Topic:      "demo-1_AbCdEf0123",
		TTL:        0,
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
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

func TestSendNotificationRequiresSubject(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		VAPIDKeys:  vapidKeys,
	})
	if !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("expected invalid subject error, got: %v", err)
	}
}

func TestSendNotificationRequiresVAPIDKeys(t *testing.T) {
	_, err := SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subject:    "email@example.com",
	})
	if !errors.Is(err, ErrMissingVAPIDKeys) {
		t.Fatalf("expected missing keys error, got: %v", err)
	}
}

func TestSendNotificationExpirationFieldRenamed(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient:      &testHTTPClient{},
		Subject:         "email@example.com",
		VAPIDKeys:       vapidKeys,
		VAPIDExpiration: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
}

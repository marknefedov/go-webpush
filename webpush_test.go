package webpush

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type testHTTPClient struct{}

func (*testHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 201}, nil
}

func getURLEncodedTestSubscription() *Subscription {
	subJson := `{
		"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"keys": {
			"p256dh": "BNNL5ZaTfK81qhXOx23-wewhigUeFb632jN6LvRWCFH1ubQr77FE_9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk",
			"auth":   "zqbxT6JKstKSY9JKibZLSQ"
		}
	}`
	sub := new(Subscription)
	if err := json.Unmarshal([]byte(subJson), sub); err != nil {
		panic(err)
	}
	return sub
}

func getStandardEncodedTestSubscription() *Subscription {
	subJson := `{
		"endpoint": "https://updates.push.services.mozilla.com/wpush/v2/gAAAAA",
		"keys": {
			"p256dh": "BNNL5ZaTfK81qhXOx23+wewhigUeFb632jN6LvRWCFH1ubQr77FE/9qV1FuojuRmHP42zmf34rXgW80OvUVDgTk=",
			"auth":   "zqbxT6JKstKSY9JKibZLSQ=="
		}
	}`
	sub := new(Subscription)
	if err := json.Unmarshal([]byte(subJson), sub); err != nil {
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
		Subscriber: "<EMAIL@EXAMPLE.COM>",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorrect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendNotificationToStandardEncodedSubscription(t *testing.T) {
	vapidKeys, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := SendNotification(context.Background(), []byte("Test"), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subscriber: "<EMAIL@EXAMPLE.COM>",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
		VAPIDKeys:  vapidKeys,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf(
			"Incorreect status code, expected=%d, got=%d",
			resp.StatusCode,
			201,
		)
	}
}

func TestSendTooLargeNotification(t *testing.T) {
	_, err := SendNotification(context.Background(), []byte(strings.Repeat("Test", int(MaxRecordSize))), getStandardEncodedTestSubscription(), &Options{
		HTTPClient: &testHTTPClient{},
		Subscriber: "<EMAIL@EXAMPLE.COM>",
		Topic:      "test_topic",
		TTL:        0,
		Urgency:    "low",
	})
	if err == nil {
		t.Fatalf("Error is nil, expected=%s", ErrRecordSizeTooSmall)
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

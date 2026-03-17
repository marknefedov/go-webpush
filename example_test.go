package webpush

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type exampleHTTPClient struct{}

func (exampleHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 201,
		Status:     "201 Created",
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

func exampleSubscription() *Subscription {
	const subJSON = `{
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

func ExampleGenerateVAPIDKeys() {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(keys.PublicKeyString()) == 87)
	// Output: true
}

func ExampleVAPIDKeys_ExportVAPIDPrivateKeyPEM() {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		panic(err)
	}
	pemBytes, err := keys.ExportVAPIDPrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.HasPrefix(pemBytes, []byte("-----BEGIN PRIVATE KEY-----")))
	// Output: true
}

func ExampleSendNotification() {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		panic(err)
	}
	resp, err := SendNotification(context.Background(), []byte("Hello from Go!"), exampleSubscription(), &Options{
		HTTPClient:      exampleHTTPClient{},
		Subject:         "user@example.com",
		VAPIDKeys:       keys,
		TTL:             60,
		VAPIDExpiration: time.Now().Add(12 * time.Hour),
	})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.StatusCode)
	// Output: 201
}

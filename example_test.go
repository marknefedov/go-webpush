package webpush

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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

func ExampleClient_Send() {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		panic(err)
	}
	client := NewClient(Config{HTTPClient: exampleHTTPClient{}})
	result, err := client.Send(context.Background(), []byte("Hello from Go!"), exampleSubscription(), SendOptions{
		Subject:   "user@example.com",
		VAPIDKeys: keys,
		TTL:       60,
	})
	if err != nil {
		panic(err)
	}
	defer result.Response.Body.Close()
	fmt.Println(result.StatusCode, result.RecordCount, result.NoPayload)
	// Output: 201 1 false
}

func ExampleClient_Send_noPayload() {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		panic(err)
	}
	client := NewClient(Config{HTTPClient: exampleHTTPClient{}})
	result, err := client.Send(context.Background(), nil, exampleSubscription(), SendOptions{
		Subject:             "user@example.com",
		VAPIDKeys:           keys,
		RequestReceipt:      true,
		ReceiptSubscription: "https://app.example/receipts",
	})
	if err != nil {
		panic(err)
	}
	defer result.Response.Body.Close()
	fmt.Println(result.StatusCode, result.NoPayload)
	// Output: 201 true
}

func ExampleClient_SendBatch() {
	keys, err := GenerateVAPIDKeys()
	if err != nil {
		panic(err)
	}
	client := NewClient(Config{HTTPClient: exampleHTTPClient{}})
	subs := []*Subscription{exampleSubscription(), exampleSubscription()}
	attempts := client.SendBatch(context.Background(), []byte("Hello from Go!"), subs, SendOptions{
		Subject:   "user@example.com",
		VAPIDKeys: keys,
		TTL:       60,
	})
	fmt.Println(len(attempts), attempts[0].Err == nil, attempts[1].Err == nil)
	// Output: 2 true true
}

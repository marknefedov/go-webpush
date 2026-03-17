package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/marknefedov/go-webpush"
)

func SaveVAPIDKeysPEM(filename string, keys *webpush.VAPIDKeys) error {
	if keys == nil {
		return fmt.Errorf("vapid keys are nil")
	}
	pem, err := keys.ExportVAPIDPrivateKeyPEM()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, pem, 0600)
}

// SaveVAPIDKeysJSON marshals VAPID keys as Web-push–style JSON and writes to file.
// The JSON object contains base64url-encoded fields:
//
//	{"publicKey": "...","privateKey": "..."}.
func SaveVAPIDKeysJSON(filename string, keys *webpush.VAPIDKeys) error {
	if keys == nil {
		return fmt.Errorf("vapid keys are nil")
	}
	j, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, j, 0600)
}

// LoadVAPIDKeysJSON reads Web-push–style JSON and reconstructs VAPIDKeys.
func LoadVAPIDKeysJSON(filename string) (*webpush.VAPIDKeys, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	vk := new(webpush.VAPIDKeys)
	if err := json.Unmarshal(b, vk); err != nil {
		return nil, err
	}
	return vk, nil
}

func LoadVAPIDKeysPEM(filename string) (*webpush.VAPIDKeys, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return webpush.LoadVAPIDPrivateKeyPEM(b)
}

func main() {
	vk1, err := LoadVAPIDKeysPEM("vapid_private.pem")
	if err != nil {
		log.Printf("could not load VAPID keys from PEM: %v\n", err)
	}
	vk2, err := LoadVAPIDKeysJSON("vapid_keys.json")
	if err != nil {
		log.Printf("could not load VAPID keys from JSON: %v\n", err)
	}
	var vapidKeys *webpush.VAPIDKeys
	if vk1 != nil && vk2 != nil && vk1.Equal(vk2) {
		log.Println("VAPID keys are equal")
		log.Println("Using loaded keys")
		vapidKeys = vk1
	} else {
		log.Println("Generating new VAPID keys")
		var err error
		vapidKeys, err = webpush.GenerateVAPIDKeys()
		err = SaveVAPIDKeysPEM("vapid_private.pem", vapidKeys)
		if err != nil {
			log.Fatal(err)
		}
		err = SaveVAPIDKeysJSON("vapid_keys.json", vapidKeys)
		if err != nil {
			log.Fatal(err)
		}
	}
	keysJson, err := json.Marshal(vapidKeys)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("VAPID keys:", string(keysJson))
	fmt.Println("Enter subscription: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	var raw strings.Builder
	sub := &webpush.Subscription{}
	parsed := false

	type subscriptionEnvelope struct {
		Subscription *webpush.Subscription `json:"subscription"`
	}
	isValid := func(s *webpush.Subscription) bool {
		return s != nil && s.Endpoint != "" && s.Keys.P256dh != nil
	}

	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
			break
		}
		raw.WriteString(scanner.Text())
		raw.WriteByte('\n')
		attempt := strings.TrimSpace(raw.String())
		if len(attempt) == 0 {
			continue
		}
		tmp := new(webpush.Subscription)
		if json.Unmarshal([]byte(attempt), tmp) == nil && isValid(tmp) {
			sub = tmp
			parsed = true
			break
		}
		var env subscriptionEnvelope
		if json.Unmarshal([]byte(attempt), &env) == nil && isValid(env.Subscription) {
			sub = env.Subscription
			parsed = true
			break
		}
	}

	if !parsed {
		attempt := strings.TrimSpace(raw.String())
		tmp := new(webpush.Subscription)
		if json.Unmarshal([]byte(attempt), tmp) == nil && isValid(tmp) {
			sub = tmp
		} else {
			var env subscriptionEnvelope
			if json.Unmarshal([]byte(attempt), &env) == nil && isValid(env.Subscription) {
				sub = env.Subscription
			} else {
				log.Fatal("could not parse a valid subscription from input (expecting a PushSubscription or {\"subscription\": {...}})")
			}
		}
	}

	fmt.Println("Subscription:", sub)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := webpush.SendNotification(
		ctx,
		[]byte("Test"),
		sub,
		&webpush.Options{
			Subject:         "example@example.com", // Do not include "mailto:"
			VAPIDKeys:       vapidKeys,
			TTL:             30,
			VAPIDExpiration: time.Now().Add(12 * time.Hour),
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Response:", resp)
}

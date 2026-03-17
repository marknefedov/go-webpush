package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	webpush "github.com/marknefedov/go-webpush"
)

func saveVAPIDKeysPEM(filename string, keys *webpush.VAPIDKeys) error {
	if keys == nil {
		return fmt.Errorf("vapid keys are nil")
	}
	pem, err := keys.ExportVAPIDPrivateKeyPEM()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, pem, 0o600)
}

func saveVAPIDKeysJSON(filename string, keys *webpush.VAPIDKeys) error {
	if keys == nil {
		return fmt.Errorf("vapid keys are nil")
	}
	j, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, j, 0o600)
}

func loadVAPIDKeysJSON(filename string) (*webpush.VAPIDKeys, error) {
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

func loadVAPIDKeysPEM(filename string) (*webpush.VAPIDKeys, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return webpush.LoadVAPIDPrivateKeyPEM(b)
}

func main() {
	vk1, err := loadVAPIDKeysPEM("vapid_private.pem")
	if err != nil {
		log.Printf("could not load VAPID keys from PEM: %v", err)
	}
	vk2, err := loadVAPIDKeysJSON("vapid_keys.json")
	if err != nil {
		log.Printf("could not load VAPID keys from JSON: %v", err)
	}

	var vapidKeys *webpush.VAPIDKeys
	if vk1 != nil && vk2 != nil && vk1.Equal(vk2) {
		log.Println("VAPID keys are equal")
		vapidKeys = vk1
	} else {
		log.Println("Generating new VAPID keys")
		vapidKeys, err = webpush.GenerateVAPIDKeys()
		if err != nil {
			log.Fatal(err)
		}
		if err := saveVAPIDKeysPEM("vapid_private.pem", vapidKeys); err != nil {
			log.Fatal(err)
		}
		if err := saveVAPIDKeysJSON("vapid_keys.json", vapidKeys); err != nil {
			log.Fatal(err)
		}
	}

	keysJSON, err := json.Marshal(vapidKeys)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("VAPID keys:", string(keysJSON))
	fmt.Println("Enter subscription JSON:")

	sub, err := readSubscription(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	client := webpush.NewClient(webpush.Config{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.Send(ctx, []byte("Test"), sub, webpush.SendOptions{
		Subject:             "example@example.com",
		VAPIDKeys:           vapidKeys,
		TTL:                 30,
		RequestReceipt:      true,
		ReceiptSubscription: "https://example.com/receipts",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Status:", result.StatusCode)
	fmt.Println("Records:", result.RecordCount)
	fmt.Println("No payload:", result.NoPayload)
	fmt.Println("Receipt subscription:", result.ReceiptSubscription)
}

func readSubscription(r *os.File) (*webpush.Subscription, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	var raw strings.Builder
	for scanner.Scan() {
		raw.WriteString(scanner.Text())
		raw.WriteByte('\n')
		attempt := strings.TrimSpace(raw.String())
		if attempt == "" {
			continue
		}
		sub, err := parseSubscription(attempt)
		if err == nil {
			return sub, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return parseSubscription(strings.TrimSpace(raw.String()))
}

func parseSubscription(input string) (*webpush.Subscription, error) {
	sub := new(webpush.Subscription)
	if err := json.Unmarshal([]byte(input), sub); err == nil && sub.Endpoint != "" && sub.Keys.P256dh != nil {
		return sub, nil
	}
	var env struct {
		Subscription *webpush.Subscription `json:"subscription"`
	}
	if err := json.Unmarshal([]byte(input), &env); err == nil && env.Subscription != nil && env.Subscription.Endpoint != "" && env.Subscription.Keys.P256dh != nil {
		return env.Subscription, nil
	}
	return nil, fmt.Errorf("could not parse a valid subscription from input")
}

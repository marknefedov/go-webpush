# go-webpush 
[![Go Reference](https://pkg.go.dev/badge/github.com/marknefedov/go-webpush.svg)](https://pkg.go.dev/github.com/marknefedov/go-webpush)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/marknefedov/go-webpush)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/tag/marknefedov/go-webpush)](https://github.com/marknefedov/go-webpush/tag/latest)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/marknefedov/go-webpush/ci.yml?branch=master)](https://github.com/marknefedov/go-webpush/actions/workflows/ci.yml)

Web Push API encryption and sending library for Go with VAPID support.

This library lets you send encrypted Web Push notifications from a Go server to browsers supporting the Push API. It implements message encryption (aes128gcm), VAPID authentication (JWT over ES256), and useful headers like TTL and Urgency.

## Installation

```
go get github.com/marknefedov/go-webpush
```

## Quick start

1) Generate VAPID keys (one-time):

```go
package main

import (
    "os"
    webpush "github.com/marknefedov/go-webpush"
)

func main() {
    keys, err := webpush.GenerateVAPIDKeys()
    if err != nil { panic(err) }
    // Persist them somewhere safe; you can export as JSON or PEM
    pem, _ := keys.ExportVAPIDPrivateKeyPEM()
    _ = os.WriteFile("vapid_private.pem", pem, 0o600)
}
```

2) On the client, subscribe with the VAPID public key and send the subscription object to your server. See the example directory for a working page and service worker.

3) Send a push message from your server:

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "time"

    webpush "github.com/marknefedov/go-webpush"
)

func main() {
    // Parse subscription JSON you stored from the browser
    var sub webpush.Subscription
    _ = json.Unmarshal([]byte(`{...}`), &sub)

    // Load your VAPID keys (from PEM)
    keys, err := webpush.LoadVAPIDPrivateKeyPEM(mustRead("vapid_private.pem"))
    if err != nil { log.Fatal(err) }

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    resp, err := webpush.SendNotification(
        ctx,
        []byte("Hello from Go!"), // payload (optional but recommended)
        &sub,
        &webpush.Options{
            Subject:    "user@example.com", // an email or URL
            VAPIDKeys:  keys,
            TTL:        60,                 // seconds push service should retain the message
            // Urgency: webpush.UrgencyHigh,   // optional: VeryLow, Low, Normal, High
            // Topic:   "demo-1",             // optional: collapse key
            // VAPIDExpiration: time.Now().Add(12 * time.Hour),
        },
    )
    if err != nil { log.Fatal(err) }
    defer resp.Body.Close()
    log.Println("push status:", resp.Status)
}

func mustRead(p string) []byte { b, _ := os.ReadFile(p); return b }
```

## Examples

A complete end-to-end example (CLI sender, HTML page, and service worker) is provided in the example/ directory:

- example/index.html – subscribe and copy the resulting subscription JSON
- example/service-worker.js – displays the push
- example/main.go – generate/load VAPID keys and send a notification

To run the example sender:

```
cd example
go run .
```

Then paste the subscription JSON from the page into the terminal when prompted.

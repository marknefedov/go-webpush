// Package webpush provides helpers for sending Web Push notifications from Go.
//
// The client-based API implements RFC 8188 / RFC 8291 content
// encryption, RFC 8292 VAPID authentication and reuse, and RFC 8030 request
// metadata such as TTL, Urgency, Topic, and receipt-request headers.
//
// It is intentionally focused on application-server sends to existing Push API
// subscriptions. Subscription creation, browser integration, and live receipt
// monitoring are left to the caller.
//
// The package does not implement RFC 8030 subscription-set creation or live
// HTTP/2 receipt consumption.
package webpush

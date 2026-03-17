// Package webpush provides helpers for sending Web Push notifications from Go.
//
// The package implements RFC 8291 content encryption, RFC 8292 VAPID
// authentication, and the RFC 8030 delivery headers used by push services:
// TTL, Urgency, and Topic.
//
// It is intentionally focused on sending a single encrypted push message to an
// existing Push API subscription. Subscription collection, browser integration,
// and push service management are left to the caller.
package webpush

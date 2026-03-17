package webpush

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxConcurrentSends = 8
	defaultVAPIDCacheSize     = 256
	maxErrorBodyBytes         = 8 * 1024
	receiptRelation           = "urn:ietf:params:push:receipt"
)

// Config configures a reusable push client.
type Config struct {
	HTTPClient         HTTPClient
	Clock              func() time.Time
	MaxConcurrentSends int
	VAPIDCacheSize     int
}

// Client sends notifications and caches reusable VAPID headers.
type Client struct {
	httpClient         HTTPClient
	clock              func() time.Time
	maxConcurrentSends int
	vapidCacheSize     int
	signVAPID          func(endpoint, normalizedSubject string, vapidKeys *VAPIDKeys, expiration time.Time) (string, error)

	mu         sync.Mutex
	cacheSeq   uint64
	vapidCache map[vapidCacheKey]cachedVAPIDHeader
}

// SendResult contains the HTTP response and metadata extracted from it.
type SendResult struct {
	Response            *http.Response
	StatusCode          int
	MessageURL          string
	ReceiptSubscription string
	UsedVAPIDExpiration time.Time
	RecordCount         int
	NoPayload           bool
}

// PushServiceError describes a non-success response from a push service.
type PushServiceError struct {
	StatusCode          int
	Header              http.Header
	Body                []byte
	RetryAfter          time.Time
	Temporary           bool
	SubscriptionExpired bool
}

// Error implements the error interface.
func (e *PushServiceError) Error() string {
	if len(e.Body) > 0 {
		return fmt.Sprintf("push service returned HTTP %d: %s", e.StatusCode, strings.TrimSpace(string(e.Body)))
	}
	return fmt.Sprintf("push service returned HTTP %d", e.StatusCode)
}

// SendAttempt captures the outcome of one send in a batch.
type SendAttempt struct {
	Subscription *Subscription
	Result       *SendResult
	Err          error
}

type vapidCacheKey struct {
	audience  string
	subject   string
	publicKey string
	expUnix   int64
}

type cachedVAPIDHeader struct {
	header string
	exp    time.Time
	seq    uint64
}

// NewClient constructs a reusable push client.
func NewClient(cfg Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	maxConcurrent := cfg.MaxConcurrentSends
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentSends
	}
	cacheSize := cfg.VAPIDCacheSize
	if cacheSize <= 0 {
		cacheSize = defaultVAPIDCacheSize
	}
	return &Client{
		httpClient:         httpClient,
		clock:              clock,
		maxConcurrentSends: maxConcurrent,
		vapidCacheSize:     cacheSize,
		signVAPID:          buildVAPIDAuthorizationHeader,
		vapidCache:         make(map[vapidCacheKey]cachedVAPIDHeader),
	}
}

// Send sends a notification to a single subscription.
func (c *Client) Send(ctx context.Context, payload []byte, sub *Subscription, opts SendOptions) (*SendResult, error) {
	if sub == nil || sub.Endpoint == "" {
		return nil, fmt.Errorf("subscription endpoint is required")
	}
	if sub.Keys.P256dh == nil {
		return nil, fmt.Errorf("subscription keys.p256dh is required")
	}
	if opts.TTL < 0 {
		return nil, fmt.Errorf("TTL must be >= 0")
	}
	if err := validateTopic(opts.Topic); err != nil {
		return nil, err
	}
	normalizedSubject, err := normalizeSubject(opts.Subject)
	if err != nil {
		return nil, err
	}
	expiration, err := resolveVAPIDExpiration(opts.VAPIDExpiration, c.clock())
	if err != nil {
		return nil, err
	}
	if opts.VAPIDKeys == nil {
		return nil, ErrMissingVAPIDKeys
	}
	if opts.RecordSize == 0 {
		opts.RecordSize = MaxRecordSize
	}
	if err := validateReceiptSubscription(opts.ReceiptSubscription); err != nil {
		return nil, err
	}

	vapidHeader, err := c.getVAPIDHeader(sub.Endpoint, normalizedSubject, opts.VAPIDKeys, expiration)
	if err != nil {
		return nil, err
	}

	noPayload := len(payload) == 0
	var body []byte
	recordCount := 0
	if !noPayload {
		body, recordCount, err = encryptNotificationRecords(payload, sub.Keys, opts.RecordSize)
		if err != nil {
			return nil, err
		}
	}

	req, err := c.buildRequest(ctx, sub.Endpoint, body, opts, vapidHeader, noPayload)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return c.parseSendResponse(resp, req, opts, expiration, recordCount, noPayload)
}

// SendBatch sends the same payload and options to a set of subscriptions.
func (c *Client) SendBatch(ctx context.Context, payload []byte, subs []*Subscription, opts SendOptions) []SendAttempt {
	attempts := make([]SendAttempt, len(subs))
	if len(subs) == 0 {
		return attempts
	}

	type indexedSub struct {
		index int
		sub   *Subscription
	}

	groupOrder := make([]string, 0)
	groups := make(map[string][]indexedSub)
	for i, sub := range subs {
		attempts[i].Subscription = sub
		if sub == nil {
			attempts[i].Err = fmt.Errorf("subscription endpoint is required")
			continue
		}
		origin, err := audienceFromEndpoint(sub.Endpoint)
		if err != nil {
			attempts[i].Err = err
			continue
		}
		if _, ok := groups[origin]; !ok {
			groupOrder = append(groupOrder, origin)
		}
		groups[origin] = append(groups[origin], indexedSub{index: i, sub: sub})
	}

	for _, origin := range groupOrder {
		items := groups[origin]
		workerCount := c.maxConcurrentSends
		if workerCount > len(items) {
			workerCount = len(items)
		}
		jobs := make(chan indexedSub)
		var wg sync.WaitGroup
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for item := range jobs {
					result, err := c.Send(ctx, payload, item.sub, opts)
					attempts[item.index].Result = result
					attempts[item.index].Err = err
				}
			}()
		}
		for _, item := range items {
			jobs <- item
		}
		close(jobs)
		wg.Wait()
	}

	return attempts
}

func (c *Client) buildRequest(ctx context.Context, endpoint string, body []byte, opts SendOptions, vapidHeader string, noPayload bool) (*http.Request, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var reader io.Reader
	if !noPayload {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, reader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("TTL", strconv.Itoa(opts.TTL))
	req.Header.Set("Authorization", vapidHeader)

	if opts.Topic != "" {
		req.Header.Set("Topic", opts.Topic)
	}
	if isValidUrgency(opts.Urgency) {
		req.Header.Set("Urgency", string(opts.Urgency))
	}
	if opts.RequestReceipt {
		req.Header.Set("Prefer", "respond-async")
	}
	if opts.ReceiptSubscription != "" {
		req.Header.Add("Link", formatReceiptSubscriptionLink(opts.ReceiptSubscription))
	}
	if !noPayload {
		req.Header.Set("Content-Encoding", "aes128gcm")
		req.Header.Set("Content-Type", "application/octet-stream")
	}

	return req, nil
}

func (c *Client) parseSendResponse(resp *http.Response, req *http.Request, opts SendOptions, expiration time.Time, recordCount int, noPayload bool) (*SendResult, error) {
	result := &SendResult{
		Response:            resp,
		StatusCode:          resp.StatusCode,
		UsedVAPIDExpiration: expiration,
		RecordCount:         recordCount,
		NoPayload:           noPayload,
	}

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusCreated {
		if location := resp.Header.Get("Location"); location != "" {
			if resolved, err := resolveReference(req.URL, location); err == nil {
				result.MessageURL = resolved
			}
		}
		if receipt := parseReceiptSubscription(resp.Header.Values("Link"), req.URL); receipt != "" {
			result.ReceiptSubscription = receipt
		}
		if opts.RequestReceipt && resp.StatusCode == http.StatusAccepted && result.ReceiptSubscription == "" {
			return result, fmt.Errorf("protocol error: missing receipt subscription link in 202 Accepted response")
		}
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return result, nil
	}

	body, err := readLimitedBody(resp)
	if err != nil {
		return result, err
	}

	serviceErr := &PushServiceError{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
	}
	if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
		serviceErr.RetryAfter = parseRetryAfter(c.clock(), retryAfter)
	}
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusGone:
		serviceErr.SubscriptionExpired = true
	case http.StatusTooManyRequests:
		serviceErr.Temporary = true
	default:
		if resp.StatusCode >= 500 {
			serviceErr.Temporary = true
		}
	}
	return result, serviceErr
}

func (c *Client) getVAPIDHeader(endpoint, normalizedSubject string, vapidKeys *VAPIDKeys, expiration time.Time) (string, error) {
	audience, err := audienceFromEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	key := vapidCacheKey{
		audience:  audience,
		subject:   normalizedSubject,
		publicKey: vapidKeys.PublicKeyString(),
		expUnix:   expiration.Unix(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cached, ok := c.vapidCache[key]; ok {
		if c.clock().Before(cached.exp.Add(-time.Minute)) {
			return cached.header, nil
		}
		delete(c.vapidCache, key)
	}

	header, err := c.signVAPID(endpoint, normalizedSubject, vapidKeys, expiration)
	if err != nil {
		return "", err
	}
	c.cacheSeq++
	c.vapidCache[key] = cachedVAPIDHeader{
		header: header,
		exp:    expiration,
		seq:    c.cacheSeq,
	}
	c.evictVAPIDCacheLocked()
	return header, nil
}

func (c *Client) evictVAPIDCacheLocked() {
	now := c.clock()
	for key, cached := range c.vapidCache {
		if !now.Before(cached.exp) {
			delete(c.vapidCache, key)
		}
	}
	for len(c.vapidCache) > c.vapidCacheSize {
		var oldestKey vapidCacheKey
		var oldestSeq uint64 = ^uint64(0)
		for key, cached := range c.vapidCache {
			if cached.seq < oldestSeq {
				oldestSeq = cached.seq
				oldestKey = key
			}
		}
		delete(c.vapidCache, oldestKey)
	}
}

func validateReceiptSubscription(receiptSubscription string) error {
	if receiptSubscription == "" {
		return nil
	}
	if _, err := url.Parse(receiptSubscription); err != nil {
		return fmt.Errorf("invalid receipt subscription: %w", err)
	}
	return nil
}

func formatReceiptSubscriptionLink(receiptSubscription string) string {
	return fmt.Sprintf("<%s>; rel=%q", receiptSubscription, receiptRelation)
}

func parseReceiptSubscription(linkHeaders []string, base *url.URL) string {
	for _, rawHeader := range linkHeaders {
		for _, value := range splitLinkHeader(rawHeader) {
			target, rel := parseLinkValue(value)
			if rel != receiptRelation || target == "" {
				continue
			}
			if resolved, err := resolveReference(base, target); err == nil {
				return resolved
			}
			return target
		}
	}
	return ""
}

func splitLinkHeader(header string) []string {
	parts := make([]string, 0, 1)
	start := 0
	inAngles := false
	inQuotes := false
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '<':
			if !inQuotes {
				inAngles = true
			}
		case '>':
			if !inQuotes {
				inAngles = false
			}
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inAngles && !inQuotes {
				parts = append(parts, strings.TrimSpace(header[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(header) {
		parts = append(parts, strings.TrimSpace(header[start:]))
	}
	return parts
}

func parseLinkValue(value string) (target string, rel string) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "<") {
		return "", ""
	}
	end := strings.IndexByte(value, '>')
	if end == -1 {
		return "", ""
	}
	target = value[1:end]
	params := strings.Split(value[end+1:], ";")
	for _, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		name, val, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "rel") {
			rel = strings.Trim(strings.TrimSpace(val), `"`)
			break
		}
	}
	return target, rel
}

func resolveReference(base *url.URL, ref string) (string, error) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	if base == nil || u.IsAbs() {
		return u.String(), nil
	}
	return base.ResolveReference(u).String(), nil
}

func readLimitedBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body, err
}

func parseRetryAfter(now time.Time, value string) time.Time {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.Atoi(value); err == nil {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if parsed, err := http.ParseTime(value); err == nil {
		return parsed
	}
	return time.Time{}
}

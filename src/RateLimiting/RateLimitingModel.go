package RateLimitingModel

import (
	"time"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// RateLimitQuota represents a quota model for a client
type RateLimitQuota struct {
	ClientID           string `validate:"required,max=64"`
	SubscriptionLevel  string `validate:"required,max=32"`
	MaxRequestsPerMin  int    `validate:"required,gte=0"`
	MaxRequestsPerHour int    `validate:"required,gte=0"`
	MaxRequestsPerDay  int    `validate:"required,gte=0"`
	CreatedAt          time.Time
}

// Validate function for RateLimitQuota
func (r *RateLimitQuota) Validate() error {
	return validate.Struct(r)
}

// RequestCount represents request count tracking
type RequestCount struct {
	ClientID    string `validate:"required,max=64"`
	IPAddress   string `validate:"required,ip"`
	Endpoint    string `validate:"required,max=128"`
	RequestTime time.Time
	Count       int `validate:"required,gte=0"`
}

// QuotaManagement represents a client quota
type QuotaManagement struct {
	ClientID          string `validate:"required,max=64"`
	Quota             int    `validate:"required,gte=0"`
	CurrentUsage      int    `validate:"gte=0"`
	SubscriptionLevel string `validate:"required,max=32"`
	CreatedAt         time.Time
}

// BurstControl tracks burst control configuration and usage
type BurstControl struct {
	ClientID    string `validate:"required,max=64"`
	BurstLimit  int    `validate:"required,gte=0"`
	BurstWindow int    `validate:"required,gte=1"`
	LastBurst   time.Time
}

// SlidingWindow represents request tracking in a sliding window
type SlidingWindow struct {
	ClientID    string `validate:"required,max=64"`
	RequestTime time.Time
}

// IpBasedLimit represents rate limits specific to an IP address
type IpBasedLimit struct {
	IPAddress    string `validate:"required,ip"`
	RequestLimit int    `validate:"required,gte=0"`
	CreatedAt    time.Time
}

// UserBasedLimit represents user-based rate limits
type UserBasedLimit struct {
	ClientID     string `validate:"required,max=64"`
	RequestLimit int    `validate:"required,gte=0"`
	CreatedAt    time.Time
}

// Penalty represents a penalty period for a client
type Penalty struct {
	ClientID        string `validate:"required,max=64"`
	PenaltyStart    time.Time
	PenaltyDuration int    `validate:"required,gte=0"` // Duration in seconds
	Reason          string `validate:"required,max=255"`
}

// NotificationsAndLogging logs notifications and rate limit events
type NotificationsAndLogging struct {
	ClientID         string `validate:"required,max=64"`
	NotificationType string `validate:"required,max=32"`
	Message          string `validate:"required"`
	LogTime          time.Time
}

// Validate function for each struct
func (r *RequestCount) Validate() error {
	return validate.Struct(r)
}

func (q *QuotaManagement) Validate() error {
	return validate.Struct(q)
}

func (b *BurstControl) Validate() error {
	return validate.Struct(b)
}

func (s *SlidingWindow) Validate() error {
	return validate.Struct(s)
}

func (i *IpBasedLimit) Validate() error {
	return validate.Struct(i)
}

func (u *UserBasedLimit) Validate() error {
	return validate.Struct(u)
}

func (p *Penalty) Validate() error {
	return validate.Struct(p)
}

func (n *NotificationsAndLogging) Validate() error {
	return validate.Struct(n)
}

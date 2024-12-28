package LoadBalanceModel

import "time"

// Strategy represents a load-balancing strategy.
type Strategy struct {
	StrategyID  int
	Name        string
	Description string
}

// Server represents a server in the load balancing pool.
type Server struct {
	ServerID    int
	IPAddress   string
	Weight      int
	Location    string
	Status      string
	LastChecked time.Time
}

// RequestLog represents a log of an incoming request.
type RequestLog struct {
	RequestID       int64
	Timestamp       time.Time
	ClientIP        string
	StrategyID      int
	ServerID        int
	ResponseTimeMs  int
	IsStickySession bool
}

// HealthCheckLog represents the results of health checks.
type HealthCheckLog struct {
	CheckID        int64
	ServerID       int
	Timestamp      time.Time
	Status         string
	ResponseTimeMs int
}

// ABTestLog represents logs of A/B testing traffic.
type ABTestLog struct {
	TestID    int
	RequestID int64
	GroupName string
}

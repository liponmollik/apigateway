package broker

import "time"

// Service represents a microservice in the mesh
type Service struct {
	Name     string            // Service name
	Address  string            // Service address (URL or IP:port)
	Metadata map[string]string // Metadata for additional info (optional)
}

// LoadBalancer interface defines the behavior of a load balancer
type LoadBalancer interface {
	Select(serviceName string) (Service, error)
}

// HealthChecker interface defines the behavior for monitoring service health
type HealthChecker interface {
	MonitorHealth(registry *ServiceRegistry, interval time.Duration)
	GetServiceHealth(serviceName string) bool
}

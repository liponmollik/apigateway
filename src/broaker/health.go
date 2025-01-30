package broker

import (
	"net/http"
	"sync"
	"time"
)

type HealthChecker struct {
	mu            sync.RWMutex
	serviceHealth map[string]bool // Map of service name to health status
}

// Create a new health checker
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		serviceHealth: make(map[string]bool),
	}
}

// Check the health of a specific service
func (hc *HealthChecker) CheckServiceHealth(service Service) bool {
	resp, err := http.Get(service.Address + "/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

// Periodically update the health of all services
func (hc *HealthChecker) MonitorHealth(registry *ServiceRegistry, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			services := registry.services
			for serviceName, instances := range services {
				for _, service := range instances {
					isHealthy := hc.CheckServiceHealth(service)
					hc.mu.Lock()
					hc.serviceHealth[serviceName] = isHealthy
					hc.mu.Unlock()
				}
			}
		}
	}()
}

// Get health status of a service
func (hc *HealthChecker) GetServiceHealth(serviceName string) bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.serviceHealth[serviceName]
}

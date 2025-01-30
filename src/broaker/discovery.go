package broker

import (
	"sync"
)

type Service struct {
	Name     string
	Address  string
	Metadata map[string]string
}

type ServiceRegistry struct {
	services map[string][]Service
	mu       sync.RWMutex
}

// Create a new service registry
func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{
		services: make(map[string][]Service),
	}
}

// Register a new service
func (sr *ServiceRegistry) Register(service Service) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.services[service.Name] = append(sr.services[service.Name], service)
}

// Deregister a service
func (sr *ServiceRegistry) Deregister(serviceName, address string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	services := sr.services[serviceName]
	for i, svc := range services {
		if svc.Address == address {
			sr.services[serviceName] = append(services[:i], services[i+1:]...)
			break
		}
	}
}

// Discover services by name
func (sr *ServiceRegistry) Discover(serviceName string) []Service {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.services[serviceName]
}

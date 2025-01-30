package broker

import (
	"sync"
	"time"
)

type Broker struct {
	registry      *ServiceRegistry
	balancer      LoadBalancer
	healthChecker *HealthChecker
	comm          *Communication
	cb            *CircuitBreaker
	mu            sync.Mutex
}

// Create a new broker instance
func NewBroker() *Broker {
	registry := NewServiceRegistry()
	healthChecker := NewHealthChecker()
	balancer := NewRoundRobinBalancer(registry) // Default load balancer
	comm := NewCommunication()
	cb := NewCircuitBreaker(3, 5*time.Second) // Default circuit breaker settings

	return &Broker{
		registry:      registry,
		balancer:      balancer,
		healthChecker: healthChecker,
		comm:          comm,
		cb:            cb,
	}
}

// Register a service
func (b *Broker) RegisterService(service Service) {
	b.registry.Register(service)
}

// Deregister a service
func (b *Broker) DeregisterService(serviceName, address string) {
	b.registry.Deregister(serviceName, address)
}

// Get a healthy service instance using the balancer
func (b *Broker) GetServiceInstance(serviceName string) (Service, error) {
	return b.balancer.Select(serviceName)
}

// Send a request to a service
func (b *Broker) SendRequest(serviceName, endpoint string, payload []byte) ([]byte, error) {
	service, err := b.GetServiceInstance(serviceName)
	if err != nil {
		return nil, err
	}

	// Use the circuit breaker to execute the request
	var response []byte
	executeErr := b.cb.Execute(func() error {
		resp, err := b.comm.Send(service, endpoint, payload)
		response = resp
		return err
	})

	return response, executeErr
}

// Monitor service health
func (b *Broker) MonitorServices(interval time.Duration) {
	b.healthChecker.MonitorHealth(b.registry, interval)
}

// Get service health
func (b *Broker) GetServiceHealth(serviceName string) bool {
	return b.healthChecker.GetServiceHealth(serviceName)
}

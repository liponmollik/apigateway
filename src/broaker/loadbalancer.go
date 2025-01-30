package broker

import (
	"fmt"
	"math/rand"
)

type LoadBalancer interface {
	Select(serviceName string) (Service, error)
}

type RoundRobinBalancer struct {
	registry *ServiceRegistry
	counters map[string]int
}

// Create a new round-robin load balancer
func NewRoundRobinBalancer(registry *ServiceRegistry) *RoundRobinBalancer {
	return &RoundRobinBalancer{
		registry: registry,
		counters: make(map[string]int),
	}
}

// Select a service instance using round-robin
func (rr *RoundRobinBalancer) Select(serviceName string) (Service, error) {
	services := rr.registry.Discover(serviceName)
	if len(services) == 0 {
		return Service{}, fmt.Errorf("no instances found for service: %s", serviceName)
	}
	index := rr.counters[serviceName] % len(services)
	rr.counters[serviceName]++
	return services[index], nil
}

type RandomBalancer struct {
	registry *ServiceRegistry
}

// Create a new random load balancer
func NewRandomBalancer(registry *ServiceRegistry) *RandomBalancer {
	return &RandomBalancer{registry: registry}
}

// Select a service instance using random selection
func (rb *RandomBalancer) Select(serviceName string) (Service, error) {
	services := rb.registry.Discover(serviceName)
	if len(services) == 0 {
		return Service{}, fmt.Errorf("no instances found for service: %s", serviceName)
	}
	index := rand.Intn(len(services))
	return services[index], nil
}

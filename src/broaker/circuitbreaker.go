package broker

import (
	"fmt"
	"sync"
	"time"
)

type CircuitBreaker struct {
	failures   int
	threshold  int
	resetTimer time.Duration
	state      string
	mu         sync.Mutex
}

// Create a new circuit breaker
func NewCircuitBreaker(threshold int, resetTimer time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:  threshold,
		resetTimer: resetTimer,
		state:      "CLOSED",
	}
}

// Execute a protected function
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()
	if cb.state == "OPEN" {
		cb.mu.Unlock()
		return fmt.Errorf("circuit breaker is OPEN")
	}
	cb.mu.Unlock()

	err := fn()
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		if cb.failures >= cb.threshold {
			cb.state = "OPEN"
			go cb.reset()
		}
		return err
	}

	cb.failures = 0
	return nil
}

// Reset the circuit breaker
func (cb *CircuitBreaker) reset() {
	time.Sleep(cb.resetTimer)
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = "CLOSED"
	cb.failures = 0
}

package LoadBalanceManager

import (
	"LoadBalanceModel"
	"LoadBalanceRepository"
)

type LoadBalanceManager struct {
	repo *LoadBalanceRepository.LoadBalanceRepository
}

func NewLoadBalanceManager(repo *LoadBalanceRepository.LoadBalanceRepository) *LoadBalanceManager {
	return &LoadBalanceManager{repo: repo}
}

// RoundRobinBalancing distributes requests in a round-robin fashion.
func (m *LoadBalanceManager) RoundRobinBalancing(request *LoadBalanceModel.RequestLog) error {
	// Implement round-robin logic and call repo.LogRequest
}

// LeastConnectionsBalancing directs requests to the server with the fewest active connections.
func (m *LoadBalanceManager) LeastConnectionsBalancing(request *LoadBalanceModel.RequestLog) error {
	// Implement least connections logic and call repo.LogRequest
}

// Additional methods for other load-balancing strategies...

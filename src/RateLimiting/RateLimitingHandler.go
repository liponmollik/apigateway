package RateLimitingHandler

import (
	"RateLimitingManager" // Importing the new manager package
	"RateLimitingModel"   // Adjust the import path accordingly
	"net/http"

	"github.com/gin-gonic/gin" // Assuming you're using Gin for HTTP handling
)

// RateLimitingHandler provides methods for handling HTTP requests related to rate limiting.
type RateLimitingHandler struct {
	manager *RateLimitingManager.RateLimitingManager
}

// NewRateLimitingHandler creates a new instance of RateLimitingHandler.
func NewRateLimitingHandler(manager *RateLimitingManager.RateLimitingManager) *RateLimitingHandler {
	return &RateLimitingHandler{manager: manager}
}

// SaveQuota handles the HTTP request to save a quota.
func (h *RateLimitingHandler) SaveQuota(c *gin.Context) {
	var quota RateLimitingModel.RateLimitQuota
	if err := c.ShouldBindJSON(&quota); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}
	if err := h.manager.CreateOrUpdateQuota(&quota); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save quota"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Quota saved successfully"})
}

// GetQuota handles the HTTP request to retrieve a quota by client ID.
func (h *RateLimitingHandler) GetQuota(c *gin.Context) {
	clientID := c.Param("client_id")
	quota, err := h.manager.repo.GetQuota(clientID) // Reusing the repository method
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Quota not found"})
		return
	}
	c.JSON(http.StatusOK, quota)
}

func main() {
	r := gin.Default()

	db, err := gorm.Open( /* your DB config here */ )
	if err != nil {
		panic("failed to connect database")
	}

	repo := RateLimitingRepository.NewRateLimitingRepository(db)
	handler := RateLimitingHandler.NewRateLimitingHandler(repo)

	// Routes
	r.POST("/quota", handler.SaveQuota)
	r.GET("/quota/:client_id", handler.GetQuota)
	r.PUT("/quota/:client_id", handler.UpdateQuota)
	r.POST("/request-count", handler.SaveRequestCount)
	r.GET("/request-count/:client_id", handler.GetRequestCount)

	r.Run(":8080") // Start the server
}

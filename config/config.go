package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config struct holds the MySQL database configuration settings.
// This struct is used to configure and manage database connection properties.
type Config struct {
	User                 string            // MySQL Username
	Passwd               string            // MySQL Password (requires User)
	Net                  string            // Network type (e.g., "tcp", "unix", etc.). Default is "tcp".
	Addr                 string            // Address (default: "127.0.0.1:3306" for "tcp")
	DBName               string            // Name of the database to connect to
	Params               map[string]string // Additional connection parameters
	ConnectionAttributes string            // Connection attributes (comma-delimited "key:value" pairs)
	Collation            string            // Collation for connection (e.g., "utf8mb4_general_ci")
	Loc                  *time.Location    // Location for time.Time values (for time zone handling)
	MaxAllowedPacket     int               // Maximum packet size allowed (default is 4MB)
	ServerPubKey         string            // Server public key name for secure connections
	TLSConfig            string            // TLS configuration name (if using named configurations)
	TLS                  *tls.Config       // TLS configuration, higher priority than TLSConfig
	Timeout              time.Duration     // Connection dial timeout
	ReadTimeout          time.Duration     // Read timeout for database I/O
	WriteTimeout         time.Duration     // Write timeout for database I/O
	Logger               Logger            // Logger for output (optional)

	// Additional flags to allow or restrict specific connection behaviors
	AllowAllFiles            bool // Allow using LOAD DATA LOCAL INFILE
	AllowCleartextPasswords  bool // Allow the cleartext client side plugin for authentication
	AllowFallbackToPlaintext bool // Allow fallback to unencrypted connection if TLS fails
	AllowNativePasswords     bool // Allow native password authentication method
	AllowOldPasswords        bool // Allow old password method (insecure)
	CheckConnLiveness        bool // Check if connections are alive before using them
	ClientFoundRows          bool // Return number of matching rows instead of rows changed
	ColumnsWithAlias         bool // Prepend table alias to column names (for clarity)
	InterpolateParams        bool // Interpolate placeholders directly into query string
	MultiStatements          bool // Allow multiple statements in one query
	ParseTime                bool // Parse date/time values into time.Time format
	RejectReadOnly           bool // Reject read-only connections
}

// LoadConfig loads the database configuration from environment variables.
// It uses defaults for some fields but ensures critical fields like User, Passwd, and DBName are set.
// If any critical configuration is missing, an error is returned.
func LoadConfig() (*Config, error) {
	// Convert the MaxAllowedPacket from a string (in environment) to an integer.
	maxAllowedPacket, err := strconv.Atoi(getEnv("MYSQL_MAX_ALLOWED_PACKET", "4194304")) // default 4MB
	if err != nil {
		return nil, fmt.Errorf("invalid MaxAllowedPacket: %v", err)
	}

	// Parse timeout values from environment (use default if not set).
	timeout, err := time.ParseDuration(getEnv("MYSQL_TIMEOUT", "30s"))
	if err != nil {
		return nil, fmt.Errorf("invalid Timeout: %v", err)
	}

	readTimeout, err := time.ParseDuration(getEnv("MYSQL_READ_TIMEOUT", "30s"))
	if err != nil {
		return nil, fmt.Errorf("invalid ReadTimeout: %v", err)
	}

	writeTimeout, err := time.ParseDuration(getEnv("MYSQL_WRITE_TIMEOUT", "30s"))
	if err != nil {
		return nil, fmt.Errorf("invalid WriteTimeout: %v", err)
	}

	// Initialize the configuration struct with values from environment variables.
	// It uses default values for optional fields and returns an error if critical fields are missing.
	config := &Config{
		User:                     os.Getenv("MYSQL_USER"),                                  // MySQL username
		Passwd:                   os.Getenv("MYSQL_PASSWORD"),                              // MySQL password
		Net:                      getEnv("MYSQL_NET", "tcp"),                               // Network type (default is "tcp")
		Addr:                     getEnv("MYSQL_ADDR", "127.0.0.1:3306"),                   // MySQL address and port
		DBName:                   os.Getenv("MYSQL_DBNAME"),                                // Database name
		Collation:                getEnv("MYSQL_COLLATION", "utf8mb4_general_ci"),          // Connection collation
		MaxAllowedPacket:         maxAllowedPacket,                                         // Maximum allowed packet size
		Timeout:                  timeout,                                                  // Dial timeout for connection
		ReadTimeout:              readTimeout,                                              // Read timeout
		WriteTimeout:             writeTimeout,                                             // Write timeout
		AllowCleartextPasswords:  getEnvAsBool("MYSQL_ALLOW_CLEAR_TEXT_PASSWORDS", false),  // Allow cleartext password plugin (default: false)
		AllowFallbackToPlaintext: getEnvAsBool("MYSQL_ALLOW_FALLBACK_TO_PLAINTEXT", false), // Allow fallback to plaintext (default: false)
	}

	// Ensure that critical fields (username, password, and database name) are set.
	if config.User == "" || config.Passwd == "" || config.DBName == "" {
		return nil, fmt.Errorf("missing required MySQL connection settings (MYSQL_USER, MYSQL_PASSWORD, MYSQL_DBNAME)")
	}

	// Return the initialized config struct.
	return config, nil
}

// Helper function to retrieve an environment variable with a fallback value.
// If the variable is not set, it returns the provided fallback value.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

// Helper function to retrieve an environment variable as a boolean.
// It defaults to the provided fallback value if the variable is not set or cannot be parsed as a boolean.
func getEnvAsBool(key string, fallback bool) bool {
	valStr := getEnv(key, "")
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}
	return fallback
}

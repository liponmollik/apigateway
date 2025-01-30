package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/net/context"
)

// RedisConfig holds the Redis configuration
type RedisConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Password     string `json:"password"`
	DB           int    `json:"db"`
	MaxRetries   int    `json:"maxRetries"`
	DialTimeout  int    `json:"dialTimeout"`
	ReadTimeout  int    `json:"readTimeout"`
	WriteTimeout int    `json:"writeTimeout"`
	PoolSize     int    `json:"poolSize"`
	PoolTimeout  int    `json:"poolTimeout"`
}

type Client struct {
	ctx         context.Context
	redisClient *redis.Client
	db          int
}

// MySQLConfig holds the MySQL configuration
type MySQLConfig struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	User            string `json:"user"`
	Password        string `json:"password"`
	Database        string `json:"database"`
	MaxOpenConns    int    `json:"maxOpenConns"`
	MaxIdleConns    int    `json:"maxIdleConns"`
	ConnMaxLifetime string `json:"connMaxLifetime"`
}

// Config holds the application configuration
type Config struct {
	Redis RedisConfig `json:"redis"`
	MySQL MySQLConfig `json:"mysql"`
}

var (
	config          Config
	redisClient     *redis.Client
	mysqlDB         *sql.DB
	ctx             = context.Background()
	MySQLConfigData MySQLConfig
	RedisConfigData RedisConfig
)

// Initialize the configuration
func init() {
	// Load the configuration when the config package is initialized
	configFile, err := os.Open("config/config.json")
	if err != nil {
		fmt.Println("Error opening file:", err)
		log.Fatal(err) // Stop the program on failure
	}
	defer configFile.Close()

	// Decode JSON into the config struct
	decoder := json.NewDecoder(configFile)
	err = decoder.Decode(&config)
	if err != nil {
		fmt.Println("Error decoding config.json:", err)
		log.Fatal(err)
	}

	// Validate Redis configuration
	if config.Redis.Host == "" || config.Redis.Port == 0 {
		log.Fatal("Error: Invalid Redis configuration (Host or Port is missing)")
	} else {
		fmt.Println("Redis configuration loaded successfully")
	}

	// Print the loaded configuration for verification
	fmt.Printf("Config loaded: %+v\n", config)
}

// ConnectRedis establishes a connection to Redis using the loaded configuration
func ConnectRedis() (*redis.Client, error) {
	RedisConfigData = config.Redis

	addr := fmt.Sprintf("%s:%d", RedisConfigData.Host, RedisConfigData.Port)

	log.Printf("Attempting to connect to Redis with host: %s and port: %d\n", RedisConfigData.Host, RedisConfigData.Port)
	log.Printf("Redis connection string: %s\n", addr)
	//RedisConfigData = config.Redis
	//fmt.Printf("RedisConfigData: %+v\n", RedisConfigData)
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     RedisConfigData.Password,
		DB:           RedisConfigData.DB,
		MaxRetries:   RedisConfigData.MaxRetries,
		DialTimeout:  time.Duration(RedisConfigData.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(RedisConfigData.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(RedisConfigData.WriteTimeout) * time.Second,
		PoolSize:     RedisConfigData.PoolSize,
		PoolTimeout:  time.Duration(RedisConfigData.PoolTimeout) * time.Second,
	})

	if err := client.Ping().Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}

// ConnectMySQL establishes a connection to MySQL
func ConnectMySQL() error {
	MySQLConfigData = config.MySQL
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", MySQLConfigData.User, MySQLConfigData.Password, MySQLConfigData.Host, MySQLConfigData.Port, MySQLConfigData.Database)
	var err error

	mysqlDB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("MySQL connection failed: %v", err)
		return err
	}

	mysqlDB.SetMaxOpenConns(MySQLConfigData.MaxOpenConns)
	mysqlDB.SetMaxIdleConns(MySQLConfigData.MaxIdleConns)

	// Set connection lifetime if specified
	if MySQLConfigData.ConnMaxLifetime != "" {
		duration, parseErr := time.ParseDuration(MySQLConfigData.ConnMaxLifetime)
		if parseErr == nil {
			mysqlDB.SetConnMaxLifetime(duration)
		} else {
			log.Printf("Invalid ConnMaxLifetime: %v", parseErr)
		}
	}

	// Test the MySQL connection
	if err = mysqlDB.Ping(); err != nil {
		log.Printf("MySQL ping failed: %v", err)
		return err
	}
	log.Println("Connected to MySQL successfully.")
	return nil
}

// GetMySQLDB provides the MySQL connection for other packages
func GetMySQLDB() *sql.DB {
	return mysqlDB
}

// GetRedisClient provides the Redis client for other packages
func GetRedisClient() *redis.Client {
	return redisClient
}

// CloseConnections closes the database connections
func CloseConnections() {
	if redisClient != nil {
		err := redisClient.Close()
		if err != nil {
			log.Printf("Error closing Redis connection: %v", err)
		} else {
			log.Println("Redis connection closed.")
		}
	}
	if mysqlDB != nil {
		err := mysqlDB.Close()
		if err != nil {
			log.Printf("Error closing MySQL connection: %v", err)
		} else {
			log.Println("MySQL connection closed.")
		}
	}
}

func validateConfig() error {
	if config.Redis.Host == "" || config.Redis.Port == 0 {
		return fmt.Errorf("invalid Redis configuration")
	}
	if config.MySQL.Host == "" || config.MySQL.Port == 0 {
		return fmt.Errorf("invalid MySQL configuration")
	}
	return nil
}

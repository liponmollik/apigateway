package db

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/net/context"
)

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

var (
	redisClient *redis.Client
	mysqlDB     *sql.DB
	ctx         = context.Background()
)

// LoadConfig loads the configuration from a JSON file
func LoadConfig(filePath string, config interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(config)
}

// ConnectRedis establishes a connection to Redis
func ConnectRedis(redisConfig RedisConfig) error {
	redisClient = redis.NewClient(&redis.Options{
		Addr:         redisConfig.Host + ":" + string(redisConfig.Port),
		Password:     redisConfig.Password,
		DB:           redisConfig.DB,
		PoolSize:     redisConfig.PoolSize,
		DialTimeout:  time.Duration(redisConfig.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(redisConfig.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(redisConfig.WriteTimeout) * time.Second,
	})

	// Test the connection
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		log.Printf("Redis connection failed: %v", err)
	}
	return err
}

// ConnectMySQL establishes a connection to MySQL
func ConnectMySQL(mysqlConfig MySQLConfig) error {
	dsn := mysqlConfig.User + ":" + mysqlConfig.Password + "@tcp(" + mysqlConfig.Host + ":" + string(mysqlConfig.Port) + ")/" + mysqlConfig.Database
	var err error
	mysqlDB, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	mysqlDB.SetMaxOpenConns(mysqlConfig.MaxOpenConns)
	mysqlDB.SetMaxIdleConns(mysqlConfig.MaxIdleConns)

	// Set connection lifetime if specified
	if mysqlConfig.ConnMaxLifetime != "" {
		duration, err := time.ParseDuration(mysqlConfig.ConnMaxLifetime)
		if err == nil {
			mysqlDB.SetConnMaxLifetime(duration)
		}
	}

	// Test the connection
	if err = mysqlDB.Ping(); err != nil {
		log.Printf("MySQL connection failed: %v", err)
	}
	return err
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
		redisClient.Close()
	}
	if mysqlDB != nil {
		mysqlDB.Close()
	}
}

package broker

import (
	"log"
	"os"
	"sync"
)

const (
	LogLevelInfo  = "INFO"
	LogLevelDebug = "DEBUG"
	LogLevelError = "ERROR"
)

// Logger is a thread-safe logging utility for the broker.
type Logger struct {
	mu      sync.Mutex
	logFile *os.File
	logger  *log.Logger
	level   string
}

// NewLogger creates a new instance of Logger.
// If filePath is empty, logs will be written to stdout.
func NewLogger(filePath string, level string) (*Logger, error) {
	var logFile *os.File
	var err error

	if filePath != "" {
		logFile, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		logFile = os.Stdout
	}

	return &Logger{
		logFile: logFile,
		logger:  log.New(logFile, "", log.LstdFlags),
		level:   level,
	}, nil
}

// Close closes the log file if it's not stdout.
func (l *Logger) Close() error {
	if l.logFile != os.Stdout {
		return l.logFile.Close()
	}
	return nil
}

// logMessage logs a message with the specified log level.
func (l *Logger) logMessage(level, message string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.shouldLog(level) {
		l.logger.Printf("[%s] %s", level, message)
	}
}

// shouldLog checks if a message with the specified level should be logged.
func (l *Logger) shouldLog(level string) bool {
	switch l.level {
	case LogLevelDebug:
		return true
	case LogLevelInfo:
		return level != LogLevelDebug
	case LogLevelError:
		return level == LogLevelError
	default:
		return false
	}
}

// Info logs an informational message.
func (l *Logger) Info(message string) {
	l.logMessage(LogLevelInfo, message)
}

// Debug logs a debug message.
func (l *Logger) Debug(message string) {
	l.logMessage(LogLevelDebug, message)
}

// Error logs an error message.
func (l *Logger) Error(message string) {
	l.logMessage(LogLevelError, message)
}

// Example of using the Logger
func ExampleLogger() {
	logger, err := NewLogger("broker.log", LogLevelInfo)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Close()

	logger.Info("This is an info message.")
	logger.Debug("This is a debug message.")
	logger.Error("This is an error message.")
}

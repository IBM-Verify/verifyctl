package cmd

import (
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	fileName = "trace.log"
)

type Logger = logrus.Entry

func NewLoggerWithFileOutput() (*Logger, error) {
	path, err := CreateOrGetDir()
	if err != nil {
		return nil, err
	}

	logFile := filepath.Join(path, fileName)
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	contextID := uuid.NewString()
	logger := NewLoggerWithOutput(contextID, file)
	return logger, nil
}

// NewLoggerWithOutput returns a new logger instance with the
// specified context ID and prints out to the
// specified output
func NewLoggerWithOutput(contextID string, output io.Writer) *Logger {

	log := logrus.New()

	// Log based on the requested formatter
	log.SetFormatter(&logrus.JSONFormatter{})

	// Set the output
	log.SetOutput(output)

	// Set the default log level.
	log.SetLevel(logrus.InfoLevel)

	// Include caller method name
	log.SetReportCaller(true)

	return log.WithFields(logrus.Fields{
		"corr_id": contextID,
	})
}

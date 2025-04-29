package cmd

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/ibm-verify/verify-sdk-go/x/logx"
)

const (
	fileName = "trace.log"
)

func NewLogger() (*logx.Logger, io.Writer, error) {
	path, err := CreateOrGetDir()
	if err != nil {
		return nil, nil, err
	}

	logFile := filepath.Join(path, fileName)
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, nil, err
	}

	contextID := uuid.NewString()
	level := slog.LevelInfo
	switch logLevel := os.Getenv("LOG_LEVEL"); logLevel {
	case "error":
		level = slog.LevelError
	case "warn":
		level = slog.LevelWarn
	case "debug":
		level = slog.LevelDebug
	}

	logger := logx.NewLoggerWithWriter(contextID, level, file)
	return logger, file, nil
}

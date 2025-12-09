package util

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"os"
	"strings"
	"time"
)

var globalLog zerolog.Logger

func InitLog(level string, dev bool) {
	var out io.Writer = os.Stdout
	if dev {
		out = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	}
	lvl := zerolog.InfoLevel
	switch strings.ToLower(level) {
	case "debug":
		lvl = zerolog.DebugLevel
	case "info":
		lvl = zerolog.InfoLevel
	case "warn":
		lvl = zerolog.WarnLevel
	case "error":
		lvl = zerolog.ErrorLevel
	}
	zerolog.SetGlobalLevel(lvl)
	globalLog = zerolog.New(out).
		With().
		Timestamp().
		Caller().
		Logger().
		Hook(redactHook{})
	log.Logger = globalLog
}
func Debug() *zerolog.Event { return globalLog.Debug() }
func Info() *zerolog.Event  { return globalLog.Info() }
func Warn() *zerolog.Event  { return globalLog.Warn() }
func Error() *zerolog.Event { return globalLog.Error() }
func Fatal() *zerolog.Event { return globalLog.Fatal() }
func GetLogger() zerolog.Logger {
	return globalLog
}

type redactHook struct{}

func (h redactHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
}

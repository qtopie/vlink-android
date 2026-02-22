package internal

import (
	"fmt"
	"io"
	stdlog "log"
	"os"
)

// Level represents log verbosity levels.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var (
	// currentLevel is the active minimum level to log.
	currentLevel = LevelInfo

	logger = stdlog.New(os.Stderr, "", stdlog.Lshortfile|stdlog.LstdFlags)
)

func levelString(l Level) string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

func shouldLog(l Level) bool {
	return l >= currentLevel
}

// SetLevel sets the active minimum log level.
func SetLevel(l Level) {
	currentLevel = l
}

// SetVerbose is a convenience to enable debug level when true.
func SetVerbose(v bool) {
	if v {
		SetLevel(LevelDebug)
	} else {
		SetLevel(LevelInfo)
	}
}

// output logs the formatted message with given level if allowed. calldepth
// should be set by callers so file/line refer to the original caller.
func output(l Level, calldepth int, format string, v ...interface{}) {
	if !shouldLog(l) {
		return
	}
	prefix := fmt.Sprintf("[%s] ", levelString(l))
	msg := fmt.Sprintf(prefix+format, v...)
	// logger.Output expects calldepth; add 1 to account for this wrapper
	logger.Output(calldepth+1, msg)
	if l == LevelFatal {
		os.Exit(1)
	}
}

// Debugf prints debug-level logs.
func Debugf(format string, v ...interface{}) { output(LevelDebug, 2, format, v...) }

// Infof prints info-level logs.
func Infof(format string, v ...interface{}) { output(LevelInfo, 2, format, v...) }

// Warnf prints warning-level logs.
func Warnf(format string, v ...interface{}) { output(LevelWarn, 2, format, v...) }

// Errorf prints error-level logs.
func Errorf(format string, v ...interface{}) { output(LevelError, 2, format, v...) }

// Fatalf prints fatal-level logs and exits.
func Fatalf(format string, v ...interface{}) { output(LevelFatal, 2, format, v...) }

type logHelper struct {
	prefix string
}

func (l *logHelper) Write(p []byte) (n int, err error) {
	if shouldLog(LevelDebug) {
		// Use Debug level for helper writes
		output(LevelDebug, 2, "%s%s", l.prefix, string(p))
		return len(p), nil
	}
	return len(p), nil
}

func newLogHelper(prefix string) *logHelper { return &logHelper{prefix} }

// NewDebugWriter returns an io.Writer that writes log output with the given prefix
// only when debug/verbose mode is enabled. Useful to pass to other libraries.
func NewDebugWriter(prefix string) io.Writer { return newLogHelper(prefix) }

// legacy internal helper kept for backward compatibility
func logDebugf(format string, v ...interface{}) { Debugf(format, v...) }

func logf(format string, v ...interface{}) { Infof(format, v...) }

func logErrorf(format string, v ...interface{}) { Errorf(format, v...) }

type stdLogBridge struct{}

func (stdLogBridge) Write(p []byte) (n int, err error) {
	// p usually ends with a newline; trim for nicer output
	s := string(p)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	// Route standard log output to INFO level (preserve call depth)
	output(LevelInfo, 3, "%s", s)
	return len(p), nil
}

func init() {
	// Default level respects existing Config.Verbose
	if shouldLog(LevelDebug) {
		SetLevel(LevelDebug)
	} else {
		SetLevel(LevelInfo)
	}
	// Redirect the standard library logger to our internal logger so all
	// existing `log.Printf`, `log.Println`, etc. go through `internal`.
	stdlog.SetFlags(0)
	stdlog.SetOutput(stdLogBridge{})
}

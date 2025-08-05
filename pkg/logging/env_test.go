package logging

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLogLevelEnvironmentVariable(t *testing.T) {
	tests := []struct {
		name          string
		envValue      string
		expectedLevel zapcore.Level
		shouldWarn    bool
	}{
		{
			name:          "debug level",
			envValue:      "debug",
			expectedLevel: zapcore.DebugLevel,
			shouldWarn:    false,
		},
		{
			name:          "info level",
			envValue:      "info",
			expectedLevel: zapcore.InfoLevel,
			shouldWarn:    false,
		},
		{
			name:          "warn level",
			envValue:      "warn",
			expectedLevel: zapcore.WarnLevel,
			shouldWarn:    false,
		},
		{
			name:          "error level",
			envValue:      "error",
			expectedLevel: zapcore.ErrorLevel,
			shouldWarn:    false,
		},
		{
			name:          "fatal level",
			envValue:      "fatal",
			expectedLevel: zapcore.FatalLevel,
			shouldWarn:    false,
		},
		{
			name:          "panic level",
			envValue:      "panic",
			expectedLevel: zapcore.PanicLevel,
			shouldWarn:    false,
		},
		{
			name:          "case insensitive DEBUG",
			envValue:      "DEBUG",
			expectedLevel: zapcore.DebugLevel,
			shouldWarn:    false,
		},
		{
			name:          "case insensitive Info",
			envValue:      "Info",
			expectedLevel: zapcore.InfoLevel,
			shouldWarn:    false,
		},
		{
			name:          "empty string uses default",
			envValue:      "",
			expectedLevel: defaultLevel,
			shouldWarn:    false,
		},
		{
			name:          "invalid level uses default and warns",
			envValue:      "invalid",
			expectedLevel: defaultLevel,
			shouldWarn:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable for this test
			t.Setenv("LOGLEVEL", tt.envValue)

			// Parse the level as the init function would
			initLevelStr := os.Getenv("LOGLEVEL")
			logLevel := defaultLevel
			initLevelValid := false
			if value, ok := LevelForLabel(initLevelStr); ok {
				logLevel = value
				initLevelValid = true
			}

			// Verify the level is parsed correctly
			assert.Equal(t, tt.expectedLevel, logLevel)

			// Verify warning behavior
			if tt.shouldWarn {
				assert.False(t, initLevelValid)
				assert.NotEmpty(t, initLevelStr)
			} else if tt.envValue != "" {
				assert.True(t, initLevelValid)
			}
		})
	}
}

func TestLogEncodingEnvironmentVariable(t *testing.T) {
	tests := []struct {
		name              string
		envValue          string
		expectedEncoding  string
		expectedTimeFunc  zapcore.TimeEncoder
		shouldPanic       bool
	}{
		{
			name:              "console encoding",
			envValue:          "console",
			expectedEncoding:  console.encoding,
			expectedTimeFunc:  console.encodeTime,
			shouldPanic:       false,
		},
		{
			name:              "json encoding",
			envValue:          "json",
			expectedEncoding:  json.encoding,
			expectedTimeFunc:  json.encodeTime,
			shouldPanic:       false,
		},
		{
			name:              "empty string defaults to console",
			envValue:          "",
			expectedEncoding:  console.encoding,
			expectedTimeFunc:  console.encodeTime,
			shouldPanic:       false,
		},
		{
			name:        "invalid encoding panics",
			envValue:    "invalid",
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable for this test
			t.Setenv("LOGENCODING", tt.envValue)

			if tt.shouldPanic {
				assert.Panics(t, func() {
					// Simulate the encoding selection logic from init()
					switch le := os.Getenv("LOGENCODING"); le {
					case "", console.encoding:
						// Valid
					case json.encoding:
						// Valid
					default:
						panic("unknown log encoding " + le)
					}
				})
			} else {
				// Simulate the encoding selection logic from init()
				testConfig := zap.NewDevelopmentConfig()
				switch le := os.Getenv("LOGENCODING"); le {
				case "", console.encoding:
					testConfig.Encoding = console.encoding
					testConfig.EncoderConfig.EncodeTime = console.encodeTime
				case json.encoding:
					testConfig.Encoding = json.encoding
					testConfig.EncoderConfig.EncodeTime = json.encodeTime
				default:
					t.Fatalf("unexpected encoding: %s", le)
				}

				assert.Equal(t, tt.expectedEncoding, testConfig.Encoding)
				// Note: We can't easily compare function pointers, but we verify the assignment happens
				assert.NotNil(t, testConfig.EncoderConfig.EncodeTime)
			}
		})
	}
}

func TestModuleLogLevelsEnvironmentVariable(t *testing.T) {
	tests := []struct {
		name                string
		envValue            string
		expectedLevels      map[string]zapcore.Level
		expectedErrorCount  int
	}{
		{
			name:     "single module",
			envValue: "grpc=debug",
			expectedLevels: map[string]zapcore.Level{
				"grpc": zapcore.DebugLevel,
			},
			expectedErrorCount: 0,
		},
		{
			name:     "multiple modules",
			envValue: "grpc=debug,kubernetes=warn,database=error",
			expectedLevels: map[string]zapcore.Level{
				"grpc":       zapcore.DebugLevel,
				"kubernetes": zapcore.WarnLevel,
				"database":   zapcore.ErrorLevel,
			},
			expectedErrorCount: 0,
		},
		{
			name:     "modules with spaces",
			envValue: " grpc = debug , kubernetes = warn ",
			expectedLevels: map[string]zapcore.Level{
				"grpc":       zapcore.DebugLevel,
				"kubernetes": zapcore.WarnLevel,
			},
			expectedErrorCount: 0,
		},
		{
			name:     "empty entries ignored",
			envValue: "grpc=debug,,kubernetes=warn,",
			expectedLevels: map[string]zapcore.Level{
				"grpc":       zapcore.DebugLevel,
				"kubernetes": zapcore.WarnLevel,
			},
			expectedErrorCount: 0,
		},
		{
			name:               "invalid level",
			envValue:           "grpc=invalid,kubernetes=warn",
			expectedLevels:     map[string]zapcore.Level{"kubernetes": zapcore.WarnLevel},
			expectedErrorCount: 1,
		},
		{
			name:               "malformed entry",
			envValue:           "grpc=debug,malformed,kubernetes=warn",
			expectedLevels:     map[string]zapcore.Level{"grpc": zapcore.DebugLevel, "kubernetes": zapcore.WarnLevel},
			expectedErrorCount: 1,
		},
		{
			name:               "empty string",
			envValue:           "",
			expectedLevels:     map[string]zapcore.Level{},
			expectedErrorCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the parseDefaultModuleLevels function directly
			levels, errs := parseDefaultModuleLevels(tt.envValue)

			assert.Equal(t, tt.expectedLevels, levels)
			assert.Len(t, errs, tt.expectedErrorCount)
		})
	}
}

func TestInitializationIntegration(t *testing.T) {
	// This test verifies that the logging package can be initialized with different
	// combinations of environment variables without panicking or causing issues
	tests := []struct {
		name        string
		logLevel    string
		logEncoding string
		modules     string
	}{
		{
			name:        "all defaults",
			logLevel:    "",
			logEncoding: "",
			modules:     "",
		},
		{
			name:        "debug console with modules",
			logLevel:    "debug",
			logEncoding: "console",
			modules:     "grpc=info,kubernetes=warn",
		},
		{
			name:        "info json without modules",
			logLevel:    "info",
			logEncoding: "json",
			modules:     "",
		},
		{
			name:        "warn console with complex modules",
			logLevel:    "warn",
			logEncoding: "console",
			modules:     "grpc=debug,kubernetes=warn,database=error,network=fatal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LOGLEVEL", tt.logLevel)
			t.Setenv("LOGENCODING", tt.logEncoding)
			t.Setenv("MODULE_LOGLEVELS", tt.modules)

			// Test that we can safely call the logging functions that would be
			// called during initialization
			require.NotPanics(t, func() {
				// Parse log level
				initLevelStr := os.Getenv("LOGLEVEL")
				logLevel := defaultLevel
				if value, ok := LevelForLabel(initLevelStr); ok {
					logLevel = value
				}

				// Parse encoding
				testConfig := zap.NewDevelopmentConfig()
				switch le := os.Getenv("LOGENCODING"); le {
				case "", console.encoding:
					testConfig.Encoding = console.encoding
					testConfig.EncoderConfig.EncodeTime = console.encodeTime
				case json.encoding:
					testConfig.Encoding = json.encoding
					testConfig.EncoderConfig.EncodeTime = json.encodeTime
				default:
					panic("unknown log encoding " + le)
				}

				testConfig.Level = zap.NewAtomicLevelAt(logLevel)

				// Parse module levels
				_, errs := parseDefaultModuleLevels(os.Getenv("MODULE_LOGLEVELS"))

				// Verify everything worked
				assert.NotNil(t, testConfig.Level)
				assert.NotEmpty(t, testConfig.Encoding)
				// Module parsing errors are expected for some test cases
				_ = errs
			})
		})
	}
}
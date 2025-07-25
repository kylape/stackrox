package utils

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	executor := NewExecutor(logger)

	ctx := context.Background()

	t.Run("successful command", func(t *testing.T) {
		result := executor.Execute(ctx, "echo", "hello", "world")
		require.NotNil(t, result)
		assert.True(t, result.Success())
		assert.Equal(t, 0, result.ExitCode)
		assert.Contains(t, result.Stdout, "hello world")
		assert.Greater(t, result.Duration, time.Duration(0))
	})

	t.Run("failed command", func(t *testing.T) {
		result := executor.Execute(ctx, "false")
		require.NotNil(t, result)
		assert.False(t, result.Success())
		assert.Equal(t, 1, result.ExitCode)
	})

	t.Run("command with stderr", func(t *testing.T) {
		result := executor.Execute(ctx, "sh", "-c", "echo error >&2")
		require.NotNil(t, result)
		assert.True(t, result.Success())
		assert.Contains(t, result.Stderr, "error")
	})

	t.Run("dry run", func(t *testing.T) {
		executor.SetDryRun(true)
		result := executor.Execute(ctx, "echo", "should not run")
		require.NotNil(t, result)
		assert.True(t, result.Success()) // Dry run always succeeds
		assert.Empty(t, result.Stdout)   // No actual output
		executor.SetDryRun(false)        // Reset
	})

	t.Run("working directory", func(t *testing.T) {
		tempDir := t.TempDir()
		executor.SetWorkDir(tempDir)
		result := executor.Execute(ctx, "pwd")
		require.NotNil(t, result)
		assert.True(t, result.Success())
		assert.Contains(t, result.Stdout, tempDir)
		executor.SetWorkDir("") // Reset
	})

	t.Run("environment variables", func(t *testing.T) {
		executor.AddEnv("TEST_VAR", "test_value")
		result := executor.Execute(ctx, "sh", "-c", "echo $TEST_VAR")
		require.NotNil(t, result)
		assert.True(t, result.Success())
		assert.Contains(t, result.Stdout, "test_value")
	})
}

func TestExecutorBatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	executor := NewExecutor(logger)

	ctx := context.Background()

	commands := [][]string{
		{"echo", "first"},
		{"echo", "second"},
		{"echo", "third"},
	}

	results := executor.ExecuteBatch(ctx, commands)
	require.Len(t, results, 3)

	for i, result := range results {
		if result != nil {
			assert.True(t, result.Success(), "Command %d should succeed", i)
		}
	}
}

func TestExecutorBatchFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	executor := NewExecutor(logger)

	ctx := context.Background()

	commands := [][]string{
		{"echo", "first"},
		{"false"}, // This will fail
		{"echo", "third"},
	}

	results := executor.ExecuteBatch(ctx, commands)
	require.Len(t, results, 3)

	// First command should succeed
	assert.True(t, results[0].Success())
	
	// Second command should fail
	assert.False(t, results[1].Success())
	
	// Third command should be nil (not executed due to failure)
	assert.Nil(t, results[2])
}

func TestCommandResult(t *testing.T) {
	result := &CommandResult{
		Command:  "echo",
		Args:     []string{"hello"},
		ExitCode: 0,
		Stdout:   "hello\n",
		Stderr:   "",
	}

	assert.True(t, result.Success())
	assert.Equal(t, "hello\n", result.Output())

	// Test with stderr
	result.Stderr = "error\n"
	assert.Equal(t, "hello\n\nerror\n", result.Output())
}
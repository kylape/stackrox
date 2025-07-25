package utils

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Executor handles command execution with logging and context support
type Executor struct {
	logger  *slog.Logger
	dryRun  bool
	workDir string
	env     map[string]string
}

// NewExecutor creates a new executor with the given logger
func NewExecutor(logger *slog.Logger) *Executor {
	return &Executor{
		logger: logger,
		env:    make(map[string]string),
	}
}

// SetDryRun enables or disables dry run mode
func (e *Executor) SetDryRun(dryRun bool) {
	e.dryRun = dryRun
}

// SetWorkDir sets the working directory for commands
func (e *Executor) SetWorkDir(workDir string) {
	e.workDir = workDir
}

// SetEnv sets environment variables for commands
func (e *Executor) SetEnv(env map[string]string) {
	e.env = env
}

// AddEnv adds a single environment variable
func (e *Executor) AddEnv(key, value string) {
	e.env[key] = value
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	ExitCode   int           `json:"exitCode"`
	Duration   time.Duration `json:"duration"`
	Stdout     string        `json:"stdout"`
	Stderr     string        `json:"stderr"`
	Error      error         `json:"error,omitempty"`
	StartTime  time.Time     `json:"startTime"`
	EndTime    time.Time     `json:"endTime"`
}

// Success returns true if the command executed successfully
func (r *CommandResult) Success() bool {
	return r.ExitCode == 0 && r.Error == nil
}

// Output returns the combined stdout and stderr
func (r *CommandResult) Output() string {
	if r.Stderr != "" {
		return r.Stdout + "\n" + r.Stderr
	}
	return r.Stdout
}

// Execute runs a command and returns the result
func (e *Executor) Execute(ctx context.Context, command string, args ...string) *CommandResult {
	result := &CommandResult{
		Command:   command,
		Args:      args,
		StartTime: time.Now(),
	}

	// Log command execution
	cmdStr := fmt.Sprintf("%s %s", command, strings.Join(args, " "))
	e.logger.Info("Executing command", "command", cmdStr, "workDir", e.workDir)

	// Handle dry run
	if e.dryRun {
		e.logger.Info("Dry run: would execute command", "command", cmdStr)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// Create command
	cmd := exec.CommandContext(ctx, command, args...)
	
	// Set working directory
	if e.workDir != "" {
		cmd.Dir = e.workDir
	}

	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range e.env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Execute command and capture output
	stdout, stderr, err := e.runCommand(cmd)
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Stdout = stdout
	result.Stderr = stderr
	result.Error = err

	// Set exit code
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	// Log result
	if result.Success() {
		e.logger.Info("Command completed successfully", 
			"command", cmdStr, 
			"duration", result.Duration,
			"exitCode", result.ExitCode)
	} else {
		e.logger.Error("Command failed", 
			"command", cmdStr, 
			"duration", result.Duration,
			"exitCode", result.ExitCode,
			"error", err,
			"stderr", stderr)
	}

	return result
}

// ExecuteWithStreaming runs a command and streams output to the logger
func (e *Executor) ExecuteWithStreaming(ctx context.Context, command string, args ...string) *CommandResult {
	result := &CommandResult{
		Command:   command,
		Args:      args,
		StartTime: time.Now(),
	}

	cmdStr := fmt.Sprintf("%s %s", command, strings.Join(args, " "))
	e.logger.Info("Executing command with streaming", "command", cmdStr, "workDir", e.workDir)

	if e.dryRun {
		e.logger.Info("Dry run: would execute command with streaming", "command", cmdStr)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// Create command
	cmd := exec.CommandContext(ctx, command, args...)
	
	if e.workDir != "" {
		cmd.Dir = e.workDir
	}

	cmd.Env = os.Environ()
	for key, value := range e.env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Create pipes for streaming output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stdout pipe: %w", err)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stderr pipe: %w", err)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// Start command
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("failed to start command: %w", err)
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// Stream output
	var stdoutBuilder, stderrBuilder strings.Builder
	
	// Start goroutines to stream output
	done := make(chan bool, 2)
	
	go e.streamOutput(stdout, "stdout", &stdoutBuilder, done)
	go e.streamOutput(stderr, "stderr", &stderrBuilder, done)

	// Wait for streaming to complete
	<-done
	<-done

	// Wait for command to complete
	err = cmd.Wait()
	
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Stdout = stdoutBuilder.String()
	result.Stderr = stderrBuilder.String()
	result.Error = err

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	return result
}

// runCommand executes a command and captures its output
func (e *Executor) runCommand(cmd *exec.Cmd) (string, string, error) {
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// streamOutput streams command output line by line to the logger
func (e *Executor) streamOutput(reader interface{}, streamName string, builder *strings.Builder, done chan bool) {
	defer func() { done <- true }()
	
	scanner := bufio.NewScanner(reader.(interface{ Read([]byte) (int, error) }))
	for scanner.Scan() {
		line := scanner.Text()
		builder.WriteString(line + "\n")
		e.logger.Info("Command output", "stream", streamName, "line", line)
	}
}

// ExecuteBatch executes multiple commands in sequence
func (e *Executor) ExecuteBatch(ctx context.Context, commands [][]string) []*CommandResult {
	results := make([]*CommandResult, len(commands))
	
	for i, cmd := range commands {
		if len(cmd) == 0 {
			continue
		}
		
		command := cmd[0]
		args := cmd[1:]
		
		results[i] = e.Execute(ctx, command, args...)
		
		// Stop on first failure unless in dry run mode
		if !e.dryRun && !results[i].Success() {
			e.logger.Error("Batch execution stopped due to command failure", 
				"command", command, 
				"index", i,
				"error", results[i].Error)
			break
		}
	}
	
	return results
}

// MustExecute executes a command and panics if it fails
func (e *Executor) MustExecute(ctx context.Context, command string, args ...string) *CommandResult {
	result := e.Execute(ctx, command, args...)
	if !result.Success() {
		panic(fmt.Sprintf("Command failed: %s %s, error: %v", command, strings.Join(args, " "), result.Error))
	}
	return result
}
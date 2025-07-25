package utils

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
	MaxAttempts int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	Jitter       bool
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       true,
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func() error

// RetryWithResultFunc is a function that can be retried and returns a result
type RetryWithResultFunc func() (interface{}, error)

// RetryResult contains the result of a retry operation
type RetryResult struct {
	Attempts  int           `json:"attempts"`
	Duration  time.Duration `json:"duration"`
	Success   bool          `json:"success"`
	LastError error         `json:"lastError,omitempty"`
}

// Retryer handles retry logic with configurable backoff
type Retryer struct {
	config RetryConfig
	logger *slog.Logger
}

// NewRetryer creates a new retryer with the given configuration
func NewRetryer(config RetryConfig, logger *slog.Logger) *Retryer {
	return &Retryer{
		config: config,
		logger: logger,
	}
}

// NewDefaultRetryer creates a new retryer with default configuration
func NewDefaultRetryer(logger *slog.Logger) *Retryer {
	return NewRetryer(DefaultRetryConfig(), logger)
}

// Retry executes a function with retry logic
func (r *Retryer) Retry(ctx context.Context, name string, fn RetryableFunc) *RetryResult {
	result := &RetryResult{
		Attempts: 0,
	}
	
	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	delay := r.config.InitialDelay
	
	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		result.Attempts = attempt
		
		r.logger.Info("Retry attempt", 
			"name", name,
			"attempt", attempt, 
			"maxAttempts", r.config.MaxAttempts)
		
		err := fn()
		if err == nil {
			result.Success = true
			r.logger.Info("Retry succeeded", 
				"name", name,
				"attempt", attempt,
				"duration", time.Since(start))
			return result
		}
		
		result.LastError = err
		
		r.logger.Warn("Retry attempt failed", 
			"name", name,
			"attempt", attempt,
			"error", err)
		
		// Don't sleep after the last attempt
		if attempt < r.config.MaxAttempts {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				result.LastError = fmt.Errorf("retry cancelled: %w", ctx.Err())
				r.logger.Info("Retry cancelled due to context", "name", name)
				return result
			default:
			}
			
			r.logger.Info("Waiting before next retry", 
				"name", name,
				"delay", delay)
			
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				result.LastError = fmt.Errorf("retry cancelled: %w", ctx.Err())
				r.logger.Info("Retry cancelled during delay", "name", name)
				return result
			case <-timer.C:
			}
			
			// Calculate next delay with exponential backoff
			delay = r.calculateNextDelay(delay)
		}
	}
	
	r.logger.Error("Retry failed after all attempts", 
		"name", name,
		"attempts", result.Attempts,
		"lastError", result.LastError,
		"duration", result.Duration)
	
	return result
}

// RetryWithResult executes a function with retry logic and returns a result
func (r *Retryer) RetryWithResult(ctx context.Context, name string, fn RetryWithResultFunc) (interface{}, *RetryResult) {
	result := &RetryResult{
		Attempts: 0,
	}
	
	start := time.Now()
	defer func() {
		result.Duration = time.Since(start)
	}()

	delay := r.config.InitialDelay
	
	for attempt := 1; attempt <= r.config.MaxAttempts; attempt++ {
		result.Attempts = attempt
		
		r.logger.Info("Retry with result attempt", 
			"name", name,
			"attempt", attempt, 
			"maxAttempts", r.config.MaxAttempts)
		
		value, err := fn()
		if err == nil {
			result.Success = true
			r.logger.Info("Retry with result succeeded", 
				"name", name,
				"attempt", attempt,
				"duration", time.Since(start))
			return value, result
		}
		
		result.LastError = err
		
		r.logger.Warn("Retry with result attempt failed", 
			"name", name,
			"attempt", attempt,
			"error", err)
		
		// Don't sleep after the last attempt
		if attempt < r.config.MaxAttempts {
			// Check if context is cancelled
			select {
			case <-ctx.Done():
				result.LastError = fmt.Errorf("retry cancelled: %w", ctx.Err())
				r.logger.Info("Retry with result cancelled due to context", "name", name)
				return nil, result
			default:
			}
			
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				result.LastError = fmt.Errorf("retry cancelled: %w", ctx.Err())
				r.logger.Info("Retry with result cancelled during delay", "name", name)
				return nil, result
			case <-timer.C:
			}
			
			delay = r.calculateNextDelay(delay)
		}
	}
	
	r.logger.Error("Retry with result failed after all attempts", 
		"name", name,
		"attempts", result.Attempts,
		"lastError", result.LastError,
		"duration", result.Duration)
	
	return nil, result
}

// calculateNextDelay calculates the next delay using exponential backoff
func (r *Retryer) calculateNextDelay(currentDelay time.Duration) time.Duration {
	nextDelay := time.Duration(float64(currentDelay) * r.config.Multiplier)
	
	// Apply maximum delay limit
	if nextDelay > r.config.MaxDelay {
		nextDelay = r.config.MaxDelay
	}
	
	// Apply jitter if enabled
	if r.config.Jitter {
		// Add up to 10% jitter
		jitterRange := float64(nextDelay) * 0.1
		jitter := time.Duration(jitterRange * (2*random() - 1)) // -10% to +10%
		nextDelay += jitter
		
		// Ensure we don't go below initial delay or above max delay
		if nextDelay < r.config.InitialDelay {
			nextDelay = r.config.InitialDelay
		}
		if nextDelay > r.config.MaxDelay {
			nextDelay = r.config.MaxDelay
		}
	}
	
	return nextDelay
}

// Simple random function for jitter (using time-based seed)
func random() float64 {
	// Simple pseudo-random based on current time
	return float64(time.Now().UnixNano()%1000) / 1000.0
}

// RetryUntilSuccess retries a function until it succeeds or context is cancelled
func (r *Retryer) RetryUntilSuccess(ctx context.Context, name string, fn RetryableFunc, checkInterval time.Duration) error {
	r.logger.Info("Starting retry until success", "name", name, "checkInterval", checkInterval)
	
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("Retry until success cancelled", "name", name)
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		default:
		}
		
		err := fn()
		if err == nil {
			r.logger.Info("Retry until success completed", "name", name)
			return nil
		}
		
		r.logger.Warn("Retry until success failed, will retry", "name", name, "error", err)
		
		timer := time.NewTimer(checkInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			r.logger.Info("Retry until success cancelled during wait", "name", name)
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

// WaitFor waits for a condition to become true
func (r *Retryer) WaitFor(ctx context.Context, name string, condition func() bool, checkInterval time.Duration, timeout time.Duration) error {
	r.logger.Info("Waiting for condition", "name", name, "checkInterval", checkInterval, "timeout", timeout)
	
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				r.logger.Error("Wait for condition timed out", "name", name, "timeout", timeout)
				return fmt.Errorf("wait for condition %s timed out after %v", name, timeout)
			}
			r.logger.Info("Wait for condition cancelled", "name", name)
			return fmt.Errorf("wait cancelled: %w", ctx.Err())
		default:
		}
		
		if condition() {
			r.logger.Info("Wait for condition completed", "name", name)
			return nil
		}
		
		timer := time.NewTimer(checkInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// RetryableError represents an error that can be retried
type RetryableError struct {
	Err       error
	Retryable bool
}

func (e RetryableError) Error() string {
	return e.Err.Error()
}

func (e RetryableError) Unwrap() error {
	return e.Err
}

// NewRetryableError creates a new retryable error
func NewRetryableError(err error) RetryableError {
	return RetryableError{Err: err, Retryable: true}
}

// NewNonRetryableError creates a new non-retryable error
func NewNonRetryableError(err error) RetryableError {
	return RetryableError{Err: err, Retryable: false}
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if retryableErr, ok := err.(RetryableError); ok {
		return retryableErr.Retryable
	}
	// By default, assume errors are retryable
	return true
}
package enricher

import (
	"github.com/stackrox/rox/pkg/sync"
)

var (
	enricherInstance VMVulnerabilityEnricher
	enricherInit     sync.Once
)

// Singleton returns the singleton instance of the VM vulnerability enricher.
func Singleton() VMVulnerabilityEnricher {
	enricherInit.Do(func() {
		// TODO: In a real implementation, this should use proper Scanner V4 client configuration
		// For now, this is a placeholder that would need to be integrated with the actual Scanner V4 setup
		enricherInstance = newEnricherWithDefaults()
	})
	return enricherInstance
}

// newEnricherWithDefaults creates a default VM enricher instance
// NOTE: This is a placeholder implementation. In production, this should be properly configured
// with the actual Scanner V4 client configuration from the environment or configuration.
func newEnricherWithDefaults() VMVulnerabilityEnricher {
	// TODO: Replace with actual Scanner V4 client initialization
	// This would typically involve reading configuration from environment variables
	// or configuration files to set up the Scanner V4 endpoints.

	// For now, return nil to indicate that this needs proper configuration
	// In the actual implementation, this would create a proper Scanner V4 client:
	//
	// scannerClient, err := client.NewGRPCScanner(ctx,
	//     client.WithIndexerAddress(indexerEndpoint),
	//     client.WithMatcherAddress(matcherEndpoint),
	// )
	// if err != nil {
	//     return nil
	// }
	//
	// vmEnricher := vmEnricher.New(scannerClient)
	// return New(vmEnricher)

	return nil
}

// SetSingleton sets the singleton instance. This is primarily for testing purposes.
func SetSingleton(enricher VMVulnerabilityEnricher) {
	enricherInstance = enricher
}

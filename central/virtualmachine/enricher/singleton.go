package enricher

import (
	"context"

	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/scannerv4/client"
	"github.com/stackrox/rox/pkg/sync"
	vmEnricher "github.com/stackrox/rox/pkg/virtualmachine/enricher"
)

var (
	enricherInstance VMVulnerabilityEnricher
	enricherInit     sync.Once
	log              = logging.LoggerForModule()
)

// Singleton returns the singleton instance of the VM vulnerability enricher.
func Singleton() VMVulnerabilityEnricher {
	enricherInit.Do(func() {
		enricherInstance = newEnricherWithDefaults()
	})
	return enricherInstance
}

// newEnricherWithDefaults creates a default VM enricher instance using Scanner V4 client configuration
func newEnricherWithDefaults() VMVulnerabilityEnricher {
	ctx := context.Background()

	// Create Scanner V4 client with default configuration
	// The client will automatically use the configured namespace and service endpoints
	scannerClient, err := client.NewGRPCScanner(ctx,
		client.WithIndexerAddress(getIndexerAddress()),
		client.WithMatcherAddress(getMatcherAddress()),
	)
	if err != nil {
		log.Errorf("Failed to create Scanner V4 client: %v", err)
		return nil
	}

	// Create the VM enricher using the Scanner V4 client
	vmEnricher := vmEnricher.New(scannerClient)
	return New(vmEnricher)
}

// getIndexerAddress returns the Scanner V4 indexer service address
func getIndexerAddress() string {
	// Default indexer address using the current namespace
	return "scanner-v4-indexer." + env.Namespace.Setting() + ".svc:8443"
}

// getMatcherAddress returns the Scanner V4 matcher service address
func getMatcherAddress() string {
	// Default matcher address using the current namespace
	return "scanner-v4-matcher." + env.Namespace.Setting() + ".svc:8443"
}

// SetSingleton sets the singleton instance. This is primarily for testing purposes.
func SetSingleton(enricher VMVulnerabilityEnricher) {
	enricherInstance = enricher
}

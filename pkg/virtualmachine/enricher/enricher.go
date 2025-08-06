package enricher

import (
	"context"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scanners/scannerv4"
	"github.com/stackrox/rox/pkg/scannerv4/client"
)

// VMEnricher provides functions for enriching virtual machines with vulnerability data.
//
//go:generate mockgen-wrapper
type VMEnricher interface {
	// EnrichVM enriches a VM with vulnerability scan data using existing components
	EnrichVM(ctx context.Context, vm *storage.VirtualMachine) error

	// EnrichVMWithPackages enriches a VM with vulnerability scan data using provided packages
	EnrichVMWithPackages(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, distribution *scannerv4.VMDistribution) error

	// EnrichVMWithFacts enriches a VM with vulnerability scan data, extracting distribution info from VM facts
	EnrichVMWithFacts(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error
}

// New returns a new VMEnricher using the provided Scanner V4 client
func New(scannerClient client.Scanner) VMEnricher {
	return &enricherImpl{
		vmEnricher: scannerv4.NewVMVulnerabilityEnricher(scannerClient),
	}
}

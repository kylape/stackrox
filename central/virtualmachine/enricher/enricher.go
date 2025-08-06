package enricher

import (
	"context"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scanners/scannerv4"
	vmEnricher "github.com/stackrox/rox/pkg/virtualmachine/enricher"
)

// VMVulnerabilityEnricher provides functionality to enrich VMs with vulnerability data using Scanner V4
//
//go:generate mockgen-wrapper
type VMVulnerabilityEnricher interface {
	// EnrichVMWithVulnerabilities enriches a VM with vulnerability scan data using existing components
	EnrichVMWithVulnerabilities(ctx context.Context, vm *storage.VirtualMachine) error

	// EnrichVMWithPackagesAndFacts enriches a VM with vulnerability data using provided packages and facts
	EnrichVMWithPackagesAndFacts(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error

	// CreateVMScanFromPackages creates a vulnerability scan for a VM using provided package data
	CreateVMScanFromPackages(ctx context.Context, vmID string, packages []*scannerv4.VMPackageData, facts map[string]string) (*storage.VirtualMachineScan, error)
}

// enricherImpl provides the implementation for VM vulnerability enrichment
type enricherImpl struct {
	vmEnricher vmEnricher.VMEnricher
}

// New creates a new VM vulnerability enricher using the provided VM enricher
func New(vmEnricher vmEnricher.VMEnricher) VMVulnerabilityEnricher {
	return &enricherImpl{
		vmEnricher: vmEnricher,
	}
}

// EnrichVMWithVulnerabilities enriches a VM with vulnerability scan data using existing components
func (e *enricherImpl) EnrichVMWithVulnerabilities(ctx context.Context, vm *storage.VirtualMachine) error {
	return e.vmEnricher.EnrichVM(ctx, vm)
}

// EnrichVMWithPackagesAndFacts enriches a VM with vulnerability data using provided packages and facts
func (e *enricherImpl) EnrichVMWithPackagesAndFacts(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
	return e.vmEnricher.EnrichVMWithFacts(ctx, vm, packages, facts)
}

// CreateVMScanFromPackages creates a vulnerability scan for a VM using provided package data
func (e *enricherImpl) CreateVMScanFromPackages(ctx context.Context, vmID string, packages []*scannerv4.VMPackageData, facts map[string]string) (*storage.VirtualMachineScan, error) {
	// Create a temporary VM for scanning purposes
	tempVM := &storage.VirtualMachine{
		Id:    vmID,
		Facts: facts,
	}

	err := e.vmEnricher.EnrichVMWithFacts(ctx, tempVM, packages, facts)
	if err != nil {
		return nil, err
	}

	return tempVM.Scan, nil
}
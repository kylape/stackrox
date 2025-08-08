package enricher

import (
	"context"
	"fmt"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/scanners/scannerv4"
)

var _ VMEnricher = (*enricherImpl)(nil)

var (
	log = logging.LoggerForModule()
)

type enricherImpl struct {
	vmMatcher *scannerv4.VMVulnerabilityMatcher
}

// EnrichVM enriches a VM with vulnerability scan data using existing components
func (e *enricherImpl) EnrichVM(ctx context.Context, vm *storage.VirtualMachine) error {
	if vm == nil {
		return fmt.Errorf("VM cannot be nil")
	}

	log.Debugf("Enriching VM %s with existing components", vm.GetId())

	// Extract distribution info from VM facts if available
	var distribution *scannerv4.VMDistribution
	if vm.GetFacts() != nil {
		distribution = scannerv4.ExtractVMDistributionFromFacts(vm.GetFacts())
	}

	// Use the matcher to get the scan, then update the VM
	scan, err := e.vmMatcher.MatchVulnerabilitiesFromComponents(ctx, vm, distribution)
	if err != nil {
		return fmt.Errorf("enriching VM %s: %w", vm.GetId(), err)
	}

	// Update VM with scan results
	vm.Scan = scan
	vm.LastUpdated = scan.GetScanTime()

	log.Infof("Successfully enriched VM %s with vulnerabilities", vm.GetId())
	return nil
}

// EnrichVMWithPackages enriches a VM with vulnerability scan data using provided packages
func (e *enricherImpl) EnrichVMWithPackages(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, distribution *scannerv4.VMDistribution) error {
	if vm == nil {
		return fmt.Errorf("VM cannot be nil")
	}

	log.Debugf("Enriching VM %s with %d provided packages", vm.GetId(), len(packages))

	// Use the matcher to get the scan, then update the VM
	scan, err := e.vmMatcher.MatchVulnerabilities(ctx, vm, packages, distribution)
	if err != nil {
		return fmt.Errorf("enriching VM %s with packages: %w", vm.GetId(), err)
	}

	// Update VM with scan results
	vm.Scan = scan
	vm.LastUpdated = scan.GetScanTime()

	log.Infof("Successfully enriched VM %s with vulnerabilities from %d packages", vm.GetId(), len(packages))
	return nil
}

// EnrichVMWithFacts enriches a VM with vulnerability scan data, extracting distribution info from VM facts
func (e *enricherImpl) EnrichVMWithFacts(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
	if vm == nil {
		return fmt.Errorf("VM cannot be nil")
	}

	log.Debugf("Enriching VM %s with %d packages and extracting distribution from facts", vm.GetId(), len(packages))

	// Extract distribution information from facts
	distribution := scannerv4.ExtractVMDistributionFromFacts(facts)
	if distribution != nil {
		log.Debugf("Extracted distribution %s %s for VM %s", distribution.Name, distribution.Version, vm.GetId())
	} else {
		log.Debugf("No distribution information found in facts for VM %s", vm.GetId())
	}

	// Use the matcher to get the scan, then update the VM
	scan, err := e.vmMatcher.MatchVulnerabilities(ctx, vm, packages, distribution)
	if err != nil {
		return fmt.Errorf("enriching VM %s with facts: %w", vm.GetId(), err)
	}

	// Update VM with scan results
	vm.Scan = scan
	vm.LastUpdated = scan.GetScanTime()

	log.Infof("Successfully enriched VM %s with vulnerabilities from %d packages and facts", vm.GetId(), len(packages))
	return nil
}

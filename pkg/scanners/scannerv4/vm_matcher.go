package scannerv4

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scannerv4/client"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	// VMMockDigest is a mock digest used for VM scanning (following node scanning pattern)
	VMMockDigest = "registry/repository@sha256:deadb33fdeadb33fdeadb33fdeadb33fdeadb33fdeadb33fdeadb33fdeadb33f"
	
	// VMScanTimeout defines timeout for VM vulnerability scanning
	VMScanTimeout = 5 * time.Minute
)

// VMVulnerabilityMatcher provides vulnerability matching for Virtual Machines
type VMVulnerabilityMatcher struct {
	scannerClient client.Scanner
}

// NewVMVulnerabilityMatcher creates a new VM vulnerability matcher
func NewVMVulnerabilityMatcher(scannerClient client.Scanner) *VMVulnerabilityMatcher {
	if scannerClient == nil {
		utils.CrashOnError(fmt.Errorf("scanner client cannot be nil"))
	}
	return &VMVulnerabilityMatcher{
		scannerClient: scannerClient,
	}
}

// MatchVulnerabilities performs vulnerability matching for a VM's package data
func (m *VMVulnerabilityMatcher) MatchVulnerabilities(ctx context.Context, vm *storage.VirtualMachine, packages []*VMPackageData, distribution *VMDistribution) (*storage.VirtualMachineScan, error) {
	if vm == nil {
		return nil, fmt.Errorf("VM cannot be nil")
	}
	
	if len(packages) == 0 {
		log.Debugf("No packages provided for VM %s, returning scan with no packages note", vm.GetId())
		return &storage.VirtualMachineScan{
			ScannerVersion: "Scanner V4", 
			DataSource:     &storage.DataSource{Name: "Scanner V4"},
			Notes:          []storage.VirtualMachineScan_Note{storage.VirtualMachineScan_PARTIAL_SCAN_DATA},
		}, nil
	}

	// Validate package data before processing
	if err := ValidateVMPackageData(packages); err != nil {
		return nil, fmt.Errorf("invalid package data for VM %s: %w", vm.GetId(), err)
	}

	// Convert VM package data to IndexReport format
	indexReport, err := ToVMIndexReport(vm.GetId(), packages, distribution)
	if err != nil {
		return nil, fmt.Errorf("creating VM IndexReport for VM %s: %w", vm.GetId(), err)
	}

	// Perform vulnerability matching with Scanner V4
	vulnerabilityReport, err := m.getVMVulnerabilityReport(ctx, vm.GetId(), indexReport)
	if err != nil {
		return nil, fmt.Errorf("getting vulnerability report for VM %s: %w", vm.GetId(), err)
	}

	// Convert Scanner V4 results to storage format
	vmScan := ToVMScan(vulnerabilityReport, vm.GetId())
	
	log.Infof("VM vulnerability matching completed for VM %s: found %d components with vulnerabilities", 
		vm.GetId(), len(vmScan.GetComponents()))
	
	return vmScan, nil
}

// MatchVulnerabilitiesFromComponents extracts packages from existing components and performs matching
func (m *VMVulnerabilityMatcher) MatchVulnerabilitiesFromComponents(ctx context.Context, vm *storage.VirtualMachine, distribution *VMDistribution) (*storage.VirtualMachineScan, error) {
	if vm == nil {
		return nil, fmt.Errorf("VM cannot be nil")
	}

	// Extract package data from existing VM scan components
	var components []*storage.EmbeddedImageScanComponent
	if vm.GetScan() != nil {
		components = vm.GetScan().GetComponents()
	}
	
	packages := VMPackageDataFromStorageComponents(components)
	return m.MatchVulnerabilities(ctx, vm, packages, distribution)
}

// getVMVulnerabilityReport makes the Scanner V4 request to get vulnerabilities
func (m *VMVulnerabilityMatcher) getVMVulnerabilityReport(ctx context.Context, vmID string, indexReport *v4.IndexReport) (*v4.VulnerabilityReport, error) {
	log.Debugf("Requesting vulnerability scan for VM %s", vmID)
	
	// Parse mock digest for VM scanning (following node scanning pattern)
	vmDigest, err := name.NewDigest(VMMockDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse digest for VM %s: %w", vmID, err)
	}

	// Create context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, VMScanTimeout)
	defer cancel()

	// Call Scanner V4 to get vulnerabilities
	vulnerabilityReport, err := m.scannerClient.GetVulnerabilities(scanCtx, vmDigest, indexReport.GetContents())
	if err != nil {
		return nil, errors.Wrap(err, "Scanner V4 client call to GetVulnerabilities")
	}

	if vulnerabilityReport == nil {
		return nil, fmt.Errorf("received nil vulnerability report for VM %s", vmID)
	}

	log.Debugf("VM vulnerability scan succeeded for VM %s", vmID)
	return vulnerabilityReport, nil
}

// VMVulnerabilityEnricher enriches a VM with vulnerability scan results
type VMVulnerabilityEnricher struct {
	matcher *VMVulnerabilityMatcher
}

// NewVMVulnerabilityEnricher creates a new VM vulnerability enricher
func NewVMVulnerabilityEnricher(scannerClient client.Scanner) *VMVulnerabilityEnricher {
	return &VMVulnerabilityEnricher{
		matcher: NewVMVulnerabilityMatcher(scannerClient),
	}
}

// EnrichVM enriches a VM with vulnerability scan data using existing components
func (e *VMVulnerabilityEnricher) EnrichVM(ctx context.Context, vm *storage.VirtualMachine, distribution *VMDistribution) error {
	if vm == nil {
		return fmt.Errorf("VM cannot be nil")
	}

	scan, err := e.matcher.MatchVulnerabilitiesFromComponents(ctx, vm, distribution)
	if err != nil {
		return fmt.Errorf("matching vulnerabilities for VM %s: %w", vm.GetId(), err)
	}

	// Update VM with scan results
	vm.Scan = scan
	vm.LastUpdated = scan.GetScanTime()

	return nil
}

// EnrichVMWithPackages enriches a VM with vulnerability scan data using provided packages
func (e *VMVulnerabilityEnricher) EnrichVMWithPackages(ctx context.Context, vm *storage.VirtualMachine, packages []*VMPackageData, distribution *VMDistribution) error {
	if vm == nil {
		return fmt.Errorf("VM cannot be nil")
	}

	scan, err := e.matcher.MatchVulnerabilities(ctx, vm, packages, distribution)
	if err != nil {
		return fmt.Errorf("matching vulnerabilities for VM %s: %w", vm.GetId(), err)
	}

	// Update VM with scan results
	vm.Scan = scan
	vm.LastUpdated = scan.GetScanTime()

	return nil
}

// ValidateVMPackageData validates VM package data before processing
func ValidateVMPackageData(packages []*VMPackageData) error {
	if len(packages) == 0 {
		return fmt.Errorf("no packages provided")
	}

	for i, pkg := range packages {
		if pkg == nil {
			return fmt.Errorf("package at index %d is nil", i)
		}
		if pkg.Name == "" {
			return fmt.Errorf("package at index %d has empty name", i)
		}
		if pkg.Version == "" {
			return fmt.Errorf("package %s has empty version", pkg.Name)
		}
	}
	
	return nil
}

// ExtractVMDistributionFromFacts creates VMDistribution from VM facts
func ExtractVMDistributionFromFacts(facts map[string]string) *VMDistribution {
	if facts == nil {
		return nil
	}

	// Look for common OS identification fields in VM facts
	var name, version, versionID, cpe string
	
	// Check various possible fact keys
	if osName, ok := facts["os_name"]; ok {
		name = osName
	} else if osName, ok := facts["OS_NAME"]; ok {
		name = osName
	} else if osName, ok := facts["operating_system"]; ok {
		name = osName
	}

	if osVersion, ok := facts["os_version"]; ok {
		version = osVersion
	} else if osVersion, ok := facts["OS_VERSION"]; ok {
		version = osVersion
	} else if osVersion, ok := facts["version"]; ok {
		version = osVersion
	}

	if osVersionID, ok := facts["os_version_id"]; ok {
		versionID = osVersionID
	} else if osVersionID, ok := facts["VERSION_ID"]; ok {
		versionID = osVersionID
	}

	if osCPE, ok := facts["os_cpe"]; ok {
		cpe = osCPE
	} else if osCPE, ok := facts["CPE_NAME"]; ok {
		cpe = osCPE
	}

	// Only create distribution if we have at least name
	if name == "" {
		return nil
	}

	return &VMDistribution{
		Name:      name,
		Version:   version,
		VersionID: versionID,
		CPE:       cpe,
	}
}
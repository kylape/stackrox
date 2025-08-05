package scannerv4

import (
	"fmt"

	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stackrox/rox/pkg/set"
)

// VMPackageData represents package data extracted from VM components
type VMPackageData struct {
	Name         string
	Version      string
	Architecture string
	SourceType   storage.SourceType
	Location     string
}

// VMDistribution represents the OS distribution information for a VM
type VMDistribution struct {
	Name      string
	Version   string
	VersionID string
	CPE       string
}

// VMPackageDataFromStorageComponents extracts package data from existing VM scan components
func VMPackageDataFromStorageComponents(components []*storage.EmbeddedImageScanComponent) []*VMPackageData {
	if len(components) == 0 {
		return nil
	}

	packages := make([]*VMPackageData, 0, len(components))
	for _, component := range components {
		if component == nil {
			continue
		}

		pkg := &VMPackageData{
			Name:         component.GetName(),
			Version:      component.GetVersion(),
			Architecture: component.GetArchitecture(),
			SourceType:   component.GetSource(),
			Location:     component.GetLocation(),
		}
		packages = append(packages, pkg)
	}

	return packages
}

// ToVMIndexReport converts VM package data into a Scanner V4 IndexReport
func ToVMIndexReport(vmID string, packages []*VMPackageData, distribution *VMDistribution) (*v4.IndexReport, error) {
	if vmID == "" {
		return nil, fmt.Errorf("VM ID cannot be empty")
	}
	
	if len(packages) == 0 {
		return nil, fmt.Errorf("no packages provided for VM %s", vmID)
	}

	contents, err := toVMContents(packages, distribution)
	if err != nil {
		return nil, fmt.Errorf("converting VM data to contents: %w", err)
	}

	return &v4.IndexReport{
		HashId:   vmID, // Use VM ID as hash ID for matching
		State:    "Success",
		Success:  true,
		Contents: contents,
	}, nil
}

// toVMContents creates Scanner V4 Contents from VM package and distribution data
func toVMContents(packages []*VMPackageData, distribution *VMDistribution) (*v4.Contents, error) {
	var v4Packages []*v4.Package
	var v4Distributions []*v4.Distribution
	environments := make(map[string]*v4.Environment_List)

	// Convert distribution data if available
	var distID string
	if distribution != nil {
		distID = fmt.Sprintf("vm-dist-%s", distribution.Name)
		v4Distributions = append(v4Distributions, &v4.Distribution{
			Id:         distID,
			Did:        distribution.Name,
			Name:       distribution.Name,
			Version:    distribution.Version,
			VersionId:  distribution.VersionID,
			Cpe:        distribution.CPE,
			PrettyName: fmt.Sprintf("%s %s", distribution.Name, distribution.Version),
		})
	}

	// Convert packages
	for i, pkg := range packages {
		if pkg == nil {
			continue
		}
		
		pkgID := fmt.Sprintf("vm-pkg-%d-%s-%s", i, pkg.Name, pkg.Version)
		
		v4Pkg := &v4.Package{
			Id:      pkgID,
			Name:    pkg.Name,
			Version: pkg.Version,
			Kind:    sourceTypeToPackageKind(pkg.SourceType),
			Arch:    pkg.Architecture,
		}
		v4Packages = append(v4Packages, v4Pkg)

		// Create environment mapping for this package
		env := &v4.Environment{
			PackageDb:      sourceTypeToPackageDB(pkg.SourceType),
			DistributionId: distID,
		}

		environments[pkgID] = &v4.Environment_List{
			Environments: []*v4.Environment{env},
		}
	}

	return &v4.Contents{
		Packages:      v4Packages,
		Distributions: v4Distributions,
		Environments:  environments,
	}, nil
}

// sourceTypeToPackageKind converts storage.SourceType to package kind string
func sourceTypeToPackageKind(sourceType storage.SourceType) string {
	switch sourceType {
	case storage.SourceType_OS:
		return "binary"
	case storage.SourceType_PYTHON:
		return "python"
	case storage.SourceType_JAVA:
		return "java-archive"
	case storage.SourceType_DOTNETCORERUNTIME:
		return "dotnet"
	case storage.SourceType_RUBY:
		return "gem"
	case storage.SourceType_GO:
		return "go"
	case storage.SourceType_NODEJS:
		return "npm"
	default:
		return "binary" // Default for OS packages
	}
}

// sourceTypeToPackageDB converts storage.SourceType to package database string
func sourceTypeToPackageDB(sourceType storage.SourceType) string {
	switch sourceType {
	case storage.SourceType_OS:
		return "var/lib/rpm/Packages" // Default for RPM packages
	case storage.SourceType_PYTHON:
		return "python"
	case storage.SourceType_JAVA:
		return "java"
	case storage.SourceType_DOTNETCORERUNTIME:
		return "dotnet"
	case storage.SourceType_RUBY:
		return "gem"
	case storage.SourceType_GO:
		return "go"
	case storage.SourceType_NODEJS:
		return "npm"
	default:
		return "var/lib/rpm/Packages"
	}
}

// ToVMScan converts Scanner V4 VulnerabilityReport to storage.VirtualMachineScan
func ToVMScan(r *v4.VulnerabilityReport, vmID string) *storage.VirtualMachineScan {
	if r == nil {
		return &storage.VirtualMachineScan{
			ScanTime:       protocompat.TimestampNow(),
			ScannerVersion: "Scanner V4",
			DataSource:     &storage.DataSource{Name: "Scanner V4"},
			Notes:          []storage.VirtualMachineScan_Note{storage.VirtualMachineScan_UNSET},
		}
	}

	return &storage.VirtualMachineScan{
		ScanTime:        protocompat.TimestampNow(),
		Components:      toVMStorageComponents(r),
		ScannerVersion:  "Scanner V4",
		OperatingSystem: extractOperatingSystem(r),
		DataSource:      &storage.DataSource{Name: "Scanner V4"},
	}
}

// toVMStorageComponents converts Scanner V4 vulnerability report to VM storage components
func toVMStorageComponents(r *v4.VulnerabilityReport) []*storage.EmbeddedImageScanComponent {
	if r == nil || r.GetContents() == nil {
		return nil
	}

	packages := r.GetContents().GetPackages()
	result := make([]*storage.EmbeddedImageScanComponent, 0, len(packages))

	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		vulns := getVMPackageVulns(pkg.GetId(), r)
		result = append(result, createVMEmbeddedComponent(pkg, vulns))
	}
	return result
}

// getVMPackageVulns extracts vulnerabilities for a specific VM package
func getVMPackageVulns(packageID string, r *v4.VulnerabilityReport) []*storage.EmbeddedVulnerability {
	vulns := make([]*storage.EmbeddedVulnerability, 0)
	
	if r.GetPackageVulnerabilities() == nil {
		return vulns
	}
	
	mapping, ok := r.GetPackageVulnerabilities()[packageID]
	if !ok {
		return vulns // No vulnerabilities for this package
	}

	processedVulns := set.NewStringSet()
	for _, vulnID := range mapping.GetValues() {
		if !processedVulns.Add(vulnID) {
			continue // Already processed this vulnerability
		}
		vulnerability, ok := r.Vulnerabilities[vulnID]
		if !ok {
			log.Debugf("Mapping for VM package %s contains unknown vulnerability ID %s", packageID, vulnID)
			continue
		}
		vulns = append(vulns, convertVMVulnerability(vulnerability))
	}
	return vulns
}

// convertVMVulnerability converts Scanner V4 vulnerability to storage format for VMs
func convertVMVulnerability(v *v4.VulnerabilityReport_Vulnerability) *storage.EmbeddedVulnerability {
	if v == nil {
		return nil
	}

	converted := &storage.EmbeddedVulnerability{
		Cve:               v.GetName(),
		Summary:           v.GetDescription(),
		VulnerabilityType: storage.EmbeddedVulnerability_VIRTUAL_MACHINE_VULNERABILITY,
		Severity:          normalizedSeverity(v.GetNormalizedSeverity()),
		Link:              link(v.GetLink()),
		PublishedOn:       v.GetIssued(),
	}

	// Set CVSS scores and versions
	if err := setScoresAndScoreVersions(converted, v.GetCvssMetrics()); err != nil {
		log.Warnf("Failed to set CVSS scores for VM vulnerability %s: %v", v.GetName(), err)
	}
	maybeOverwriteSeverity(converted)
	
	// Set fixed version if available
	if v.GetFixedInVersion() != "" {
		converted.SetFixedBy = &storage.EmbeddedVulnerability_FixedBy{
			FixedBy: v.GetFixedInVersion(),
		}
	}

	return converted
}

// createVMEmbeddedComponent creates an embedded component for VM scan results
func createVMEmbeddedComponent(pkg *v4.Package, vulns []*storage.EmbeddedVulnerability) *storage.EmbeddedImageScanComponent {
	if pkg == nil {
		return nil
	}

	sourceType := packageKindToSourceType(pkg.GetKind())
	
	return &storage.EmbeddedImageScanComponent{
		Name:         pkg.GetName(),
		Version:      pkg.GetVersion(),
		Vulns:        vulns,
		Source:       sourceType,
		Location:     "VM Package", // Indicate this is from VM
		Architecture: pkg.GetArch(),
	}
}

// packageKindToSourceType converts package kind string back to storage.SourceType
func packageKindToSourceType(kind string) storage.SourceType {
	switch kind {
	case "binary":
		return storage.SourceType_OS
	case "python":
		return storage.SourceType_PYTHON
	case "npm":
		return storage.SourceType_NODEJS
	case "java-archive":
		return storage.SourceType_JAVA
	case "dotnet":
		return storage.SourceType_DOTNETCORERUNTIME
	case "gem":
		return storage.SourceType_RUBY
	case "go":
		return storage.SourceType_GO
	default:
		return storage.SourceType_OS // Default to OS packages
	}
}

// extractOperatingSystem extracts OS information from vulnerability report
func extractOperatingSystem(r *v4.VulnerabilityReport) string {
	if r == nil || r.GetContents() == nil {
		return "Unknown"
	}
	
	distributions := r.GetContents().GetDistributions()
	if len(distributions) == 0 {
		return "Unknown"
	}
	
	dist := distributions[0] // Use first distribution
	if dist.GetPrettyName() != "" {
		return dist.GetPrettyName()
	}
	
	return fmt.Sprintf("%s %s", dist.GetName(), dist.GetVersion())
}
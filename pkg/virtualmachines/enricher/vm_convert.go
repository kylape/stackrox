package enricher

import (
	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stackrox/rox/pkg/set"
)

func toVirtualMachineScan(vr *v4.VulnerabilityReport, vmName string) *storage.VirtualMachineScan {
	return &storage.VirtualMachineScan{
		ScanTime:        protocompat.TimestampNow(),
		Components:      toImageScanComponents(vr),
		Notes:           toVMScanNotes(vr.Notes),
		OperatingSystem: determineVMOperatingSystem(vmName),
		ScannerVersion:  "Scanner V4",
	}
}

func toImageScanComponents(vr *v4.VulnerabilityReport) []*storage.EmbeddedImageScanComponent {
	packages := vr.GetContents().GetPackages()
	result := make([]*storage.EmbeddedImageScanComponent, 0, len(packages))

	for _, pkg := range packages {
		vulns := getVMPackageVulns(pkg.GetId(), vr)
		result = append(result, createEmbeddedImageComponent(pkg, vulns))
	}
	return result
}

func getVMPackageVulns(packageID string, vr *v4.VulnerabilityReport) []*storage.EmbeddedVulnerability {
	vulns := make([]*storage.EmbeddedVulnerability, 0)
	mapping, ok := vr.GetPackageVulnerabilities()[packageID]
	if !ok {
		return vulns
	}

	processedVulns := set.NewStringSet()
	for _, vulnID := range mapping.GetValues() {
		if !processedVulns.Add(vulnID) {
			continue
		}
		vulnerability, ok := vr.Vulnerabilities[vulnID]
		if !ok {
			log.Debugf("VM package %s contains unknown vulnerability ID %s", packageID, vulnID)
			continue
		}
		vulns = append(vulns, convertVMVulnerability(vulnerability))
	}
	return vulns
}

func convertVMVulnerability(v *v4.VulnerabilityReport_Vulnerability) *storage.EmbeddedVulnerability {
	converted := &storage.EmbeddedVulnerability{
		Cve:               v.GetName(),
		Summary:           v.GetDescription(),
		VulnerabilityType: storage.EmbeddedVulnerability_IMAGE_VULNERABILITY,
		Severity:          normalizedSeverity(v.GetNormalizedSeverity()),
		Link:              v.GetLink(),
		PublishedOn:       v.GetIssued(),
	}

	if err := setScoresAndScoreVersions(converted, v.GetCvssMetrics()); err != nil {
		log.Warnf("Failed to set CVSS scores for vulnerability %s: %v", v.GetName(), err)
	}
	maybeOverwriteSeverity(converted)

	if v.GetFixedInVersion() != "" {
		converted.SetFixedBy = &storage.EmbeddedVulnerability_FixedBy{
			FixedBy: v.GetFixedInVersion(),
		}
	}

	return converted
}

func createEmbeddedImageComponent(pkg *v4.Package, vulns []*storage.EmbeddedVulnerability) *storage.EmbeddedImageScanComponent {
	return &storage.EmbeddedImageScanComponent{
		Name:    pkg.GetName(),
		Version: pkg.GetVersion(),
		Vulns:   vulns,
	}
}

func toVMScanNotes(notes []v4.VulnerabilityReport_Note) []storage.VirtualMachineScan_Note {
	convertedNotes := make([]storage.VirtualMachineScan_Note, 0, len(notes))
	for _, n := range notes {
		switch n {
		case v4.VulnerabilityReport_NOTE_OS_UNKNOWN:
			convertedNotes = append(convertedNotes, storage.VirtualMachineScan_OS_UNAVAILABLE)
		case v4.VulnerabilityReport_NOTE_OS_UNSUPPORTED:
			convertedNotes = append(convertedNotes, storage.VirtualMachineScan_OS_UNAVAILABLE)
		case v4.VulnerabilityReport_NOTE_UNSPECIFIED:
			convertedNotes = append(convertedNotes, storage.VirtualMachineScan_UNSET)
		default:
			log.Warnf("Unknown VM vulnerability report note: %s", n.String())
		}
	}
	return convertedNotes
}

func determineVMOperatingSystem(vmName string) string {
	// VM-specific OS detection logic - different from node RHCOS detection
	return "Unknown"
}
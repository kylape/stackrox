package scannerv4

import (
	"testing"

	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestVMPackageDataFromStorageComponents(t *testing.T) {
	t.Run("nil components", func(t *testing.T) {
		result := VMPackageDataFromStorageComponents(nil)
		assert.Nil(t, result)
	})

	t.Run("empty components", func(t *testing.T) {
		result := VMPackageDataFromStorageComponents([]*storage.EmbeddedImageScanComponent{})
		assert.Nil(t, result)
	})

	t.Run("valid components", func(t *testing.T) {
		components := []*storage.EmbeddedImageScanComponent{
			{
				Name:         "curl",
				Version:      "7.68.0-1ubuntu2.18",
				Architecture: "amd64",
				Source:       storage.SourceType_OS,
				Location:     "/usr/bin/curl",
			},
			{
				Name:    "requests",
				Version: "2.25.1",
				Source:  storage.SourceType_PYTHON,
			},
		}

		result := VMPackageDataFromStorageComponents(components)
		require.Len(t, result, 2)

		assert.Equal(t, "curl", result[0].Name)
		assert.Equal(t, "7.68.0-1ubuntu2.18", result[0].Version)
		assert.Equal(t, "amd64", result[0].Architecture)
		assert.Equal(t, storage.SourceType_OS, result[0].SourceType)
		assert.Equal(t, "/usr/bin/curl", result[0].Location)

		assert.Equal(t, "requests", result[1].Name)
		assert.Equal(t, "2.25.1", result[1].Version)
		assert.Equal(t, storage.SourceType_PYTHON, result[1].SourceType)
	})

	t.Run("skip nil components", func(t *testing.T) {
		components := []*storage.EmbeddedImageScanComponent{
			{Name: "valid", Version: "1.0"},
			nil,
			{Name: "another", Version: "2.0"},
		}

		result := VMPackageDataFromStorageComponents(components)
		require.Len(t, result, 2)
		assert.Equal(t, "valid", result[0].Name)
		assert.Equal(t, "another", result[1].Name)
	})
}

func TestToVMIndexReport(t *testing.T) {
	t.Run("empty VM ID", func(t *testing.T) {
		packages := []*VMPackageData{{Name: "test", Version: "1.0"}}
		_, err := ToVMIndexReport("", packages, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VM ID cannot be empty")
	})

	t.Run("no packages", func(t *testing.T) {
		_, err := ToVMIndexReport("vm-123", nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no packages provided")
	})

	t.Run("valid conversion", func(t *testing.T) {
		packages := []*VMPackageData{
			{
				Name:         "curl",
				Version:      "7.68.0",
				Architecture: "amd64",
				SourceType:   storage.SourceType_OS,
			},
		}

		distribution := &VMDistribution{
			Name:      "ubuntu",
			Version:   "20.04",
			VersionID: "20.04",
			CPE:       "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
		}

		result, err := ToVMIndexReport("vm-123", packages, distribution)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "vm-123", result.HashId)
		assert.Equal(t, "Success", result.State)
		assert.True(t, result.Success)
		require.NotNil(t, result.Contents)

		// Check packages
		require.Len(t, result.Contents.Packages, 1)
		pkg := result.Contents.Packages[0]
		assert.Equal(t, "curl", pkg.Name)
		assert.Equal(t, "7.68.0", pkg.Version)
		assert.Equal(t, "binary", pkg.Kind)
		assert.Equal(t, "amd64", pkg.Arch)

		// Check distributions
		require.Len(t, result.Contents.Distributions, 1)
		dist := result.Contents.Distributions[0]
		assert.Equal(t, "ubuntu", dist.Name)
		assert.Equal(t, "20.04", dist.Version)
		assert.Equal(t, "20.04", dist.VersionId)

		// Check environments
		assert.Len(t, result.Contents.Environments, 1)
	})
}

func TestSourceTypeToPackageKind(t *testing.T) {
	testCases := []struct {
		sourceType   storage.SourceType
		expectedKind string
	}{
		{storage.SourceType_OS, "binary"},
		{storage.SourceType_PYTHON, "python"},
		{storage.SourceType_NODEJS, "npm"},
		{storage.SourceType_JAVA, "java-archive"},
		{storage.SourceType_RUBY, "gem"},
		{storage.SourceType_GO, "go"},
		{storage.SourceType_DOTNETCORERUNTIME, "dotnet"},
		{storage.SourceType(999), "binary"}, // Unknown type defaults to binary
	}

	for _, tc := range testCases {
		t.Run(tc.sourceType.String(), func(t *testing.T) {
			result := sourceTypeToPackageKind(tc.sourceType)
			assert.Equal(t, tc.expectedKind, result)
		})
	}
}

func TestPackageKindToSourceType(t *testing.T) {
	testCases := []struct {
		kind               string
		expectedSourceType storage.SourceType
	}{
		{"binary", storage.SourceType_OS},
		{"python", storage.SourceType_PYTHON},
		{"npm", storage.SourceType_NODEJS},
		{"java-archive", storage.SourceType_JAVA},
		{"gem", storage.SourceType_RUBY},
		{"go", storage.SourceType_GO},
		{"dotnet", storage.SourceType_DOTNETCORERUNTIME},
		{"unknown", storage.SourceType_OS}, // Unknown kind defaults to OS
	}

	for _, tc := range testCases {
		t.Run(tc.kind, func(t *testing.T) {
			result := packageKindToSourceType(tc.kind)
			assert.Equal(t, tc.expectedSourceType, result)
		})
	}
}

func TestToVMScan(t *testing.T) {
	t.Run("nil report", func(t *testing.T) {
		result := ToVMScan(nil, "vm-123")
		require.NotNil(t, result)
		assert.Equal(t, "Scanner V4", result.ScannerVersion)
		assert.Equal(t, "Scanner V4", result.DataSource.Name)
		assert.Contains(t, result.Notes, storage.VirtualMachineScan_UNSET)
	})

	t.Run("valid report", func(t *testing.T) {
		report := &v4.VulnerabilityReport{
			Contents: &v4.Contents{
				Packages: []*v4.Package{
					{
						Id:      "pkg-1",
						Name:    "curl",
						Version: "7.68.0",
						Kind:    "binary",
						Arch:    "amd64",
					},
				},
				Distributions: []*v4.Distribution{
					{
						Id:         "dist-1",
						Name:       "ubuntu",
						Version:    "20.04",
						PrettyName: "Ubuntu 20.04 LTS",
					},
				},
			},
			PackageVulnerabilities: map[string]*v4.StringList{
				"pkg-1": {Values: []string{"vuln-1"}},
			},
			Vulnerabilities: map[string]*v4.VulnerabilityReport_Vulnerability{
				"vuln-1": {
					Id:          "vuln-1",
					Name:        "CVE-2023-1234",
					Description: "Test vulnerability",
					Severity:    "HIGH",
					NormalizedSeverity: v4.VulnerabilityReport_Vulnerability_SEVERITY_IMPORTANT,
					Link:        "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
					Issued:      &timestamppb.Timestamp{Seconds: 1609459200}, // 2021-01-01
				},
			},
		}

		result := ToVMScan(report, "vm-123")
		require.NotNil(t, result)

		assert.Equal(t, "Scanner V4", result.ScannerVersion)
		assert.Equal(t, "Scanner V4", result.DataSource.Name)
		assert.Equal(t, "Ubuntu 20.04 LTS", result.OperatingSystem)

		require.Len(t, result.Components, 1)
		component := result.Components[0]
		assert.Equal(t, "curl", component.Name)
		assert.Equal(t, "7.68.0", component.Version)
		assert.Equal(t, storage.SourceType_OS, component.Source)
		assert.Equal(t, "VM Package", component.Location)

		require.Len(t, component.Vulns, 1)
		vuln := component.Vulns[0]
		assert.Equal(t, "CVE-2023-1234", vuln.Cve)
		assert.Equal(t, "Test vulnerability", vuln.Summary)
		assert.Equal(t, storage.EmbeddedVulnerability_VIRTUAL_MACHINE_VULNERABILITY, vuln.VulnerabilityType)
	})
}

func TestConvertVMVulnerability(t *testing.T) {
	t.Run("nil vulnerability", func(t *testing.T) {
		result := convertVMVulnerability(nil)
		assert.Nil(t, result)
	})

	t.Run("valid vulnerability", func(t *testing.T) {
		vuln := &v4.VulnerabilityReport_Vulnerability{
			Id:                 "vuln-1",
			Name:               "CVE-2023-1234",
			Description:        "Test vulnerability description",
			Severity:           "HIGH",
			NormalizedSeverity: v4.VulnerabilityReport_Vulnerability_SEVERITY_IMPORTANT,
			Link:               "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
			Issued:             &timestamppb.Timestamp{Seconds: 1609459200},
			FixedInVersion:     "7.68.1",
		}

		result := convertVMVulnerability(vuln)
		require.NotNil(t, result)

		assert.Equal(t, "CVE-2023-1234", result.Cve)
		assert.Equal(t, "Test vulnerability description", result.Summary)
		assert.Equal(t, storage.EmbeddedVulnerability_VIRTUAL_MACHINE_VULNERABILITY, result.VulnerabilityType)
		assert.NotNil(t, result.PublishedOn)
		require.NotNil(t, result.SetFixedBy)
		fixedBy := result.SetFixedBy.(*storage.EmbeddedVulnerability_FixedBy)
		assert.Equal(t, "7.68.1", fixedBy.FixedBy)
	})
}

func TestCreateVMEmbeddedComponent(t *testing.T) {
	t.Run("nil package", func(t *testing.T) {
		result := createVMEmbeddedComponent(nil, nil)
		assert.Nil(t, result)
	})

	t.Run("valid package", func(t *testing.T) {
		pkg := &v4.Package{
			Id:      "pkg-1",
			Name:    "curl",
			Version: "7.68.0",
			Kind:    "binary",
			Arch:    "amd64",
		}

		vulns := []*storage.EmbeddedVulnerability{
			{Cve: "CVE-2023-1234"},
		}

		result := createVMEmbeddedComponent(pkg, vulns)
		require.NotNil(t, result)

		assert.Equal(t, "curl", result.Name)
		assert.Equal(t, "7.68.0", result.Version)
		assert.Equal(t, storage.SourceType_OS, result.Source)
		assert.Equal(t, "VM Package", result.Location)
		assert.Equal(t, "amd64", result.Architecture)
		assert.Len(t, result.Vulns, 1)
	})
}

func TestExtractOperatingSystem(t *testing.T) {
	t.Run("nil report", func(t *testing.T) {
		result := extractOperatingSystem(nil)
		assert.Equal(t, "Unknown", result)
	})

	t.Run("no distributions", func(t *testing.T) {
		report := &v4.VulnerabilityReport{
			Contents: &v4.Contents{},
		}
		result := extractOperatingSystem(report)
		assert.Equal(t, "Unknown", result)
	})

	t.Run("distribution with pretty name", func(t *testing.T) {
		report := &v4.VulnerabilityReport{
			Contents: &v4.Contents{
				Distributions: []*v4.Distribution{
					{
						Name:       "ubuntu",
						Version:    "20.04",
						PrettyName: "Ubuntu 20.04 LTS",
					},
				},
			},
		}
		result := extractOperatingSystem(report)
		assert.Equal(t, "Ubuntu 20.04 LTS", result)
	})

	t.Run("distribution without pretty name", func(t *testing.T) {
		report := &v4.VulnerabilityReport{
			Contents: &v4.Contents{
				Distributions: []*v4.Distribution{
					{
						Name:    "rhel",
						Version: "8.5",
					},
				},
			},
		}
		result := extractOperatingSystem(report)
		assert.Equal(t, "rhel 8.5", result)
	})
}
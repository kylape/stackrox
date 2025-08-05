package scannerv4

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scannerv4/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockScannerClient is a simple mock implementation for testing
type mockScannerClient struct {
	getVulnerabilitiesFunc func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error)
	closeFunc             func() error
}

func (m *mockScannerClient) GetImageIndex(ctx context.Context, hashID string) (*v4.IndexReport, bool, error) {
	return nil, false, errors.New("not implemented")
}

func (m *mockScannerClient) GetOrCreateImageIndex(ctx context.Context, ref name.Digest, auth authn.Authenticator, opt client.ImageRegistryOpt) (*v4.IndexReport, error) {
	return nil, errors.New("not implemented")
}

func (m *mockScannerClient) IndexAndScanImage(ctx context.Context, ref name.Digest, auth authn.Authenticator, opt client.ImageRegistryOpt) (*v4.VulnerabilityReport, error) {
	return nil, errors.New("not implemented")
}

func (m *mockScannerClient) GetVulnerabilities(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
	if m.getVulnerabilitiesFunc != nil {
		return m.getVulnerabilitiesFunc(ctx, digest, contents)
	}
	return nil, errors.New("not implemented")
}

func (m *mockScannerClient) GetMatcherMetadata(ctx context.Context) (*v4.Metadata, error) {
	return nil, errors.New("not implemented")
}

func (m *mockScannerClient) GetSBOM(ctx context.Context, name string, ref name.Digest, uri string) ([]byte, bool, error) {
	return nil, false, errors.New("not implemented")
}

func (m *mockScannerClient) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

var _ client.Scanner = (*mockScannerClient)(nil)

func TestNewVMVulnerabilityMatcher(t *testing.T) {
	t.Run("valid client", func(t *testing.T) {
		client := &mockScannerClient{}
		matcher := NewVMVulnerabilityMatcher(client)
		assert.NotNil(t, matcher)
		assert.Equal(t, client, matcher.scannerClient)
	})

	t.Run("nil client panics", func(t *testing.T) {
		assert.Panics(t, func() {
			NewVMVulnerabilityMatcher(nil)
		})
	})
}

func TestVMVulnerabilityMatcher_MatchVulnerabilities(t *testing.T) {
	ctx := context.Background()

	t.Run("nil VM", func(t *testing.T) {
		client := &mockScannerClient{}
		matcher := NewVMVulnerabilityMatcher(client)

		_, err := matcher.MatchVulnerabilities(ctx, nil, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VM cannot be nil")
	})

	t.Run("no packages", func(t *testing.T) {
		client := &mockScannerClient{}
		matcher := NewVMVulnerabilityMatcher(client)

		vm := &storage.VirtualMachine{Id: "vm-123"}
		
		result, err := matcher.MatchVulnerabilities(ctx, vm, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Scanner V4", result.ScannerVersion)
		assert.Contains(t, result.Notes, storage.VirtualMachineScan_PARTIAL_SCAN_DATA)
	})

	t.Run("invalid package data", func(t *testing.T) {
		client := &mockScannerClient{}
		matcher := NewVMVulnerabilityMatcher(client)

		vm := &storage.VirtualMachine{Id: "vm-123"}
		packages := []*VMPackageData{
			{Name: "", Version: "1.0"}, // Invalid: empty name
		}
		
		_, err := matcher.MatchVulnerabilities(ctx, vm, packages, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid package data")
	})

	t.Run("scanner client error", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return nil, errors.New("scanner error")
			},
		}
		matcher := NewVMVulnerabilityMatcher(client)

		vm := &storage.VirtualMachine{Id: "vm-123"}
		packages := []*VMPackageData{
			{Name: "curl", Version: "7.68.0", SourceType: storage.SourceType_OS},
		}

		_, err := matcher.MatchVulnerabilities(ctx, vm, packages, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "getting vulnerability report")
	})

	t.Run("successful scan", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{
								Id:      "vm-pkg-0-curl-7.68.0",
								Name:    "curl",
								Version: "7.68.0",
								Kind:    "binary",
							},
						},
						Distributions: []*v4.Distribution{
							{
								Id:         "vm-dist-ubuntu",
								Name:       "ubuntu",
								Version:    "20.04",
								PrettyName: "Ubuntu 20.04",
							},
						},
					},
					PackageVulnerabilities: map[string]*v4.StringList{
						"vm-pkg-0-curl-7.68.0": {Values: []string{"vuln-1"}},
					},
					Vulnerabilities: map[string]*v4.VulnerabilityReport_Vulnerability{
						"vuln-1": {
							Id:          "vuln-1",
							Name:        "CVE-2023-1234",
							Description: "Test vulnerability",
							Severity:    "HIGH",
							NormalizedSeverity: v4.VulnerabilityReport_Vulnerability_SEVERITY_IMPORTANT,
							Link:        "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
							Issued:      &timestamppb.Timestamp{Seconds: 1609459200},
						},
					},
				}, nil
			},
		}
		matcher := NewVMVulnerabilityMatcher(client)

		vm := &storage.VirtualMachine{Id: "vm-123"}
		packages := []*VMPackageData{
			{Name: "curl", Version: "7.68.0", SourceType: storage.SourceType_OS},
		}
		distribution := &VMDistribution{
			Name:    "ubuntu",
			Version: "20.04",
		}


		result, err := matcher.MatchVulnerabilities(ctx, vm, packages, distribution)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "Scanner V4", result.ScannerVersion)
		assert.Equal(t, "Ubuntu 20.04", result.OperatingSystem)
		require.Len(t, result.Components, 1)

		component := result.Components[0]
		assert.Equal(t, "curl", component.Name)
		assert.Equal(t, "7.68.0", component.Version)
		require.Len(t, component.Vulns, 1)

		vuln := component.Vulns[0]
		assert.Equal(t, "CVE-2023-1234", vuln.Cve)
		assert.Equal(t, storage.EmbeddedVulnerability_VIRTUAL_MACHINE_VULNERABILITY, vuln.VulnerabilityType)
	})
}

func TestVMVulnerabilityMatcher_MatchVulnerabilitiesFromComponents(t *testing.T) {
	ctx := context.Background()

	t.Run("nil VM", func(t *testing.T) {
		client := &mockScannerClient{}
		matcher := NewVMVulnerabilityMatcher(client)

		_, err := matcher.MatchVulnerabilitiesFromComponents(ctx, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VM cannot be nil")
	})

	t.Run("VM with no scan", func(t *testing.T) {
		client := &mockScannerClient{}
		matcher := NewVMVulnerabilityMatcher(client)

		vm := &storage.VirtualMachine{Id: "vm-123"}
		
		result, err := matcher.MatchVulnerabilitiesFromComponents(ctx, vm, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.Notes, storage.VirtualMachineScan_PARTIAL_SCAN_DATA)
	})

	t.Run("VM with existing components", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{Id: "vm-pkg-0-curl-7.68.0", Name: "curl", Version: "7.68.0"},
						},
					},
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		matcher := NewVMVulnerabilityMatcher(client)

		vm := &storage.VirtualMachine{
			Id: "vm-123",
			Scan: &storage.VirtualMachineScan{
				Components: []*storage.EmbeddedImageScanComponent{
					{
						Name:    "curl",
						Version: "7.68.0",
						Source:  storage.SourceType_OS,
					},
				},
			},
		}

		result, err := matcher.MatchVulnerabilitiesFromComponents(ctx, vm, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Components, 1)

		component := result.Components[0]
		assert.Equal(t, "curl", component.Name)
		assert.Equal(t, "7.68.0", component.Version)

	})
}

func TestVMVulnerabilityEnricher(t *testing.T) {
	ctx := context.Background()

	t.Run("NewVMVulnerabilityEnricher", func(t *testing.T) {
		client := &mockScannerClient{}
		enricher := NewVMVulnerabilityEnricher(client)
		assert.NotNil(t, enricher)
		assert.NotNil(t, enricher.matcher)
	})

	t.Run("EnrichVM", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{Id: "vm-pkg-0-curl-7.68.0", Name: "curl", Version: "7.68.0"},
						},
					},
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		enricher := NewVMVulnerabilityEnricher(client)

		vm := &storage.VirtualMachine{
			Id: "vm-123",
			Scan: &storage.VirtualMachineScan{
				Components: []*storage.EmbeddedImageScanComponent{
					{Name: "curl", Version: "7.68.0", Source: storage.SourceType_OS},
				},
			},
		}

		err := enricher.EnrichVM(ctx, vm, nil)
		require.NoError(t, err)

		assert.NotNil(t, vm.Scan)
		assert.NotNil(t, vm.LastUpdated)
		assert.Equal(t, "Scanner V4", vm.Scan.ScannerVersion)

	})

	t.Run("EnrichVMWithPackages", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{Id: "vm-pkg-0-curl-7.68.0", Name: "curl", Version: "7.68.0"},
						},
					},
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		enricher := NewVMVulnerabilityEnricher(client)

		vm := &storage.VirtualMachine{Id: "vm-123"}
		packages := []*VMPackageData{
			{Name: "curl", Version: "7.68.0", SourceType: storage.SourceType_OS},
		}

		err := enricher.EnrichVMWithPackages(ctx, vm, packages, nil)
		require.NoError(t, err)

		assert.NotNil(t, vm.Scan)
		assert.NotNil(t, vm.LastUpdated)
		assert.Equal(t, "Scanner V4", vm.Scan.ScannerVersion)

	})
}

func TestValidateVMPackageData(t *testing.T) {
	t.Run("nil packages", func(t *testing.T) {
		err := ValidateVMPackageData(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no packages provided")
	})

	t.Run("empty packages", func(t *testing.T) {
		err := ValidateVMPackageData([]*VMPackageData{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no packages provided")
	})

	t.Run("nil package in slice", func(t *testing.T) {
		packages := []*VMPackageData{nil}
		err := ValidateVMPackageData(packages)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "package at index 0 is nil")
	})

	t.Run("package with empty name", func(t *testing.T) {
		packages := []*VMPackageData{
			{Name: "", Version: "1.0"},
		}
		err := ValidateVMPackageData(packages)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty name")
	})

	t.Run("package with empty version", func(t *testing.T) {
		packages := []*VMPackageData{
			{Name: "curl", Version: ""},
		}
		err := ValidateVMPackageData(packages)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty version")
	})

	t.Run("valid packages", func(t *testing.T) {
		packages := []*VMPackageData{
			{Name: "curl", Version: "7.68.0"},
			{Name: "python", Version: "3.8"},
		}
		err := ValidateVMPackageData(packages)
		assert.NoError(t, err)
	})
}

func TestExtractVMDistributionFromFacts(t *testing.T) {
	t.Run("nil facts", func(t *testing.T) {
		result := ExtractVMDistributionFromFacts(nil)
		assert.Nil(t, result)
	})

	t.Run("empty facts", func(t *testing.T) {
		result := ExtractVMDistributionFromFacts(map[string]string{})
		assert.Nil(t, result)
	})

	t.Run("facts without OS name", func(t *testing.T) {
		facts := map[string]string{
			"hostname": "test-vm",
			"memory":   "8GB",
		}
		result := ExtractVMDistributionFromFacts(facts)
		assert.Nil(t, result)
	})

	t.Run("facts with os_name only", func(t *testing.T) {
		facts := map[string]string{
			"os_name": "ubuntu",
		}
		result := ExtractVMDistributionFromFacts(facts)
		require.NotNil(t, result)
		assert.Equal(t, "ubuntu", result.Name)
		assert.Empty(t, result.Version)
		assert.Empty(t, result.VersionID)
		assert.Empty(t, result.CPE)
	})

	t.Run("facts with complete OS information (lowercase)", func(t *testing.T) {
		facts := map[string]string{
			"os_name":       "ubuntu",
			"os_version":    "20.04",
			"os_version_id": "20.04",
			"os_cpe":        "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
		}
		result := ExtractVMDistributionFromFacts(facts)
		require.NotNil(t, result)
		assert.Equal(t, "ubuntu", result.Name)
		assert.Equal(t, "20.04", result.Version)
		assert.Equal(t, "20.04", result.VersionID)
		assert.Equal(t, "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*", result.CPE)
	})

	t.Run("facts with complete OS information (uppercase)", func(t *testing.T) {
		facts := map[string]string{
			"OS_NAME":    "RHEL",
			"OS_VERSION": "8.5",
			"VERSION_ID": "8.5",
			"CPE_NAME":   "cpe:2.3:o:redhat:enterprise_linux:8.5:*:*:*:*:*:*:*",
		}
		result := ExtractVMDistributionFromFacts(facts)
		require.NotNil(t, result)
		assert.Equal(t, "RHEL", result.Name)
		assert.Equal(t, "8.5", result.Version)
		assert.Equal(t, "8.5", result.VersionID)
		assert.Equal(t, "cpe:2.3:o:redhat:enterprise_linux:8.5:*:*:*:*:*:*:*", result.CPE)
	})

	t.Run("facts with alternative field names", func(t *testing.T) {
		facts := map[string]string{
			"operating_system": "CentOS",
			"version":          "7.9",
		}
		result := ExtractVMDistributionFromFacts(facts)
		require.NotNil(t, result)
		assert.Equal(t, "CentOS", result.Name)
		assert.Equal(t, "7.9", result.Version)
		assert.Empty(t, result.VersionID)
		assert.Empty(t, result.CPE)
	})

	t.Run("facts with mixed case and priority", func(t *testing.T) {
		// Should prefer lowercase over uppercase and more specific over generic
		facts := map[string]string{
			"os_name":          "ubuntu",
			"OS_NAME":          "UBUNTU_CAPS",
			"operating_system": "ubuntu_generic",
			"os_version":       "20.04",
			"version":          "generic_version",
		}
		result := ExtractVMDistributionFromFacts(facts)
		require.NotNil(t, result)
		assert.Equal(t, "ubuntu", result.Name)        // Should prefer os_name
		assert.Equal(t, "20.04", result.Version)     // Should prefer os_version
		assert.Empty(t, result.VersionID)
		assert.Empty(t, result.CPE)
	})
}
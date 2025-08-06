package enricher

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scanners/scannerv4"
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

func TestNew(t *testing.T) {
	t.Run("valid scanner client", func(t *testing.T) {
		client := &mockScannerClient{}
		enricher := New(client)
		assert.NotNil(t, enricher)
		
		impl, ok := enricher.(*enricherImpl)
		require.True(t, ok)
		assert.NotNil(t, impl.vmEnricher)
	})

	t.Run("nil scanner client panics", func(t *testing.T) {
		assert.Panics(t, func() {
			New(nil)
		})
	})
}

func TestEnricherImpl_EnrichVM(t *testing.T) {
	ctx := context.Background()

	t.Run("nil VM", func(t *testing.T) {
		client := &mockScannerClient{}
		enricher := New(client)
		
		err := enricher.EnrichVM(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VM cannot be nil")
	})

	t.Run("VM without existing scan", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{},
					},
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{
			Id: "vm-123",
		}
		
		err := enricher.EnrichVM(ctx, vm)
		require.NoError(t, err)
		assert.NotNil(t, vm.Scan)
		assert.Equal(t, "Scanner V4", vm.Scan.ScannerVersion)
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
		enricher := New(client)
		
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
		
		err := enricher.EnrichVM(ctx, vm)
		require.NoError(t, err)
		require.NotNil(t, vm.Scan)
		require.Len(t, vm.Scan.Components, 1)
		
		component := vm.Scan.Components[0]
		assert.Equal(t, "curl", component.Name)
		assert.Equal(t, "7.68.0", component.Version)
		require.Len(t, component.Vulns, 1)
		
		vuln := component.Vulns[0]
		assert.Equal(t, "CVE-2023-1234", vuln.Cve)
		assert.Equal(t, storage.EmbeddedVulnerability_VIRTUAL_MACHINE_VULNERABILITY, vuln.VulnerabilityType)
	})

	t.Run("VM with facts containing distribution info", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				// This function should not be called when VM has no components
				return nil, errors.New("unexpected call to GetVulnerabilities")
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{
			Id: "vm-123",
			Facts: map[string]string{
				"os_name":    "ubuntu",
				"os_version": "20.04",
			},
		}
		
		err := enricher.EnrichVM(ctx, vm)
		require.NoError(t, err)
		assert.NotNil(t, vm.Scan)
		// When VM has no existing components, we get a partial scan with no operating system
		assert.Contains(t, vm.Scan.Notes, storage.VirtualMachineScan_PARTIAL_SCAN_DATA)
		assert.Equal(t, "", vm.Scan.OperatingSystem)
	})

	t.Run("scanner error", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return nil, errors.New("scanner error")
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{
			Id: "vm-123",
			Scan: &storage.VirtualMachineScan{
				Components: []*storage.EmbeddedImageScanComponent{
					{Name: "curl", Version: "7.68.0", Source: storage.SourceType_OS},
				},
			},
		}
		
		err := enricher.EnrichVM(ctx, vm)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enriching VM vm-123")
	})
}

func TestEnricherImpl_EnrichVMWithPackages(t *testing.T) {
	ctx := context.Background()

	t.Run("nil VM", func(t *testing.T) {
		client := &mockScannerClient{}
		enricher := New(client)
		
		err := enricher.EnrichVMWithPackages(ctx, nil, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VM cannot be nil")
	})

	t.Run("successful enrichment", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{Id: "vm-pkg-0-python-3.8", Name: "python", Version: "3.8"},
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
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{Id: "vm-456"}
		packages := []*scannerv4.VMPackageData{
			{Name: "python", Version: "3.8", SourceType: storage.SourceType_PYTHON},
		}
		distribution := &scannerv4.VMDistribution{
			Name:    "ubuntu",
			Version: "20.04",
		}
		
		err := enricher.EnrichVMWithPackages(ctx, vm, packages, distribution)
		require.NoError(t, err)
		require.NotNil(t, vm.Scan)
		require.Len(t, vm.Scan.Components, 1)
		
		component := vm.Scan.Components[0]
		assert.Equal(t, "python", component.Name)
		assert.Equal(t, "3.8", component.Version)
		assert.Equal(t, "Ubuntu 20.04", vm.Scan.OperatingSystem)
	})

	t.Run("scanner error with packages", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return nil, errors.New("scanner failure")
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{Id: "vm-789"}
		packages := []*scannerv4.VMPackageData{
			{Name: "nginx", Version: "1.18", SourceType: storage.SourceType_OS},
		}
		
		err := enricher.EnrichVMWithPackages(ctx, vm, packages, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enriching VM vm-789 with packages")
	})
}

func TestEnricherImpl_EnrichVMWithFacts(t *testing.T) {
	ctx := context.Background()

	t.Run("nil VM", func(t *testing.T) {
		client := &mockScannerClient{}
		enricher := New(client)
		
		err := enricher.EnrichVMWithFacts(ctx, nil, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VM cannot be nil")
	})

	t.Run("successful enrichment with facts", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{Id: "vm-pkg-0-gcc-9.3.0", Name: "gcc", Version: "9.3.0"},
						},
						Distributions: []*v4.Distribution{
							{
								Id:         "vm-dist-rhel",
								Name:       "rhel",
								Version:    "8.5",
								PrettyName: "Red Hat Enterprise Linux 8.5",
							},
						},
					},
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{Id: "vm-rhel"}
		packages := []*scannerv4.VMPackageData{
			{Name: "gcc", Version: "9.3.0", SourceType: storage.SourceType_OS},
		}
		facts := map[string]string{
			"os_name":    "rhel",
			"os_version": "8.5",
			"hostname":   "test-vm",
		}
		
		err := enricher.EnrichVMWithFacts(ctx, vm, packages, facts)
		require.NoError(t, err)
		require.NotNil(t, vm.Scan)
		require.Len(t, vm.Scan.Components, 1)
		
		component := vm.Scan.Components[0]
		assert.Equal(t, "gcc", component.Name)
		assert.Equal(t, "9.3.0", component.Version)
		assert.Equal(t, "Red Hat Enterprise Linux 8.5", vm.Scan.OperatingSystem)
	})

	t.Run("facts without distribution info", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return &v4.VulnerabilityReport{
					Contents: &v4.Contents{
						Packages: []*v4.Package{
							{Id: "vm-pkg-0-vim-8.2", Name: "vim", Version: "8.2"},
						},
					},
					PackageVulnerabilities: map[string]*v4.StringList{},
					Vulnerabilities:        map[string]*v4.VulnerabilityReport_Vulnerability{},
				}, nil
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{Id: "vm-unknown"}
		packages := []*scannerv4.VMPackageData{
			{Name: "vim", Version: "8.2", SourceType: storage.SourceType_OS},
		}
		facts := map[string]string{
			"hostname": "test-vm",
			"memory":   "8GB",
		}
		
		err := enricher.EnrichVMWithFacts(ctx, vm, packages, facts)
		require.NoError(t, err)
		require.NotNil(t, vm.Scan)
		require.Len(t, vm.Scan.Components, 1)
		
		component := vm.Scan.Components[0]
		assert.Equal(t, "vim", component.Name)
		assert.Equal(t, "8.2", component.Version)
	})

	t.Run("scanner error with facts", func(t *testing.T) {
		client := &mockScannerClient{
			getVulnerabilitiesFunc: func(ctx context.Context, digest name.Digest, contents *v4.Contents) (*v4.VulnerabilityReport, error) {
				return nil, errors.New("facts scanner error")
			},
		}
		enricher := New(client)
		
		vm := &storage.VirtualMachine{Id: "vm-error"}
		packages := []*scannerv4.VMPackageData{
			{Name: "package", Version: "1.0", SourceType: storage.SourceType_OS},
		}
		facts := map[string]string{
			"os_name": "ubuntu",
		}
		
		err := enricher.EnrichVMWithFacts(ctx, vm, packages, facts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enriching VM vm-error with facts")
	})
}
package enricher

import (
	"context"
	"errors"
	"testing"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/scanners/scannerv4"
	vmEnricher "github.com/stackrox/rox/pkg/virtualmachine/enricher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockVMEnricher is a test mock for the VM enricher interface
type mockVMEnricher struct {
	enrichVMFunc                   func(ctx context.Context, vm *storage.VirtualMachine) error
	enrichVMWithPackagesFunc       func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, distribution *scannerv4.VMDistribution) error
	enrichVMWithFactsFunc          func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error
}

func (m *mockVMEnricher) EnrichVM(ctx context.Context, vm *storage.VirtualMachine) error {
	if m.enrichVMFunc != nil {
		return m.enrichVMFunc(ctx, vm)
	}
	return nil
}

func (m *mockVMEnricher) EnrichVMWithPackages(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, distribution *scannerv4.VMDistribution) error {
	if m.enrichVMWithPackagesFunc != nil {
		return m.enrichVMWithPackagesFunc(ctx, vm, packages, distribution)
	}
	return nil
}

func (m *mockVMEnricher) EnrichVMWithFacts(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
	if m.enrichVMWithFactsFunc != nil {
		return m.enrichVMWithFactsFunc(ctx, vm, packages, facts)
	}
	return nil
}

var _ vmEnricher.VMEnricher = (*mockVMEnricher)(nil)

func TestNew(t *testing.T) {
	t.Run("valid enricher", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{}
		enricher := New(mockEnricher)
		assert.NotNil(t, enricher)
		
		impl, ok := enricher.(*enricherImpl)
		require.True(t, ok)
		assert.Equal(t, mockEnricher, impl.vmEnricher)
	})
}

func TestEnricherImpl_EnrichVMWithVulnerabilities(t *testing.T) {
	ctx := context.Background()

	t.Run("successful enrichment", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMFunc: func(ctx context.Context, vm *storage.VirtualMachine) error {
				vm.Scan = &storage.VirtualMachineScan{
					ScannerVersion: "Scanner V4",
					Components: []*storage.EmbeddedImageScanComponent{
						{Name: "test-pkg", Version: "1.0.0"},
					},
				}
				return nil
			},
		}
		
		enricher := New(mockEnricher)
		vm := &storage.VirtualMachine{Id: "vm-123"}
		
		err := enricher.EnrichVMWithVulnerabilities(ctx, vm)
		require.NoError(t, err)
		assert.NotNil(t, vm.Scan)
		assert.Equal(t, "Scanner V4", vm.Scan.ScannerVersion)
	})

	t.Run("enrichment error", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMFunc: func(ctx context.Context, vm *storage.VirtualMachine) error {
				return errors.New("enrichment failed")
			},
		}
		
		enricher := New(mockEnricher)
		vm := &storage.VirtualMachine{Id: "vm-123"}
		
		err := enricher.EnrichVMWithVulnerabilities(ctx, vm)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enrichment failed")
	})
}

func TestEnricherImpl_EnrichVMWithPackagesAndFacts(t *testing.T) {
	ctx := context.Background()

	t.Run("successful enrichment with packages and facts", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMWithFactsFunc: func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
				vm.Scan = &storage.VirtualMachineScan{
					ScannerVersion:  "Scanner V4",
					OperatingSystem: "Ubuntu 20.04",
					Components: []*storage.EmbeddedImageScanComponent{
						{Name: "curl", Version: "7.68.0"},
					},
				}
				return nil
			},
		}
		
		enricher := New(mockEnricher)
		vm := &storage.VirtualMachine{Id: "vm-456"}
		packages := []*scannerv4.VMPackageData{
			{Name: "curl", Version: "7.68.0", SourceType: storage.SourceType_OS},
		}
		facts := map[string]string{
			"os_name":    "ubuntu",
			"os_version": "20.04",
		}
		
		err := enricher.EnrichVMWithPackagesAndFacts(ctx, vm, packages, facts)
		require.NoError(t, err)
		require.NotNil(t, vm.Scan)
		assert.Equal(t, "Scanner V4", vm.Scan.ScannerVersion)
		assert.Equal(t, "Ubuntu 20.04", vm.Scan.OperatingSystem)
		require.Len(t, vm.Scan.Components, 1)
		assert.Equal(t, "curl", vm.Scan.Components[0].Name)
	})

	t.Run("enrichment error with packages and facts", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMWithFactsFunc: func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
				return errors.New("facts enrichment failed")
			},
		}
		
		enricher := New(mockEnricher)
		vm := &storage.VirtualMachine{Id: "vm-456"}
		packages := []*scannerv4.VMPackageData{
			{Name: "invalid", Version: "", SourceType: storage.SourceType_OS},
		}
		
		err := enricher.EnrichVMWithPackagesAndFacts(ctx, vm, packages, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "facts enrichment failed")
	})
}

func TestEnricherImpl_CreateVMScanFromPackages(t *testing.T) {
	ctx := context.Background()

	t.Run("successful scan creation", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMWithFactsFunc: func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
				vm.Scan = &storage.VirtualMachineScan{
					ScannerVersion:  "Scanner V4",
					OperatingSystem: "RHEL 8.5",
					Components: []*storage.EmbeddedImageScanComponent{
						{Name: "gcc", Version: "9.3.0"},
						{Name: "python", Version: "3.8"},
					},
				}
				return nil
			},
		}
		
		enricher := New(mockEnricher)
		packages := []*scannerv4.VMPackageData{
			{Name: "gcc", Version: "9.3.0", SourceType: storage.SourceType_OS},
			{Name: "python", Version: "3.8", SourceType: storage.SourceType_PYTHON},
		}
		facts := map[string]string{
			"os_name":    "rhel",
			"os_version": "8.5",
		}
		
		scan, err := enricher.CreateVMScanFromPackages(ctx, "vm-rhel", packages, facts)
		require.NoError(t, err)
		require.NotNil(t, scan)
		assert.Equal(t, "Scanner V4", scan.ScannerVersion)
		assert.Equal(t, "RHEL 8.5", scan.OperatingSystem)
		require.Len(t, scan.Components, 2)
		assert.Equal(t, "gcc", scan.Components[0].Name)
		assert.Equal(t, "python", scan.Components[1].Name)
	})

	t.Run("scan creation error", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMWithFactsFunc: func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
				return errors.New("scan creation failed")
			},
		}
		
		enricher := New(mockEnricher)
		packages := []*scannerv4.VMPackageData{
			{Name: "broken", Version: "1.0", SourceType: storage.SourceType_OS},
		}
		
		scan, err := enricher.CreateVMScanFromPackages(ctx, "vm-error", packages, nil)
		assert.Error(t, err)
		assert.Nil(t, scan)
		assert.Contains(t, err.Error(), "scan creation failed")
	})

	t.Run("empty packages", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{
			enrichVMWithFactsFunc: func(ctx context.Context, vm *storage.VirtualMachine, packages []*scannerv4.VMPackageData, facts map[string]string) error {
				vm.Scan = &storage.VirtualMachineScan{
					ScannerVersion: "Scanner V4",
					Notes:          []storage.VirtualMachineScan_Note{storage.VirtualMachineScan_PARTIAL_SCAN_DATA},
				}
				return nil
			},
		}
		
		enricher := New(mockEnricher)
		
		scan, err := enricher.CreateVMScanFromPackages(ctx, "vm-empty", nil, nil)
		require.NoError(t, err)
		require.NotNil(t, scan)
		assert.Equal(t, "Scanner V4", scan.ScannerVersion)
		assert.Contains(t, scan.Notes, storage.VirtualMachineScan_PARTIAL_SCAN_DATA)
	})
}

func TestSetSingleton(t *testing.T) {
	// Save the original singleton
	originalSingleton := enricherInstance
	defer func() {
		enricherInstance = originalSingleton
	}()

	t.Run("set custom singleton", func(t *testing.T) {
		mockEnricher := &mockVMEnricher{}
		customEnricher := New(mockEnricher)
		
		SetSingleton(customEnricher)
		
		// Verify the singleton was set correctly
		assert.Equal(t, customEnricher, enricherInstance)
	})
}
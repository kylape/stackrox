package scannerv4

import (
	"context"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/rox/generated/api/v1"
	v4 "github.com/stackrox/rox/generated/internalapi/scanner/v4"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stackrox/rox/pkg/registries"
	"github.com/stackrox/rox/pkg/scanners/types"
	scannerTypes "github.com/stackrox/rox/pkg/scanners/types"
	pkgscanner "github.com/stackrox/rox/pkg/scannerv4"
	"github.com/stackrox/rox/pkg/scannerv4/client"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/rox/pkg/uuid"
	scannerv1 "github.com/stackrox/scanner/generated/scanner/api/v1"
)

// mockDigest is the digest used for annotating any Node/VM Index.
// The Scanner endpoint requires a digest for each image layer before analyzing it - TODO(ROX-25614)
// As the Node/VM contents are treated as one big image layer, they also need a bogus digest.
// This digest is taken from the test of the digest library we're using (go-containerregistry).
const mockDigest = "registry/repository@sha256:deadb33fdeadb33fdeadb33fdeadb33fdeadb33fdeadb33fdeadb33fdeadb33f"

var (
	_ types.Scanner                  = (*scannerv4)(nil)
	_ types.ImageVulnerabilityGetter = (*scannerv4)(nil)
	_ types.NodeScanner              = (*scannerv4)(nil)
	_ types.SBOMer                   = (*scannerv4)(nil)

	log = logging.LoggerForModule()

	// DefaultIndexerEndpoint is the default gRPC endpoint for the indexer.
	DefaultIndexerEndpoint = fmt.Sprintf("scanner-v4-indexer.%s.svc:8443", env.Namespace.Setting())

	// DefaultMatcherEndpoint is the default gRPC endpoint for the matcher.
	DefaultMatcherEndpoint = fmt.Sprintf("scanner-v4-matcher.%s.svc:8443", env.Namespace.Setting())

	defaultMaxConcurrentScans = int64(30)

	scanTimeout     = env.ScanTimeout.DurationSetting()
	metadataTimeout = 1 * time.Minute
)

// Creator provides the type scanners.Creator to add to the scanners Registry.
func Creator(set registries.Set) (string, func(integration *storage.ImageIntegration) (types.Scanner, error)) {
	return types.ScannerV4, func(integration *storage.ImageIntegration) (types.Scanner, error) {
		scan, err := newScanner(integration, set)
		return scan, err
	}
}

type scannerv4 struct {
	types.ScanSemaphore
	types.NodeScanSemaphore

	name             string
	activeRegistries registries.Set
	scannerClient    client.Scanner
}

func newScanner(integration *storage.ImageIntegration, activeRegistries registries.Set) (*scannerv4, error) {
	conf := integration.GetScannerV4()
	if conf == nil {
		return nil, errors.New("scanner V4 configuration required")
	}

	indexerEndpoint := DefaultIndexerEndpoint
	if conf.IndexerEndpoint != "" {
		indexerEndpoint = conf.IndexerEndpoint
	}

	matcherEndpoint := DefaultMatcherEndpoint
	if conf.MatcherEndpoint != "" {
		matcherEndpoint = conf.MatcherEndpoint
	}

	numConcurrentScans := defaultMaxConcurrentScans
	if conf.GetNumConcurrentScans() > 0 {
		numConcurrentScans = int64(conf.GetNumConcurrentScans())
	}

	log.Debugf("Creating Scanner V4 with name [%s] indexer address [%s], matcher address [%s], num concurrent scans [%d]", integration.GetName(), indexerEndpoint, matcherEndpoint, numConcurrentScans)
	ctx := context.Background()
	c, err := client.NewGRPCScanner(ctx,
		client.WithIndexerAddress(indexerEndpoint),
		client.WithMatcherAddress(matcherEndpoint),
	)
	if err != nil {
		return nil, err
	}

	scanner := &scannerv4{
		name:              integration.GetName(),
		activeRegistries:  activeRegistries,
		ScanSemaphore:     types.NewSemaphoreWithValue(numConcurrentScans),
		NodeScanSemaphore: types.NewNodeSemaphoreWithValue(numConcurrentScans),
		scannerClient:     c,
	}

	return scanner, nil
}

// GetSBOM returns sbom of an image as a byte array. It also returns a boolean indicating if the index report for the image was found.
func (s *scannerv4) GetSBOM(image *storage.Image) ([]byte, bool, error) {
	digest, err := pkgscanner.DigestFromImage(image)
	if err != nil {
		return nil, false, err
	}

	imgName := image.GetName()
	// Desired URI for images: https://<registry>/<repo>-<uuid>
	uri := "https://" + imgName.GetRegistry() + "/" + imgName.GetRemote() + "-" + uuid.NewV4().String()

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	sbom, found, err := s.scannerClient.GetSBOM(ctx, image.GetName().GetFullName(), digest, uri)
	return sbom, found, err
}

func (s *scannerv4) GetScan(image *storage.Image) (*storage.ImageScan, error) {
	if image.GetMetadata() == nil {
		return nil, nil
	}

	rc := s.activeRegistries.GetRegistryMetadataByImage(image)
	if rc == nil {
		log.Debugf("No registry matched during scan of %q", image.GetName().GetFullName())
		return nil, nil
	}

	auth := authn.Basic{
		Username: rc.Username,
		Password: rc.Password,
	}

	digest, err := pkgscanner.DigestFromImage(image)
	if err != nil {
		return nil, err
	}

	log.Debugf("Scanning %q for digest %q with image ID %q, manifest v2 digest %q, and manifest v1 digest %q",
		image.GetName().GetFullName(),
		digest.String(),
		image.GetId(),
		image.GetMetadata().GetV2().GetDigest(),
		image.GetMetadata().GetV1().GetDigest(),
	)
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	opt := client.ImageRegistryOpt{InsecureSkipTLSVerify: rc.GetInsecure()}
	vr, err := s.scannerClient.IndexAndScanImage(ctx, digest, &auth, opt)
	if err != nil {
		return nil, fmt.Errorf("index and scan image report (reference: %q): %w", digest.Name(), err)
	}

	log.Debugf("Vuln report received for %q (hash %q): %d dists, %d envs, %d pkgs, %d repos, %d pkg vulns, %d vulns",
		image.GetName().GetFullName(),
		vr.GetHashId(),
		len(vr.GetContents().GetDistributions()),
		len(vr.GetContents().GetEnvironments()),
		len(vr.GetContents().GetPackages()),
		len(vr.GetContents().GetRepositories()),
		len(vr.GetPackageVulnerabilities()),
		len(vr.GetVulnerabilities()),
	)

	return imageScan(image.GetMetadata(), vr), nil
}

func (s *scannerv4) GetVulnDefinitionsInfo() (*v1.VulnDefinitionsInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), metadataTimeout)
	defer cancel()

	metadata, err := s.scannerClient.GetMatcherMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("pulling metadata from matcher: %w", err)
	}

	lastTms := metadata.GetLastVulnerabilityUpdate()
	if protocompat.IsZeroTimestamp(lastTms) {
		return nil, errors.New("no timestamp available")
	}

	return &v1.VulnDefinitionsInfo{
		LastUpdatedTimestamp: lastTms,
	}, nil
}

func (s *scannerv4) Match(image *storage.ImageName) bool {
	return s.activeRegistries.Match(image)
}

func (s *scannerv4) Name() string {
	return s.name
}

func (s *scannerv4) Test() error {
	// TODO(ROX-20624): Dependent on the matcher/indexer test endpoints being avail.
	log.Warn("ScannerV4 - Returning FAKE 'success' to Test")
	return nil
}

func (s *scannerv4) Type() string {
	return types.ScannerV4
}

func (s *scannerv4) GetVulnerabilities(image *storage.Image, components *types.ScanComponents, _ []scannerv1.Note) (*storage.ImageScan, error) {
	v4Contents := components.ScannerV4()

	digest, err := pkgscanner.DigestFromImage(image)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	vr, err := s.scannerClient.GetVulnerabilities(ctx, digest, v4Contents)
	if err != nil {
		return nil, fmt.Errorf("get vulnerability report (reference: %q): %w", digest.Name(), err)
	}

	log.Debugf("Vuln report (match) received for %q (hash %q): %d dists, %d envs, %d pkgs, %d repos, %d pkg vulns, %d vulns",
		image.GetName().GetFullName(),
		vr.GetHashId(),
		len(vr.GetContents().GetDistributions()),
		len(vr.GetContents().GetEnvironments()),
		len(vr.GetContents().GetPackages()),
		len(vr.GetContents().GetRepositories()),
		len(vr.GetPackageVulnerabilities()),
		len(vr.GetVulnerabilities()),
	)

	return imageScan(image.GetMetadata(), vr), nil
}

func (s *scannerv4) GetNodeVulnerabilityReport(node *storage.Node, indexReport *v4.IndexReport) (*v4.VulnerabilityReport, error) {
	nodeDigest, err := name.NewDigest(mockDigest)
	if err != nil {
		log.Errorf("Failed to parse digest from node %q: %v", node.GetName(), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	vr, err := s.scannerClient.GetVulnerabilities(ctx, nodeDigest, indexReport.GetContents())
	if err != nil {
		return nil, errors.Wrap(err, "Scanner V4 client call to GetVulnerabilities")
	}

	return vr, nil
}

func (s *scannerv4) GetNodeInventoryScan(node *storage.Node, inv *storage.NodeInventory, ir *v4.IndexReport) (*storage.NodeScan, error) {
	if ir == nil && inv != nil {
		return nil, errors.New("Received Scanner v2 data for Scanner v4. Exiting.")
	}
	vr, err := s.GetNodeVulnerabilityReport(node, ir)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create vulnerability report")
	}
	log.Debugf("Received Vulnerability Report with %d packages containing %d vulnerabilities", len(vr.GetContents().GetPackages()), len(vr.Vulnerabilities))
	return toNodeScan(vr, node.GetOsImage()), nil
}

func (s *scannerv4) GetNodeScan(_ *storage.Node) (*storage.NodeScan, error) {
	return nil, errors.New("Not implemented for Scanner v4")
}

func (s *scannerv4) TestNodeScanner() error {
	log.Warn("NodeScanner v4 - Returning FAKE 'success' to Test")
	return nil
}

// NodeScannerCreator provides the type scanners.NodeScannerCreator to add to the scanners registry.
func NodeScannerCreator() (string, func(integration *storage.NodeIntegration) (scannerTypes.NodeScanner, error)) {
	return scannerTypes.ScannerV4, func(integration *storage.NodeIntegration) (scannerTypes.NodeScanner, error) {
		return newNodeScanner(integration)
	}
}

func newNodeScanner(integration *storage.NodeIntegration) (*scannerv4, error) {
	conf := integration.GetScannerv4()
	if conf == nil {
		return nil, errors.New("scanner v4 configuration required")
	}
	indexerEndpoint := DefaultIndexerEndpoint
	if conf.IndexerEndpoint != "" {
		indexerEndpoint = conf.IndexerEndpoint
	}

	matcherEndpoint := DefaultMatcherEndpoint
	if conf.MatcherEndpoint != "" {
		matcherEndpoint = conf.MatcherEndpoint
	}

	numConcurrentScans := defaultMaxConcurrentScans
	if conf.GetNumConcurrentScans() > 0 {
		numConcurrentScans = int64(conf.GetNumConcurrentScans())
	}

	log.Debugf("Creating Scanner V4 with name [%s] indexer address [%s], matcher address [%s], num concurrent scans [%d]", integration.GetName(), indexerEndpoint, matcherEndpoint, numConcurrentScans)
	ctx := context.Background()
	c, err := client.NewGRPCScanner(ctx,
		client.WithIndexerAddress(indexerEndpoint),
		client.WithMatcherAddress(matcherEndpoint),
	)
	if err != nil {
		return nil, err
	}

	scanner := &scannerv4{
		name:              integration.GetName(),
		activeRegistries:  nil,
		ScanSemaphore:     types.NewSemaphoreWithValue(numConcurrentScans),
		NodeScanSemaphore: types.NewNodeSemaphoreWithValue(numConcurrentScans),
		scannerClient:     c,
	}

	return scanner, nil
}

// VM Vulnerability Scanning functionality

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
	vmDigest, err := name.NewDigest(mockDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse digest for VM %s: %w", vmID, err)
	}

	// Create context with timeout - using the same timeout as other scans
	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
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
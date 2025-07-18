package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	pkgErrors "github.com/pkg/errors"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/errox"
	"github.com/stackrox/rox/pkg/images"
	"github.com/stackrox/rox/pkg/images/types"
	"github.com/stackrox/rox/pkg/images/utils"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/registries"
	"github.com/stackrox/rox/pkg/registries/docker"
	registryTypes "github.com/stackrox/rox/pkg/registries/types"
	"github.com/stackrox/rox/pkg/registrymirror"
	"github.com/stackrox/rox/pkg/signatures"
	"github.com/stackrox/rox/pkg/tlscheck"
	"github.com/stackrox/rox/sensor/common/scannerclient"
	scannerV1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
)

const (
	defaultMaxSemaphoreWaitTime = 5 * time.Second
	imageScanLowerBound         = 10
)

var (
	// ErrNoLocalScanner indicates there is no Secured Cluster local Scanner connection.
	// This happens if it's not desired or if there is a connection error.
	ErrNoLocalScanner = errors.New("no local Scanner connection")

	// ErrTooManyParallelScans indicates there are too many scans in progress and wait time
	// has been exceeded.
	ErrTooManyParallelScans = errors.New("too many parallel scans to local scanner")

	// ErrEnrichNotStarted will be wrapped by other more specific errors. It is used to determine
	// if the enrichment was never started and will be no messages sent to Central.
	ErrEnrichNotStarted = errors.New("enrich was not started")

	log = logging.LoggerForModule()
)

// LocalScan wraps the functions required for enriching local images. This allows us to inject different values for testing purposes.
type LocalScan struct {
	// NOTE: If you change these, make sure to also change the respective values within the tests.
	scanImg                   func(context.Context, *storage.Image, registryTypes.ImageRegistry, scannerclient.ScannerClient) (*scannerclient.ImageAnalysis, error)
	fetchSignaturesWithRetry  func(context.Context, signatures.SignatureFetcher, *storage.Image, string, registryTypes.Registry) ([]*storage.Signature, error)
	scannerClientSingleton    func() scannerclient.ScannerClient
	createNoAuthImageRegistry func(context.Context, *storage.ImageName, registries.Factory) (registryTypes.ImageRegistry, error)
	getCentralRegistries      func(*storage.ImageName) []registryTypes.ImageRegistry
	getPullSecretRegistries   func(*storage.ImageName, string, []string) ([]registryTypes.ImageRegistry, error)
	getGlobalRegistries       func(*storage.ImageName) ([]registryTypes.ImageRegistry, error)

	// scanSemaphore limits the number of active scans.
	scanSemaphore *semaphore.Weighted
	// adHocScanSemaphore limits the number of delegated scans.
	adHocScanSemaphore   *semaphore.Weighted
	maxSemaphoreWaitTime time.Duration

	regFactory registries.Factory

	mirrorStore registrymirror.Store
}

// LocalScanRequest encapsulates request specific fields used when enriching an image local to Sensor.
type LocalScanRequest struct {
	ID               string
	Image            *storage.ContainerImage
	ImagePullSecrets []string
	Namespace        string
	Force            bool
}

type registryStore interface {
	GetPullSecretRegistries(image *storage.ImageName, namespace string, imagePullSecrets []string) ([]registryTypes.ImageRegistry, error)
	GetGlobalRegistries(*storage.ImageName) ([]registryTypes.ImageRegistry, error)
	GetCentralRegistries(*storage.ImageName) []registryTypes.ImageRegistry
}

// LocalScanCentralClient interface to central's client
type LocalScanCentralClient interface {
	EnrichLocalImageInternal(context.Context, *v1.EnrichLocalImageInternalRequest, ...grpc.CallOption) (*v1.ScanImageInternalResponse, error)
}

// NewLocalScan initializes a LocalScan struct
func NewLocalScan(registryStore registryStore, mirrorStore registrymirror.Store) *LocalScan {
	regFactory := registries.NewFactory(registries.FactoryOptions{
		CreatorFuncs: []registryTypes.CreatorWrapper{
			docker.CreatorWithoutRepoList,
		},
	})
	activeScanSemaLimit := max(imageScanLowerBound, env.MaxParallelImageScanInternal.IntegerSetting()-env.MaxParallelAdHocScan.IntegerSetting())
	adHocSemaLimit := env.MaxParallelAdHocScan.IntegerSetting()
	images.SetSensorScanSemaphoreLimit(float64(activeScanSemaLimit), "sensor")
	images.SetSensorScanSemaphoreLimit(float64(adHocSemaLimit), "central")

	ls := &LocalScan{
		scanImg:                   scanImage,
		fetchSignaturesWithRetry:  signatures.FetchImageSignaturesWithRetries,
		scannerClientSingleton:    scannerclient.GRPCClientSingleton,
		scanSemaphore:             semaphore.NewWeighted(int64(activeScanSemaLimit)),
		adHocScanSemaphore:        semaphore.NewWeighted(int64(adHocSemaLimit)),
		maxSemaphoreWaitTime:      defaultMaxSemaphoreWaitTime,
		regFactory:                regFactory,
		mirrorStore:               mirrorStore,
		createNoAuthImageRegistry: createNoAuthImageRegistry,
		getCentralRegistries:      registryStore.GetCentralRegistries,
		getPullSecretRegistries:   registryStore.GetPullSecretRegistries,
		getGlobalRegistries:       registryStore.GetGlobalRegistries,
	}
	return ls
}

func acquireSemaphoreWithMetrics(semaphore *semaphore.Weighted, ctx context.Context, labelReqOrigin string) error {
	images.ScanSemaphoreQueueSize.WithLabelValues("sensor", "delegated-scan", labelReqOrigin).Inc()
	defer images.ScanSemaphoreQueueSize.WithLabelValues("sensor", "delegated-scan", labelReqOrigin).Dec()
	if err := semaphore.Acquire(ctx, 1); err != nil {
		return errors.Join(err, ErrTooManyParallelScans, ErrEnrichNotStarted)
	}
	images.ScanSemaphoreHoldingSize.WithLabelValues("sensor", "delegated-scan", labelReqOrigin).Inc()
	return nil
}

// EnrichLocalImageInNamespace will enrich an image with scan results from local scanner as well as signatures
// from the local registry. Afterwards, missing enriched data such as signature verification results and image
// vulnerabilities will be fetched from central, returning the fully enriched image. A request is always sent
// to central even if errors occur pulling metadata, scanning, or fetching signatures so that the error may be
// recorded.
//
// Will use the first registry that succeeds in pulling metadata from sync'd image integrations, pull secrets,
// the OCP global pull secret, or no auth if no registry found.
//
// Will return any errors that may occur during scanning or when reaching out to Central.
func (s *LocalScan) EnrichLocalImageInNamespace(ctx context.Context, centralClient LocalScanCentralClient, req *LocalScanRequest) (*storage.Image, error) {
	err := validateRequest(req)
	if err != nil {
		return nil, errors.Join(err, ErrEnrichNotStarted)
	}

	// Check if there is a local Scanner.
	// No need to continue if there is no local Scanner.
	if s.scannerClientSingleton() == nil {
		return nil, errors.Join(ErrNoLocalScanner, ErrEnrichNotStarted)
	}

	labelRequestOrigin := "sensor"
	// Throttle the # of active scans.
	scanLimitSemaphore := s.scanSemaphore
	// Ad hoc requests have a request ID.
	if req.ID != "" {
		labelRequestOrigin = "central"
		scanLimitSemaphore = s.adHocScanSemaphore
	}

	semaphoreCtx, cancel := context.WithTimeout(ctx, s.maxSemaphoreWaitTime)
	defer cancel()

	if err := acquireSemaphoreWithMetrics(scanLimitSemaphore, semaphoreCtx, labelRequestOrigin); err != nil {
		return nil, err
	}
	defer func() {
		scanLimitSemaphore.Release(1)
		images.ScanSemaphoreHoldingSize.WithLabelValues("sensor", "delegated-scan", labelRequestOrigin).Dec()
	}()

	srcImage := req.Image
	log.Debugf("Enriching image locally %q, namespace %q, requestID %q, force %v", srcImage.GetName().GetFullName(), req.Namespace, req.ID, req.Force)

	errorList := errorhelpers.NewErrorList("image enrichment")

	// Enrich image with metadata from one of registries.
	reg, pullSourceImage := s.getImageWithMetadata(ctx, errorList, req)
	if pullSourceImage == nil {
		// A nil pullSourceImage indicates that the source image and all
		// mirrors were invalid images.
		return nil, errors.Join(errorList.ToError(), ErrEnrichNotStarted)
	}

	// Perform partial scan (image analysis / identify components) via local scanner.
	scannerResp := s.fetchImageAnalysis(ctx, errorList, reg, pullSourceImage)

	// Fetch signatures associated with image from registry.
	sigs := s.fetchSignatures(ctx, errorList, reg, pullSourceImage)

	// Send local enriched data to central to receive a fully enrich image. This includes image vulnerabilities and
	// signature verification results.
	centralResp, err := centralClient.EnrichLocalImageInternal(ctx, &v1.EnrichLocalImageInternalRequest{
		ImageId:        srcImage.GetId(),
		ImageName:      srcImage.GetName(),
		Metadata:       pullSourceImage.GetMetadata(),
		Components:     scannerResp.GetComponents(),
		V4Contents:     scannerResp.GetContents(),
		Notes:          scannerResp.GetNotes(),
		IndexerVersion: scannerResp.GetIndexerVersion(),
		ImageSignature: &storage.ImageSignature{Signatures: sigs},
		ImageNotes:     pullSourceImage.GetNotes(),
		Error:          errorList.String(),
		RequestId:      req.ID,
		Force:          req.Force,
	})
	if err != nil {
		log.Debugf("Unable to enrich image %q: %v", srcImage.GetName().GetFullName(), err)
		return nil, pkgErrors.Wrapf(err, "enriching image %q via central", srcImage.GetName())
	}

	if errorList.Empty() {
		log.Debugf("Retrieved image enrichment results from Central for %q with id %q (%d) components", srcImage.GetName().GetFullName(), srcImage.GetId(), centralResp.GetImage().GetComponents())
	}

	return centralResp.GetImage(), errorList.ToError()
}

func (s *LocalScan) enrichImageForPullSource(ctx context.Context, pullSource *storage.ContainerImage, req *LocalScanRequest) (
	registryTypes.ImageRegistry, *storage.Image, error,
) {
	errorList := errorhelpers.NewErrorList(fmt.Sprintf("for pull source %q", pullSource.GetName().GetFullName()))

	registries, err := s.getRegistries(ctx, req.Namespace, pullSource.GetName(), req.ImagePullSecrets)
	if err != nil {
		log.Warnf("Error getting registries for pull source %q, skipping: %v", pullSource.GetName().GetFullName(), err)
		errorList.AddError(err)
		return nil, nil, pkgErrors.Wrap(errorList.ToError(), "getting registries for pull source")
	}

	log.Debugf("Using %d registries for enriching pull source %q", len(registries), pullSource.GetName().GetFullName())

	// Create an image and attempt to enrich it with metadata.
	pullSourceImage := types.ToImage(pullSource)
	reg := s.enrichImageWithMetadata(ctx, errorList, registries, pullSourceImage)
	if reg != nil {
		// Successful enrichment.
		enrichImageDataSource(req.Image, reg, pullSourceImage)

		srcName := req.Image.GetName().GetFullName()
		srcID := req.Image.GetId()
		pullName := pullSourceImage.GetName().GetFullName()
		pullID := pullSourceImage.GetId()
		log.Infof("Image %q (%v) enriched with metadata using pull source %q (%v) and integration %q (insecure: %t)", srcName, srcID, pullName, pullID, reg.Name(), reg.Config(ctx).GetInsecure())
		log.Debugf("Metadata for image %q (%v) using pull source %q (%v): %v", srcName, srcID, pullName, pullID, pullSourceImage.GetMetadata())
		return reg, pullSourceImage, nil
	}
	return nil, nil, pkgErrors.Wrap(errorList.ToError(), "enriching image metadata for pull source")
}

// getImageWithMetadata on success returns the registry used to pull metadata and an image with metadata populated.
// The image returned may represent the source image or an image from a registry mirror.
func (s *LocalScan) getImageWithMetadata(ctx context.Context, errorList *errorhelpers.ErrorList, req *LocalScanRequest) (registryTypes.ImageRegistry, *storage.Image) {
	// Obtain the pull sources, which will include mirrors.
	pullSources := s.getPullSources(req.Image)
	if len(pullSources) == 0 {
		errorList.AddError(pkgErrors.Errorf("zero valid pull sources found for image %q", req.Image.GetName().GetFullName()))
		return nil, nil
	}

	// allErrs are only added to errorList when attempts from all pull sources + all registries fail.
	allErrs := errorhelpers.NewErrorList("")

	// For each pull source, obtain the associated registries and attempt to obtain metadata, stopping on first success.
	for _, pullSource := range pullSources {
		reg, pullSourceImage, err := s.enrichImageForPullSource(ctx, pullSource, req)
		if err != nil {
			allErrs.AddError(err)
			continue
		}
		return reg, pullSourceImage
	}

	// Attempts for every pull source and registry have failed.
	errorList.AddErrors(allErrs.Errors()...)

	image := types.ToImage(req.Image)
	image.Notes = append(image.Notes, storage.Image_MISSING_METADATA)
	return nil, image
}

func enrichImageDataSource(sourceImage *storage.ContainerImage, reg registryTypes.ImageRegistry, targetImg *storage.Image) {
	ds := reg.DataSource().CloneVT()

	// If target is a mirror, then add mirror details to the data source.
	if sourceImage.GetName().GetFullName() != targetImg.GetName().GetFullName() {
		ds.Mirror = targetImg.GetName().GetFullName()
	}

	targetImg.GetMetadata().DataSource = ds
}

// getRegistries will return registries that match the provided image, starting with image integrations sync'd from Central,
// then namespace pull secrets, and lastly any global pull secrets (such as the OCP global pull secret). If no registries
// are found will return a new registry that has no credentials.
func (s *LocalScan) getRegistries(ctx context.Context, namespace string, imgName *storage.ImageName, imagePullSecrets []string) ([]registryTypes.ImageRegistry, error) {
	var regs []registryTypes.ImageRegistry

	// Add registries from Central's image integrations.
	if centralIntegrations := s.getCentralRegistries(imgName); len(centralIntegrations) > 0 {
		regs = append(regs, centralIntegrations...)
	}

	// Add registries from k8s pull secrets.
	if namespace != "" {
		// If namespace provided pull appropriate registry.
		// An err indicates no registry was found, only append if was no err.
		if sRegs, err := s.getPullSecretRegistries(imgName, namespace, imagePullSecrets); err == nil {
			regs = append(regs, sRegs...)
		}
	}

	// Add global pull secret registries.
	// An err indicates no registries were found, only append if was no err.
	if gRegs, err := s.getGlobalRegistries(imgName); err == nil {
		regs = append(regs, gRegs...)
	}

	// Create a no auth registry if no other registries have been found.
	if len(regs) == 0 {
		// No registries found thus far, create a no auth registry.
		reg, err := s.createNoAuthImageRegistry(ctx, imgName, s.regFactory)
		if err != nil {
			return nil, pkgErrors.Wrapf(err, "unable to create no auth integration for %q", imgName.GetFullName())
		}
		regs = append(regs, reg)
	}

	return regs, nil
}

func (s *LocalScan) getPullSources(srcImage *storage.ContainerImage) []*storage.ContainerImage {
	pullSources, err := s.mirrorStore.PullSources(srcImage.GetName().GetFullName())
	// A not exist error is expected when mirroring is not setup, therefore we do not log it.
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warnf("Error obtaining pull sources: %v", err)
	}

	if len(pullSources) == 0 {
		// If no pull source was found due to an error or some other reason, we
		// default to the source image.
		log.Debugf("Using source image only for enriching %q (id: %q)", srcImage.GetName().GetFullName(), srcImage.GetId())
		return []*storage.ContainerImage{srcImage}
	}

	// Convert and filter the pull sources.
	cImages := make([]*storage.ContainerImage, 0, len(pullSources))
	for _, pullSource := range pullSources {
		img, err := utils.GenerateImageFromString(pullSource)
		if err != nil {
			log.Warnf("Skipping pull source %q due to error generating image from string: %v", pullSource, err)
			continue
		}

		// This ID assignment addresses an edge case where a podspec references an image
		// by tag (e.g. latest) and the registry contents for that tag change after the pod was
		// created. We want to ensure that we pull metadata and layers based on the
		// ID (digest) of the running image instead of what the tag currently represents.
		// This condition will only be true for mirrors setup via the ImageTagMirrorSet (ITMS) CR.
		// The other supported CRs, ImageContentSourcePolicy (ICSP) and ImageDigestMirrorSet (IDMS),
		// will only match IF the podspec references the image by digest, in which case ID
		// would be populated and this condition never true.
		if img.GetId() == "" && srcImage.GetId() != "" {
			log.Debugf("Adding id from source image %q (id: %q) to pull source %q", srcImage.GetName().GetFullName(), srcImage.GetId(), img.GetName().GetFullName())
			img.Id = srcImage.GetId()
		}

		cImages = append(cImages, img)
	}

	log.Debugf("Using %d pull sources for enriching %q (id: %q): %+v", len(cImages), srcImage.GetName().GetFullName(), srcImage.GetId(), cImages)
	return cImages
}

// enrichImageWithMetadata will loop through registries returning the first that succeeds in enriching image with metadata.
func (s *LocalScan) enrichImageWithMetadata(ctx context.Context, errorList *errorhelpers.ErrorList,
	registries []registryTypes.ImageRegistry, image *storage.Image,
) registryTypes.ImageRegistry {
	var errs []error
	for _, reg := range registries {
		metadata, err := reg.Metadata(image)
		if err != nil {
			insecure := reg.Config(ctx).GetInsecure()
			log.Debugf("Failed fetching metadata for image %q (%q) with integration %q (insecure: %t): %v", image.GetName().GetFullName(), image.GetId(), reg.Name(), insecure, err)
			errs = append(errs, pkgErrors.Wrapf(err, "with integration %q (insecure: %t)", reg.Name(), insecure))
			continue
		}

		// Ensure the metadata is set on the image we pass to i.e. fetching signatures. If no V2 digest is available for the
		// image, the signature will not be attempted to be fetched.
		// We don't need to do anything on central side, as there the image will correctly have the metadata assigned.
		image.Metadata = metadata
		return reg
	}

	errorList.AddErrors(errs...)
	return nil
}

// fetchImageAnalysis analyzes an image via the local scanner. Does nothing if errorList contains errors.
func (s *LocalScan) fetchImageAnalysis(ctx context.Context, errorList *errorhelpers.ErrorList, registry registryTypes.ImageRegistry, image *storage.Image) *scannerclient.ImageAnalysis {
	if !errorList.Empty() {
		// do nothing if errors previously encountered.
		return nil
	}

	// Scan the image via local scanner.
	scannerResp, err := s.scanImg(ctx, image, registry, s.scannerClientSingleton())
	if err != nil {
		log.Debugf("Scan for image %q with id %v failed: %v", image.GetName().GetFullName(), image.GetId(), err)
		image.Notes = append(image.Notes, storage.Image_MISSING_SCAN_DATA)
		errorList.AddError(pkgErrors.Wrapf(err, "scanning image %q locally", image.GetName()))
		return nil
	}

	return scannerResp
}

// fetchSignatures fetches signatures from the registry for an image. Does nothing if errorList contains errors.
func (s *LocalScan) fetchSignatures(ctx context.Context, errorList *errorhelpers.ErrorList, registry registryTypes.ImageRegistry, image *storage.Image) []*storage.Signature {
	if !errorList.Empty() {
		// do nothing if errors previously encountered.
		return nil
	}

	// Fetch signatures from cluster-local registry.
	sigs, err := s.fetchSignaturesWithRetry(ctx, signatures.NewSignatureFetcher(), image, image.GetName().GetFullName(), registry)
	if err != nil {
		// Like Central, only log errors related to fetching signatures.
		if !errors.Is(err, errox.NotAuthorized) {
			log.Errorf("Fetching image signatures for image %q: %v", image.GetName().GetFullName(), err)
		} else {
			// Log not authorized errors in debug mode, since we expect them to occur.
			log.Debugf("Unauthorized error fetching image signatures for image %q: %v", image.GetName().GetFullName(), err)
		}
	}

	if len(sigs) == 0 {
		image.Notes = append(image.Notes, storage.Image_MISSING_SIGNATURE)
	}

	return sigs
}

// scanImage will scan the given image and return its components.
func scanImage(ctx context.Context, image *storage.Image,
	registry registryTypes.ImageRegistry, scannerClient scannerclient.ScannerClient,
) (*scannerclient.ImageAnalysis, error) {
	// Get the image analysis from the local Scanner.
	scanResp, err := scannerClient.GetImageAnalysis(ctx, image, registry.Config(ctx))
	if err != nil {
		return nil, pkgErrors.Wrap(err, "getting image analysis from local scanner")
	}
	// Return an error indicating a non-successful scan result.
	if scanResp.GetStatus() != scannerV1.ScanStatus_SUCCEEDED {
		return nil, fmt.Errorf("scan failed with status %q", scanResp.GetStatus().String())
	}

	return scanResp, nil
}

// createNoAuthImageRegistry creates an image registry that has no user/pass.
func createNoAuthImageRegistry(ctx context.Context, imgName *storage.ImageName, regFactory registries.Factory) (registryTypes.ImageRegistry, error) {
	reg := imgName.GetRegistry()
	if reg == "" {
		return nil, errors.New("no image registry provided, nothing to do")
	}

	secure, err := tlscheck.CheckTLS(ctx, reg)
	if err != nil {
		return nil, pkgErrors.Wrapf(err, "unable to check TLS for registry %q", reg)
	}

	name := fmt.Sprintf("%s/reg:%v", registryTypes.NoAuthNamePrefix, reg)
	ii := &storage.ImageIntegration{
		Id:         name,
		Name:       name,
		Type:       registryTypes.DockerType,
		Categories: []storage.ImageIntegrationCategory{storage.ImageIntegrationCategory_REGISTRY},
		IntegrationConfig: &storage.ImageIntegration_Docker{
			Docker: &storage.DockerConfig{
				Endpoint: reg,
				Insecure: !secure,
			},
		},
	}

	registry, err := regFactory.CreateRegistry(ii)
	if err != nil {
		return nil, pkgErrors.Wrapf(err, "creating no-auth image registry for %q", imgName.GetRegistry())
	}
	return registry, nil
}

// validateRequest will return an error if the request is invalid per local
// scanning expectations.
func validateRequest(req *LocalScanRequest) error {
	if req == nil {
		return pkgErrors.New("request is nil")
	}

	if req.Image == nil {
		return pkgErrors.New("missing image")
	}

	if req.Image.GetName() == nil {
		return pkgErrors.New("missing image name")
	}

	// A fully qualified image is expected at this point.
	if req.Image.GetName().GetRegistry() == "" {
		return pkgErrors.New("missing image registry")
	}

	return nil
}

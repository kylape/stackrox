package env

import "time"

// These environment variables are used in the deployment file.
// Please check the files before deleting.
var (
	// AdvertisedEndpoint is used to provide the Sensor with the endpoint it
	// should advertise to services that need to contact it, within its own cluster.
	AdvertisedEndpoint = RegisterSetting("ROX_ADVERTISED_ENDPOINT", WithDefault("sensor.stackrox.svc:443"),
		StripAnyPrefix("https://", "http://"))

	// SensorEndpoint is used to communicate the sensor endpoint to other services in the same cluster.
	SensorEndpoint = RegisterSetting("ROX_SENSOR_ENDPOINT", WithDefault("sensor.stackrox.svc:443"))

	// ScannerSlimGRPCEndpoint is used to communicate the scanner endpoint to other services in the same cluster.
	// This is typically used for Sensor to communicate with a local Scanner-slim's gRPC server.
	ScannerSlimGRPCEndpoint = RegisterSetting("ROX_SCANNER_GRPC_ENDPOINT", WithDefault("scanner.stackrox.svc:8443"))

	// ScannerV4IndexerEndpoint is used to communicate with the Scanner V4 Indexer endpoint in the same cluster.
	ScannerV4IndexerEndpoint = RegisterSetting("ROX_SCANNER_V4_INDEXER_ENDPOINT", WithDefault("scanner-v4-indexer.stackrox.svc:8443"))

	// LocalImageScanningEnabled is used to specify if Sensor should attempt to scan images via a local Scanner.
	LocalImageScanningEnabled = RegisterBooleanSetting("ROX_LOCAL_IMAGE_SCANNING_ENABLED", false)

	// EventPipelineQueueSize is used to specify the size of the eventPipeline's queues.
	EventPipelineQueueSize = RegisterIntegerSetting("ROX_EVENT_PIPELINE_QUEUE_SIZE", 1000)

	// ConnectionRetryInitialInterval defines how long it takes for sensor to retry gRPC connection when it first disconnects.
	ConnectionRetryInitialInterval = registerDurationSetting("ROX_SENSOR_CONNECTION_RETRY_INITIAL_INTERVAL", 10*time.Second)

	// ConnectionRetryMaxInterval defines the maximum interval between retries after the gRPC connection disconnects.
	ConnectionRetryMaxInterval = registerDurationSetting("ROX_SENSOR_CONNECTION_RETRY_MAX_INTERVAL", 5*time.Minute)

	// DelegatedScanningDisabled disables the capabilities associated with delegated image scanning.
	// This is meant to be a 'kill switch' that allows for local scanning to continue (ie: for OCP internal repos)
	// in the event the delegated scanning capabilities are causing unforeseen issues.
	DelegatedScanningDisabled = RegisterBooleanSetting("ROX_DELEGATED_SCANNING_DISABLED", false)

	// DeduperStateSyncTimeout defines the maximum time Sensor will wait for the expected deduper state coming from Central.
	DeduperStateSyncTimeout = registerDurationSetting("ROX_DEDUPER_STATE_TIMEOUT", 30*time.Second)

	// NetworkFlowBufferSize holds the size of how many network flows updates will be kept in Sensor while offline.
	// 1 Item in the buffer = ~100 bytes per flow
	// 100 (per flow) * 1000 (flows) * 100 (buffer size) = 10 MB
	NetworkFlowBufferSize = RegisterIntegerSetting("ROX_SENSOR_NETFLOW_OFFLINE_BUFFER_SIZE", 100)

	// ProcessIndicatorBufferSize indicates how many process indicators will be kept in Sensor while offline.
	// 1 Item in the buffer = ~300 bytes
	// 50000 * 300 = 15 MB
	ProcessIndicatorBufferSize = RegisterIntegerSetting("ROX_SENSOR_PROCESS_INDICATOR_BUFFER_SIZE", 50000)

	// DetectorProcessIndicatorBufferSize indicates how many process indicators will be kept in Sensor while offline in the detector.
	// 1 Item in the buffer = ~1000 bytes
	// 20000 * 1000 = 20 MB
	// Notice: the actual size of each item is ~40 bytes since it holds pointers to the actual objects.
	// Multiple items can hold a pointer to the same object (e.g. same Deployment) so these numbers are pessimistic because we assume all items hold different objects.
	DetectorProcessIndicatorBufferSize = RegisterIntegerSetting("ROX_SENSOR_DETECTOR_PROCESS_INDICATOR_BUFFER_SIZE", 20000)

	// DetectorNetworkFlowBufferSize indicates how many network flows will be kept in Sensor while offline in the detector.
	// 1 Item in the buffer = ~1000 bytes
	// 20000 * 1000 = 20 MB
	// Notice: the actual size of each item is ~40 bytes since it holds pointers to the actual objects.
	// Multiple items can hold a pointer to the same object (e.g. same Deployment) so these numbers are pessimistic because we assume all items hold different objects.
	DetectorNetworkFlowBufferSize = RegisterIntegerSetting("ROX_SENSOR_DETECTOR_NETWORK_FLOW_BUFFER_SIZE", 20000)

	// DetectorDeploymentBufferSize indicates how many deployments will be kept in Sensor while offline in the detector.
	// 1 Item in the buffer = ~1000 bytes
	// 20000 * 1000 = 20 MB
	// Notice: the actual size of each item is ~40 bytes since it holds pointers to the actual objects.
	// Multiple items can hold a pointer to the same object (e.g. same Deployment) so these numbers are pessimistic because we assume all items hold different objects.
	DetectorDeploymentBufferSize = RegisterIntegerSetting("ROX_SENSOR_DETECTOR_DEPLOYMENT_BUFFER_SIZE", 20000)

	// BufferScaleCeiling sets the upper limit queue.ScaleSize will scale buffers and queues to.
	// In its default, the ceiling is defined as triple the relative size.
	// For example, the NetflowBufferSize will never surpass 100 * 3 = 300.
	BufferScaleCeiling = RegisterIntegerSetting("ROX_SENSOR_BUFFER_SCALE_CEILING", 3)

	// DiagnosticDataCollectionTimeout defines the timeout for the diagnostic data collection on Sensor side.
	DiagnosticDataCollectionTimeout = registerDurationSetting("ROX_DIAGNOSTIC_DATA_COLLECTION_TIMEOUT",
		2*time.Minute)

	// SensorComplianceChannelBufferSize defines how many node scanning ACK messages may be buffered before sending them to Compliance
	SensorComplianceChannelBufferSize = RegisterIntegerSetting("ROX_SENSOR_COMPLIANCE_CHANNEL_BUFFER_SIZE", 2)

	// ResponsesChannelBufferSize defines how many messages to central are we buffering before dropping messages
	// Setting this variable to zero will disable this feature.
	ResponsesChannelBufferSize = RegisterIntegerSetting("ROX_RESPONSES_CHANNEL_BUFFER_SIZE", 100000)

	// EnrichmentPurgerTickerMaxAge controls the max age of collector updates (network flows & container endpoints)
	// for keeping them in  Sensor's memory. Entries that has not been enriched (due to a bug or error)
	// will stay in Sensors memory until restart. Purger cleans all those entries based on rules.
	// The max-age is a rule of last resort (when all other rules do not apply) and is used to protect Sensor from OOM kills.
	// Set to zero to not purge based on max-age (other purger rules will be executed).
	// Disabled (set to 0), because removing items from the enrichment queue (hostConnections) causes
	// unintended messages being sent to central about endpoints listening on ports being closed, whereas in fact
	// they are not closed but only removed from the queue. To enable this, we need a refactor
	// to decouple the enrichment queue from the mechanism that sends updates to Central.
	EnrichmentPurgerTickerMaxAge = registerDurationSetting("ROX_ENRICHMENT_PURGER_MAX_AGE", 0, WithDurationZeroAllowed())
	// EnrichmentPurgerTickerCycle controls how frequently purger is run to check for collector updates
	// (network flows & container endpoints) that stuck in Sensor's memory. Set to zero to completely disable the purger.
	EnrichmentPurgerTickerCycle = registerDurationSetting("ROX_ENRICHMENT_PURGER_UPDATE_CYCLE", 30*time.Minute, WithDurationZeroAllowed())
	// PastSensorsMaxEntries sets the limit of entries that Sensor stores about its past instances in the `sensor-past-instances` configmap.
	PastSensorsMaxEntries = RegisterIntegerSetting("ROX_PAST_SENSORS_MAX_ENTRIES", 20).WithMinimum(2)
	// PastSensorsConfigmapName defines the name of the configmap where Sensor's metadata about past instances are stored
	PastSensorsConfigmapName = RegisterSetting("ROX_PAST_SENSORS_CONFIG_MAP_NAME", WithDefault("sensor-past-instances"))
)

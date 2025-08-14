package client

//go:generate mockgen-wrapper CentralClient

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/clientconn"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/mtls"
	"github.com/stackrox/rox/pkg/size"
	platformv1alpha1 "github.com/stackrox/rox/results-controller/api/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	centralHostPort = fmt.Sprintf("central.%s.svc:443", env.Namespace.Setting())
	log             = logging.LoggerForModule()
)

// getClusterName returns the current cluster name
// TODO: This should be populated from the actual cluster identity
func getClusterName() string {
	// For now, return a placeholder. This should be enhanced to:
	// 1. Read from environment variable if set
	// 2. Query Kubernetes API for cluster info
	// 3. Use a default based on the deployment
	if clusterName := os.Getenv("ROX_CLUSTER_NAME"); clusterName != "" {
		return clusterName
	}
	return "local-cluster" // Default fallback
}

// CentralClient defines the interface for communicating with StackRox Central
type CentralClient interface {
	// GetVulnerabilitiesForNamespace retrieves vulnerability data for a specific namespace
	GetVulnerabilitiesForNamespace(ctx context.Context, namespace, clusterName string) ([]platformv1alpha1.VulnerabilityInfo, error)

	// GetPolicyViolationsForNamespace retrieves policy violations (alerts) for a specific namespace
	GetPolicyViolationsForNamespace(ctx context.Context, namespace, clusterName string) ([]platformv1alpha1.PolicyViolationInfo, error)

	// TestConnection verifies the connection to Central is working
	TestConnection(ctx context.Context) error
}

type perRPCCreds struct {
	svc         v1.AuthServiceClient
	metadata    map[string]string
	lastUpdated time.Time
}

func (c *perRPCCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return c.metadata, nil
}

func (c *perRPCCreds) RequireTransportSecurity() bool {
	return true
}

func (c *perRPCCreds) refreshToken(ctx context.Context) error {
	log.Debug("Refreshing Central API token")
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return errors.WithMessage(err, "error reading service account token file")
	}

	req := v1.ExchangeAuthMachineToMachineTokenRequest{
		IdToken: string(token),
	}

	resp, err := c.svc.ExchangeAuthMachineToMachineToken(ctx, &req)
	if err != nil {
		return errors.WithMessage(err, "error exchanging service account token for API token")
	}

	c.metadata = map[string]string{
		"authorization": fmt.Sprintf("Bearer %s", resp.GetAccessToken()),
	}
	c.lastUpdated = time.Now()

	log.Debug("Successfully refreshed Central API token")
	return nil
}

type centralClient struct {
	conn        *grpc.ClientConn
	authClient  v1.AuthServiceClient
	vulnClient  v1.VulnMgmtServiceClient
	alertClient v1.AlertServiceClient
	creds       *perRPCCreds
}

// New creates a new Central client with M2M authentication
func New(ctx context.Context) (CentralClient, error) {
	log.Info("Connecting to Central", "endpoint", centralHostPort)

	clientconn.SetUserAgent(clientconn.Sensor) // Use Sensor user agent for results controller

	// Create per-RPC credentials for M2M token authentication
	creds := &perRPCCreds{
		metadata: make(map[string]string),
	}

	// Setup connection options similar to config-controller
	dialOpts := []grpc.DialOption{
		grpc.WithNoProxy(),
	}

	opts := clientconn.Options{
		InsecureNoTLS:                  false,
		InsecureAllowCredsViaPlaintext: false,
		DialOptions:                    dialOpts,
		PerRPCCreds:                    creds,
	}

	callOpts := []grpc.CallOption{grpc.MaxCallRecvMsgSize(12 * size.MB)}

	conn, err := clientconn.GRPCConnection(ctx, mtls.CentralSubject, centralHostPort, opts, grpc.WithDefaultCallOptions(callOpts...))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to Central at %s", centralHostPort)
	}

	// Set auth service for token refresh
	creds.svc = v1.NewAuthServiceClient(conn)

	// Get initial token
	if err := creds.refreshToken(ctx); err != nil {
		conn.Close()
		return nil, errors.Wrap(err, "failed to get initial authentication token")
	}

	client := &centralClient{
		conn:        conn,
		authClient:  v1.NewAuthServiceClient(conn),
		vulnClient:  v1.NewVulnMgmtServiceClient(conn),
		alertClient: v1.NewAlertServiceClient(conn),
		creds:       creds,
	}

	log.Info("Successfully connected to Central")
	return client, nil
}

// TestConnection verifies the connection to Central is working
func (c *centralClient) TestConnection(ctx context.Context) error {
	_, err := c.authClient.GetAuthStatus(ctx, &v1.Empty{})
	if err != nil {
		return errors.Wrap(err, "failed to test connection to Central")
	}
	return nil
}

// GetVulnerabilitiesForNamespace retrieves vulnerability data for a specific namespace
func (c *centralClient) GetVulnerabilitiesForNamespace(ctx context.Context, namespace, clusterName string) ([]platformv1alpha1.VulnerabilityInfo, error) {
	// Check if token needs refresh (refresh every 30 minutes)
	if time.Since(c.creds.lastUpdated) > 30*time.Minute {
		if err := c.creds.refreshToken(ctx); err != nil {
			return nil, errors.Wrap(err, "failed to refresh authentication token")
		}
	}

	// Query vulnerabilities for deployments in the namespace and cluster
	query := fmt.Sprintf("Namespace:%s+Cluster:%s", namespace, clusterName)
	req := &v1.VulnMgmtExportWorkloadsRequest{
		Query:   query,
		Timeout: 30, // 30 second timeout
	}

	stream, err := c.vulnClient.VulnMgmtExportWorkloads(ctx, req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query vulnerabilities for namespace %s in cluster %s", namespace, clusterName)
	}

	var vulnerabilities []platformv1alpha1.VulnerabilityInfo
	vulnMap := make(map[string]*platformv1alpha1.VulnerabilityInfo)

	for {
		resp, err := stream.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, errors.Wrap(err, "error receiving vulnerability data")
		}

		deployment := resp.GetDeployment()
		images := resp.GetImages()

		for _, image := range images {
			if image.GetScan() == nil {
				continue
			}

			for _, component := range image.GetScan().GetComponents() {
				for _, vuln := range component.GetVulns() {
					cve := vuln.GetCve()
					if cve == "" {
						continue
					}

					// Aggregate vulnerabilities by CVE
					if existing, found := vulnMap[cve]; found {
						// Add this image and deployment to existing vulnerability
						existing.AffectedImages = appendUnique(existing.AffectedImages, image.GetName().GetFullName())
						existing.AffectedDeployments = appendUnique(existing.AffectedDeployments, deployment.GetName())
					} else {
						// Create new vulnerability entry
						vuln := &platformv1alpha1.VulnerabilityInfo{
							CVE:                 cve,
							Severity:            convertVulnerabilitySeverity(vuln.GetSeverity()),
							CVSS:                float64(vuln.GetCvss()),
							Summary:             vuln.GetSummary(),
							Fixable:             vuln.GetFixedBy() != "",
							FixedByVersion:      vuln.GetFixedBy(),
							AffectedImages:      []string{image.GetName().GetFullName()},
							AffectedDeployments: []string{deployment.GetName()},
						}

						if image.GetScan().GetScanTime() != nil {
							scanTime := metav1.NewTime(image.GetScan().GetScanTime().AsTime())
							vuln.LastScanned = &scanTime
						}

						vulnMap[cve] = vuln
					}
				}
			}
		}
	}

	// Convert map to slice and limit to 100 items
	count := 0
	for _, vuln := range vulnMap {
		if count >= 100 {
			break
		}
		vulnerabilities = append(vulnerabilities, *vuln)
		count++
	}

	log.Debug("Retrieved vulnerabilities for namespace", "namespace", namespace, "count", len(vulnerabilities))
	return vulnerabilities, nil
}

// GetPolicyViolationsForNamespace retrieves policy violations (alerts) for a specific namespace
func (c *centralClient) GetPolicyViolationsForNamespace(ctx context.Context, namespace, clusterName string) ([]platformv1alpha1.PolicyViolationInfo, error) {
	// Check if token needs refresh
	if time.Since(c.creds.lastUpdated) > 30*time.Minute {
		if err := c.creds.refreshToken(ctx); err != nil {
			return nil, errors.Wrap(err, "failed to refresh authentication token")
		}
	}

	// Query active alerts for the namespace and cluster
	query := fmt.Sprintf("Namespace:%s+Cluster:%s+Violation State:Active", namespace, clusterName)
	req := &v1.ListAlertsRequest{
		Query: query,
		Pagination: &v1.Pagination{
			Limit: 50, // Limit to 50 policy violations
		},
	}

	resp, err := c.alertClient.ListAlerts(ctx, req)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query alerts for namespace %s in cluster %s", namespace, clusterName)
	}

	var violations []platformv1alpha1.PolicyViolationInfo
	for _, alert := range resp.GetAlerts() {
		violation := platformv1alpha1.PolicyViolationInfo{
			AlertID:      alert.GetId(),
			PolicyName:   alert.GetPolicy().GetName(),
			Severity:     convertSeverity(alert.GetPolicy().GetSeverity()),
			Description:  alert.GetPolicy().GetDescription(),
			ResourceName: alert.GetDeployment().GetName(),
			ResourceType: "Deployment",
			State:        convertViolationState(alert.GetState()),
			Categories:   alert.GetPolicy().GetCategories(),
		}

		if alert.GetTime() != nil {
			firstOccurred := metav1.NewTime(alert.GetTime().AsTime())
			violation.FirstOccurred = &firstOccurred
			violation.LastOccurred = &firstOccurred
		}

		violations = append(violations, violation)
	}

	log.Debug("Retrieved policy violations for namespace", "namespace", namespace, "count", len(violations))
	return violations, nil
}

// Helper functions

func convertVulnerabilitySeverity(severity storage.VulnerabilitySeverity) string {
	switch severity {
	case storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY:
		return "Low"
	case storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY:
		return "Medium"
	case storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY:
		return "High"
	case storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY:
		return "Critical"
	default:
		return "Unknown"
	}
}

func convertSeverity(severity storage.Severity) string {
	switch severity {
	case storage.Severity_LOW_SEVERITY:
		return "Low"
	case storage.Severity_MEDIUM_SEVERITY:
		return "Medium"
	case storage.Severity_HIGH_SEVERITY:
		return "High"
	case storage.Severity_CRITICAL_SEVERITY:
		return "Critical"
	default:
		return "Unknown"
	}
}

func convertViolationState(state storage.ViolationState) string {
	switch state {
	case storage.ViolationState_ACTIVE:
		return "Active"
	case storage.ViolationState_RESOLVED:
		return "Resolved"
	case storage.ViolationState_ATTEMPTED:
		return "Snoozed" // Map ATTEMPTED to Snoozed for compatibility
	default:
		return "Unknown"
	}
}

func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

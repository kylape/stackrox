package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/retry"
	"github.com/stackrox/rox/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

const (
	podAttachPolicyName = "Kubernetes Actions: Attach to Pod"
	testNamespace      = "qa-pod-attach-test"
	testPodName        = "test-nginx-pod"
	testContainerName  = "nginx"
)

func TestPodAttachDetection(t *testing.T) {
	// Setup test environment
	ctx := context.Background()
	k8sClient := getK8sClient(t)
	roxClient := getRoxClient(t)

	// Create test namespace
	namespace := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	_, err := k8sClient.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	require.NoError(t, err)
	defer cleanupNamespace(t, k8sClient, testNamespace)

	// Ensure pod attach policy is enabled
	enablePodAttachPolicy(t, roxClient)

	// Create a test pod
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testNamespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    testContainerName,
					Image:   "nginx:alpine",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c", "while true; do sleep 30; done"},
					Stdin:   true,
					TTY:     true,
				},
			},
		},
	}

	createdPod, err := k8sClient.CoreV1().Pods(testNamespace).Create(ctx, pod, metav1.CreateOptions{})
	require.NoError(t, err)

	// Wait for pod to be running
	err = waitForPodRunning(k8sClient, testNamespace, testPodName, 2*time.Minute)
	require.NoError(t, err)

	// Record current time for alert filtering
	attachTime := time.Now()

	// Perform pod attach operation
	err = attachToPod(k8sClient, testNamespace, testPodName, testContainerName)
	require.NoError(t, err)

	// Wait for and verify the alert
	var foundAlert *storage.Alert
	err = retry.WithRetry(func() error {
		// Query for runtime alerts
		alerts, err := roxClient.GetRuntimeAlerts(ctx, &storage.ListAlertsRequest{
			Query: fmt.Sprintf("Policy:\"%s\" AND Namespace:%s", podAttachPolicyName, testNamespace),
		})
		if err != nil {
			return retry.MakeRetryable(err)
		}

		// Look for our specific alert
		for _, alert := range alerts.GetAlerts() {
			// Check if alert is after our attach time
			if alert.GetTime().AsTime().After(attachTime) &&
				strings.Contains(alert.GetViolationMessage(), testPodName) {
				foundAlert = alert
				return nil
			}
		}

		return retry.MakeRetryable(fmt.Errorf("pod attach alert not found yet"))
	}, retry.Tries(20), retry.BetweenAttempts(func(previousAttempt int) {
		time.Sleep(3 * time.Second)
	}))

	require.NoError(t, err, "Failed to find pod attach alert")
	require.NotNil(t, foundAlert)

	// Verify alert details
	assert.Equal(t, podAttachPolicyName, foundAlert.GetPolicy().GetName())
	assert.Equal(t, storage.Severity_HIGH_SEVERITY, foundAlert.GetPolicy().GetSeverity())
	assert.Equal(t, testNamespace, foundAlert.GetNamespace())
	assert.Contains(t, foundAlert.GetViolationMessage(), testPodName)
	assert.Contains(t, foundAlert.GetViolationMessage(), testContainerName)
	assert.Contains(t, foundAlert.GetViolationMessage(), "attach session initiated")
	
	// Verify the violation message includes attach options
	violationMsg := foundAlert.GetViolationMessage()
	assert.Contains(t, violationMsg, "stdin")
	assert.Contains(t, violationMsg, "stdout")
	assert.Contains(t, violationMsg, "tty")

	// Verify Kubernetes event details
	kubeEvent := foundAlert.GetKubernetesEvent()
	require.NotNil(t, kubeEvent)
	assert.Equal(t, storage.KubernetesEvent_Object_PODS_ATTACH, kubeEvent.GetObject().GetResource())
	assert.Equal(t, testPodName, kubeEvent.GetObject().GetName())
	assert.Equal(t, testNamespace, kubeEvent.GetObject().GetNamespace())
	
	// Verify user information is captured
	assert.NotEmpty(t, kubeEvent.GetUser().GetUsername())
	assert.NotEmpty(t, kubeEvent.GetUser().GetGroups())
}

func TestPodAttachDifferentOptions(t *testing.T) {
	// Test various attach configurations
	testCases := []struct {
		name           string
		stdin          bool
		stdout         bool
		stderr         bool
		tty            bool
		expectedInMsg  []string
	}{
		{
			name:          "stdin and tty only",
			stdin:         true,
			stdout:        false,
			stderr:        false,
			tty:           true,
			expectedInMsg: []string{"stdin", "tty"},
		},
		{
			name:          "stdout and stderr only",
			stdin:         false,
			stdout:        true,
			stderr:        true,
			tty:           false,
			expectedInMsg: []string{"stdout", "stderr"},
		},
		{
			name:          "all options enabled",
			stdin:         true,
			stdout:        true,
			stderr:        true,
			tty:           true,
			expectedInMsg: []string{"stdin", "stdout", "stderr", "tty"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			k8sClient := getK8sClient(t)
			roxClient := getRoxClient(t)

			// Create unique namespace for this test
			testNS := fmt.Sprintf("qa-attach-test-%d", time.Now().Unix())
			namespace := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNS,
				},
			}
			_, err := k8sClient.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
			require.NoError(t, err)
			defer cleanupNamespace(t, k8sClient, testNS)

			// Create test pod
			podName := fmt.Sprintf("test-pod-%s", tc.name)
			pod := createTestPod(podName, testNS)
			_, err = k8sClient.CoreV1().Pods(testNS).Create(ctx, pod, metav1.CreateOptions{})
			require.NoError(t, err)

			// Wait for pod to be running
			err = waitForPodRunning(k8sClient, testNS, podName, 2*time.Minute)
			require.NoError(t, err)

			// Perform attach with specific options
			attachTime := time.Now()
			err = attachToPodWithOptions(k8sClient, testNS, podName, testContainerName,
				tc.stdin, tc.stdout, tc.stderr, tc.tty)
			require.NoError(t, err)

			// Verify alert contains expected options
			alert := waitForAttachAlert(t, roxClient, testNS, podName, attachTime)
			require.NotNil(t, alert)

			violationMsg := alert.GetViolationMessage()
			for _, expected := range tc.expectedInMsg {
				assert.Contains(t, violationMsg, expected,
					"Expected '%s' in violation message", expected)
			}
		})
	}
}

// Helper functions

func enablePodAttachPolicy(t *testing.T, roxClient RoxClient) {
	ctx := context.Background()
	
	// Get the pod attach policy
	policies, err := roxClient.GetPolicies(ctx, &storage.RawQuery{
		Query: fmt.Sprintf("Policy:\"%s\"", podAttachPolicyName),
	})
	require.NoError(t, err)
	require.Len(t, policies.GetPolicies(), 1, "Pod attach policy not found")

	policy := policies.GetPolicies()[0]
	
	// Enable the policy if it's disabled
	if policy.GetDisabled() {
		policy.Disabled = false
		_, err = roxClient.UpdatePolicy(ctx, policy)
		require.NoError(t, err)
	}
}

func attachToPod(k8sClient kubernetes.Interface, namespace, podName, containerName string) error {
	return attachToPodWithOptions(k8sClient, namespace, podName, containerName, true, true, true, true)
}

func attachToPodWithOptions(k8sClient kubernetes.Interface, namespace, podName, containerName string,
	stdin, stdout, stderr, tty bool) error {
	
	config := k8sClient.CoreV1().RESTClient().(*rest.RESTClient).Config
	req := k8sClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("attach").
		VersionedParams(&v1.PodAttachOptions{
			Container: containerName,
			Stdin:     stdin,
			Stdout:    stdout,
			Stderr:    stderr,
			TTY:       tty,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return err
	}

	// Create a simple stream that immediately closes
	// This is enough to trigger the admission webhook
	stream := &fakeStream{
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
		tty:    tty,
	}

	// Start the attach session
	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  stream,
		Stdout: stream,
		Stderr: stream,
		Tty:    tty,
	})

	// We expect the stream to fail/close quickly, which is fine
	// The important part is that the admission webhook was triggered
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return err
	}

	return nil
}

func waitForPodRunning(k8sClient kubernetes.Interface, namespace, podName string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return retry.WithRetry(func() error {
		pod, err := k8sClient.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return retry.MakeRetryable(err)
		}

		if pod.Status.Phase != v1.PodRunning {
			return retry.MakeRetryable(fmt.Errorf("pod is not running yet, current phase: %s", pod.Status.Phase))
		}

		// Check container is ready
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if !containerStatus.Ready {
				return retry.MakeRetryable(fmt.Errorf("container %s is not ready", containerStatus.Name))
			}
		}

		return nil
	}, retry.Tries(40), retry.BetweenAttempts(func(previousAttempt int) {
		time.Sleep(3 * time.Second)
	}))
}

func waitForAttachAlert(t *testing.T, roxClient RoxClient, namespace, podName string, afterTime time.Time) *storage.Alert {
	var foundAlert *storage.Alert
	
	err := retry.WithRetry(func() error {
		ctx := context.Background()
		alerts, err := roxClient.GetRuntimeAlerts(ctx, &storage.ListAlertsRequest{
			Query: fmt.Sprintf("Policy:\"%s\" AND Namespace:%s", podAttachPolicyName, namespace),
		})
		if err != nil {
			return retry.MakeRetryable(err)
		}

		for _, alert := range alerts.GetAlerts() {
			if alert.GetTime().AsTime().After(afterTime) &&
				strings.Contains(alert.GetViolationMessage(), podName) {
				foundAlert = alert
				return nil
			}
		}

		return retry.MakeRetryable(fmt.Errorf("pod attach alert not found yet"))
	}, retry.Tries(20), retry.BetweenAttempts(func(previousAttempt int) {
		time.Sleep(3 * time.Second)
	}))

	require.NoError(t, err, "Failed to find pod attach alert")
	return foundAlert
}

func createTestPod(name, namespace string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:    testContainerName,
					Image:   "nginx:alpine",
					Command: []string{"/bin/sh"},
					Args:    []string{"-c", "while true; do sleep 30; done"},
					Stdin:   true,
					TTY:     true,
				},
			},
		},
	}
}

func cleanupNamespace(t *testing.T, k8sClient kubernetes.Interface, namespace string) {
	ctx := context.Background()
	err := k8sClient.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	if err != nil {
		t.Logf("Failed to cleanup namespace %s: %v", namespace, err)
	}
}

// fakeStream implements the stream interfaces needed for attach
type fakeStream struct {
	stdin  bool
	stdout bool
	stderr bool
	tty    bool
}

func (f *fakeStream) Read(p []byte) (n int, err error) {
	// Return EOF immediately to close the stream
	return 0, fmt.Errorf("EOF")
}

func (f *fakeStream) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// Mock interfaces - these would typically come from your test framework
type RoxClient interface {
	GetPolicies(ctx context.Context, query *storage.RawQuery) (*storage.ListPoliciesResponse, error)
	UpdatePolicy(ctx context.Context, policy *storage.Policy) (*storage.Policy, error)
	GetRuntimeAlerts(ctx context.Context, request *storage.ListAlertsRequest) (*storage.ListAlertsResponse, error)
}

func getK8sClient(t *testing.T) kubernetes.Interface {
	// This would return your configured Kubernetes client
	t.Fatal("getK8sClient not implemented - use your test framework's client")
	return nil
}

func getRoxClient(t *testing.T) RoxClient {
	// This would return your configured StackRox client
	t.Fatal("getRoxClient not implemented - use your test framework's client")
	return nil
}
# Pod Attach Implementation Plan for StackRox Admission Controller

## Overview
This document outlines the implementation plan for adding pod attach event interception to the StackRox admission controller, which currently only intercepts pod exec events.

## Current State
- The admission controller intercepts `pods/exec` and `pods/portforward` events
- No support for `pods/attach` events exists
- Pod exec is handled via `PodExecOptions` in `pkg/kubernetes/event.go`

## Implementation Steps

### 1. Update Proto Definitions
**File:** `proto/storage/kube_event.proto`

```protobuf
// Add to Resource enum (around line 36):
PODS_ATTACH = 10;

// Add to ObjectArgs oneof (around line 54):
PodAttachArgs pod_attach_args = 7;

// Add message definition (after PodPortForwardArgs):
message PodAttachArgs {
  string container = 1;
  bool stdin = 2;
  bool stdout = 3;
  bool stderr = 4;
  bool tty = 5;
}
```

### 2. Update Event Conversion Logic
**File:** `pkg/kubernetes/event.go`

```go
// Add constant:
const (
    podExecOptionsKind        = "PodExecOptions"
    podPortForwardOptionsKind = "PodPortForwardOptions"
    podAttachOptionsKind      = "PodAttachOptions"  // NEW
)

// Update AdmissionRequestToKubeEventObj switch statement:
func AdmissionRequestToKubeEventObj(req *admission.AdmissionRequest) (*storage.KubernetesEvent, error) {
    switch req.Kind.Kind {
    case podExecOptionsKind:
        return podExecEvent(req)
    case podPortForwardOptionsKind:
        return podPortForwardEvent(req)
    case podAttachOptionsKind:  // NEW
        return podAttachEvent(req)
    default:
        return nil, ErrUnsupportedRequestKind.CausedByf("%q", req.Kind)
    }
}

// Add new function:
func podAttachEvent(req *admission.AdmissionRequest) (*storage.KubernetesEvent, error) {
    apiVerb, supported := supportedAPIVerbs[req.Operation]
    if !supported {
        return nil, ErrUnsupportedAPIVerb.CausedByf("%q", req.Operation)
    }

    var obj core.PodAttachOptions
    if _, _, err := universalDeserializer.Decode(req.Object.Raw, nil, &obj); err != nil {
        return nil, err
    }

    return &storage.KubernetesEvent{
        Id:      string(req.UID),
        ApiVerb: apiVerb,
        Object: &storage.KubernetesEvent_Object{
            Name:      req.Name,
            Resource:  storage.KubernetesEvent_Object_PODS_ATTACH,
            Namespace: req.Namespace,
        },
        ObjectArgs: &storage.KubernetesEvent_PodAttachArgs_{
            PodAttachArgs: &storage.KubernetesEvent_PodAttachArgs{
                Container: obj.Container,
                Stdin:     obj.Stdin,
                Stdout:    obj.Stdout,
                Stderr:    obj.Stderr,
                TTY:       obj.TTY,
            },
        },
        User: &storage.KubernetesEvent_User{
            Username: req.UserInfo.Username,
            Groups:   req.UserInfo.Groups,
        },
    }, nil
}
```

### 3. Update Webhook Configuration
**File:** `image/templates/helm/stackrox-secured-cluster/templates/admission-controller.yaml`

```yaml
- name: k8sevents.stackrox.io
  rules:
    - apiGroups: ['*']
      apiVersions: ['*']
      operations: [CONNECT]
      resources: [pods, pods/exec, pods/portforward, pods/attach]  # Add pods/attach
```

### 4. Create Default Pod Attach Policy
**File:** `pkg/defaults/policies/files/pod_attach.json`

```json
{
  "id": "8494c6f0-ade0-4a1a-b911-a4b901e3f1c5",
  "name": "Kubernetes Actions: Attach to Pod",
  "description": "Detects when users attach to a pod which can be used for debugging but may also be used by attackers to gain access to running containers",
  "rationale": "Pod attach sessions may be used by attackers to gain interactive access to running containers, potentially leading to data access, privilege escalation, or lateral movement within the cluster",
  "remediation": "Restrict pod attach access to only necessary users and service accounts. Use Kubernetes RBAC to limit who can perform pod attach operations. Monitor and audit all pod attach events.",
  "disabled": false,
  "categories": ["Kubernetes"],
  "lifecycleStages": ["RUNTIME"],
  "severity": "HIGH_SEVERITY",
  "policyVersion": "1.1",
  "policySections": [{
    "policyGroups": [{
      "fieldName": "Kubernetes Resource",
      "booleanOperator": "OR",
      "negate": false,
      "values": [{
        "value": "PODS_ATTACH"
      }]
    }]
  }],
  "mitreAttackVectors": [{
    "tactic": "TA0002",
    "techniques": ["T1609"]
  }],
  "criteriaLocked": true,
  "mitreVectorsLocked": true,
  "isDefault": true
}
```

### 5. Update Violation Message Printer
**File:** `pkg/booleanpolicy/violationmessages/printer/kube_event.go`

```go
// In GetViolationMessage function, add case:
case storage.KubernetesEvent_Object_PODS_ATTACH:
    return podAttachViolationMsg(event)

// Add new function:
func podAttachViolationMsg(event *storage.KubernetesEvent) string {
    podAttachArgs := event.GetPodAttachArgs()
    if podAttachArgs == nil {
        return unknownViolationMessage
    }
    
    var msg strings.Builder
    msg.WriteString("Pod ")
    msg.WriteString(quote(event.GetObject().GetName()))
    
    if podAttachArgs.GetContainer() != "" {
        msg.WriteString(" container ")
        msg.WriteString(quote(podAttachArgs.GetContainer()))
    }
    
    msg.WriteString(" attach session initiated")
    
    var options []string
    if podAttachArgs.GetStdin() {
        options = append(options, "stdin")
    }
    if podAttachArgs.GetStdout() {
        options = append(options, "stdout")
    }
    if podAttachArgs.GetStderr() {
        options = append(options, "stderr")
    }
    if podAttachArgs.GetTTY() {
        options = append(options, "tty")
    }
    
    if len(options) > 0 {
        msg.WriteString(" with ")
        msg.WriteString(strings.Join(options, ", "))
    }
    
    return msg.String()
}
```

### 6. Add Test Data
**File:** `sensor/admission-control/service/testdata/review_requests/pod_attach_event_review.json`

```json
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "12345678-1234-1234-1234-123456789012",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "PodAttachOptions"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods",
      "subresource": "attach"
    },
    "requestKind": {
      "group": "",
      "version": "v1",
      "kind": "PodAttachOptions"
    },
    "requestResource": {
      "group": "",
      "version": "v1",
      "resource": "pods",
      "subresource": "attach"
    },
    "name": "nginx-deployment-66b6c48dd5-dhppc",
    "namespace": "default",
    "operation": "CONNECT",
    "userInfo": {
      "username": "test-user",
      "groups": ["system:authenticated"]
    },
    "object": {
      "kind": "PodAttachOptions",
      "apiVersion": "v1",
      "stdin": true,
      "stdout": true,
      "stderr": true,
      "tty": true,
      "container": "nginx"
    },
    "oldObject": null,
    "dryRun": false,
    "options": {
      "kind": "UpdateOptions",
      "apiVersion": "meta.k8s.io/v1"
    }
  }
}
```

### 7. Update Policy List
**File:** `pkg/defaults/policies/policies.go`

Add the new policy to the embedded policies list to ensure it's loaded on startup.

### 8. Testing Requirements

#### Unit Tests
- Test `podAttachEvent()` function with various PodAttachOptions configurations
- Test violation message generation for different attach scenarios
- Test proto serialization/deserialization of PodAttachArgs

#### Integration Tests
- Test admission webhook receives and processes pod attach requests
- Test policy evaluation triggers on pod attach events
- Test alert generation and storage

#### E2E Tests
- Deploy a pod and attempt to attach to it
- Verify alert is generated with correct details
- Test with different attach options (stdin, stdout, tty, etc.)
- Test with different users and namespaces

## Migration Considerations
- This change requires updating the ValidatingWebhookConfiguration
- Existing deployments will need to update their webhook configuration
- The new policy will be automatically deployed as a default policy

## Security Considerations
- Pod attach is a sensitive operation that provides interactive access
- Should be monitored and restricted similar to pod exec
- Consider implementing additional controls for production environments
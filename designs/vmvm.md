# Product Requirements Document: Vulnerability Reporting for Virtual Machines in ACS (ROX-27051)

Version: 1.0
Date: July 9, 2025

**Project Name:** Showing Vulnerabilities for Virtual Machines in ACS (ROX-27051)

Authors:

* Gemini (based on provided documents)
* Kyle Lape

## 1. Introduction

This document outlines the product requirements for integrating vulnerability
reporting for Virtual Machines (VMs) into Red Hat Advanced Cluster Security
(ACS). The primary goal is to enable the collection and display of package data
and associated vulnerabilities (CVEs) from RHEL-based VMs running on OpenShift
Virtualization. This functionality aims to provide security teams with a
unified console experience for managing both containerized workloads and
virtual machines.

## 2. Problem Statement

Security teams managing diverse workloads, including both containers and
virtual machines, require a single, centralized console for security
management. Specifically, there is a recognized need to collect and report
vulnerability data (CVEs) from RHEL-based Virtual Machines running on OpenShift
Virtualization. The existing ACS Collector is "blind" to the internal processes
and network traffic of VMs due to their separate kernels and networking
configurations (e.g., non-Pod networking like Multus or SR-IOV). This lack of
visibility prevents ACS from performing crucial security functions like
vulnerability scanning, compliance checks, and runtime monitoring for VMs,
which customers currently expect.

## 3. Goals

**Primary Goal:** Add VM vulnerability scanning support to ACS for VMs running on Red Hat OpenShift Virtualization platform.

### Key Outcomes

* Enable collection of package data from RHEL-based VMs.
* Utilize Scanner V4 to identify vulnerabilities based on collected package data.
* Display a list of vulnerabilities (CVEs) for RHEL-based VMs in ACS.
* Provide a robust and secure mechanism for transmitting data from the VM agent to Sensor.

## 4. Scope

### In Scope for MVP (4.9 Release)

* Detecting Virtual Machines running on OpenShift Virtualization.
* Collecting package data (RPM lists) from RHEL-based VMs via an agent.
* Transmitting collected package data from the VM agent to an Aggregator.
* Matching collected component data to vulnerabilities using Scanner.
* Persisting VM inventory and vulnerability data in Central.
* Designing and implementing a new API to list VMs, get components, and get vulnerabilities.
* Designing and implementing UI to display VM vulnerability information.
* Establishing End-to-End (E2E) testing capabilities for VM integration.
* Populating VM inventory by reading KubeVirt Custom Resources (CRs).
* Determining installation and configuration requirements for VM integration.
* Documenting and facilitating developer environments for VM development.

### Out of Scope for MVP (4.9 Release)

* Policy evaluation and enforcement for VMs.
* Remediation of vulnerabilities.
* Collecting additional VM facts beyond what's needed for initial CVE matching.
* Runtime monitoring for VMs.
* Full network activity visibility for VMs not using passt networking type (e.g., Multus secondary interface, SRIOV).
* Integration with third-party vulnerability scanning tools (e.g., CrowdStrike) for the initial MVP.
* Windows VMs

## 5. Stakeholders

* **Product Management:** Shubha Badve
* **Engineering Lead:** Kyle Lape (Data Collection, API, Persistence, Matching, Dev Environments, Aggregator)
* **UX Design:** Zhenpeng Chen (UX Lead)
* **UI Development:** Brad Rogers
* **Scanner Team:** (Input for data collection and matching)
* **Core Workflows Team:** (API, Persistence) 
* **Maple Team:** (Data Collection) 
* **SensEco Team:** (Potential owner of Data Collection/Aggregator)
* **Customers:** (Primary beneficiaries of vulnerability reporting) 

## 6. User Stories / Features

* As a security team member, I want to see a list of virtual machines running on OpenShift Virtualization in ACS, so I can understand my VM inventory. 
* As a security team member, I want to see a list of vulnerabilities (CVEs) for each virtual machine, so I can assess their security posture. 
* As a security team member, I want ACS to continuously monitor VMs for vulnerabilities at runtime, so I can stay updated on their security status. 
* As a security team member, I want to see where a detected CVE in a VM is fixed in RHEL, so I can prioritize remediation efforts.

## 7. Functional Requirements

### 7.1. VM Data Collection (ROX-27667)

* The system SHALL collect package data (RPM lists) from RHEL-based Virtual Machines.
* The system SHALL provide a common interface (HTTP endpoint, Protobuf messages) for receiving VM data from various sources.
* The system SHOULD ship the VM agent as a container image.
* The system SHOULD allow customers to run the agent using Podman, with consideration for Podman Quadlet as a daemon.
* The VM agent SHALL push data to ACS using the defined standard interface.
* The initial scope of data collection SHALL be limited to information necessary for CVE matching by ACS Scanner (e.g., RPM listing, possibly DNF repo info).
* The data collection mechanism SHALL be designed to be expandable for future data types (e.g., process listings).
* The solution SHOULD consider supporting non-RHEL hosts, but this may be deferred if time constraints arise.

### 7.2. Aggregator & Data Transmission (ROX-29576)

* The team SHALL implement an "Aggregator" component to receive data from VM data sources.
* The Aggregator SHALL relay received VM data to Central using Protobuf messages over a gRPC connection.
* The team SHALL determine whether the Aggregator is an extension of Sensor or a separate deployment.
* The team SHALL decide on the communication method between VM Agents and the Aggregator (Cluster Networking vs. VSOCK \+ Compliance).

### 7.3. API for VM Data (ROX-27664)

* The system SHALL expose a REST API to retrieve a list of virtual machines.
* The system SHALL expose a REST API to retrieve details for a specific virtual machine, including its component list and vulnerabilities.
* The API SHALL allow virtual machines to be added via Sensor messages.
* The API SHOULD allow retrieval of "facts" about VMs (e.g., OS Release, kernel version, hostname, network addresses, creation date).

### 7.4. Data Persistence (ROX-27663)

* The system SHALL persist VM vulnerability data into Central.
* The system SHALL define a new data model for VMs, likely including separate tables for VMs, components (packages installed), and identified vulnerabilities.
* The data model SHOULD avoid GraphQL if possible.

### 7.5. Vulnerability Matching (ROX-27668)

* The system SHALL utilize Scanner V4 to match component lists from VMs to vulnerabilities.
* The matching process SHALL follow a pattern similar to node scanning.
* The process SHALL include requesting data collection, persisting package data in DB, formatting data for Scanner V4's matcher service (IndexReport), making the request to Matcher, and persisting/returning results.
* The feature's "tech preview" status is dependent on the resolution of kernel vulnerability advisories (RHELWF-12660).

### 7.6. VM Inventory (ROX-29591)

* The system SHALL populate VM inventory by reading KubeVirt VirtualMachine and VirtualMachineInstance Custom Resources (CRs).
* The system SHALL extract relevant fields from these CRs (initial list TBD).
* The extracted VM information SHALL be sent to Central for persistence.
* The collected CR data will be used to link various sources of VM data (e.g., VSOCK ID, MAC address, Pod name).

## 8. Non-Functional Requirements

### Security

* Secure communication between VM agent and Sensor is paramount.
* Authentication mechanism for VM Agents will be required if direct communication is chosen.
* Leverage existing mTLS authentication if Compliance is used as a relay.
* Reduce attack surface for VM agent by avoiding direct exposure to broader cluster network (favors VSOCK).

### Performance

* Low-latency communication channel between VM and host (favors VSOCK).
* Efficient protocol for data transmission (e.g., gRPC, HTTP/2 with TLS).

### Scalability

* The solution should scale to handle numerous VMs and their associated data.

### Reliability

* Robust mechanism for data transmission to Sensor.
* Ensure proper error handling and buffering (Compliance's potential role).

### Maintainability

* Minimize burden of extending existing components where possible (e.g., Compliance).

### Usability

* Integration into the ACS Console for a single pane of glass experience.

## 9. Open Questions / Future Considerations

* **VSOCK Availability:** Confirm availability and stability of VSOCK support in OpenShift Virtualization for the target release. Users will need to ensure autoattachVSOCK: true is enabled in their VM configurations.
* **Compliance Scope:** Define exact responsibilities of Compliance beyond data relay (e.g., pre-processing, buffering, error handling).
* **Network Segmentation:** If Cluster Networking is chosen, define specific network segmentation requirements.
* **Kernel Vulnerabilities:** Detailed plan for addressing kernel vulnerabilities and their impact on the "tech preview" status.
* **Agent Data Collection:** What exact information (beyond RPMs and DNF repos) is needed for comprehensive vulnerability matching by Scanner?
* **Agent Authentication:** How will VM data sources authenticate with ACS?
* **VM Identity:** How will Compliance reliably match agents with VM identity from the VSOCK connection? 
* **Non-RHEL Support:** Concrete plan and timeline for supporting non-RHEL distributions beyond 4.9.

## 10. Release Strategy

* **Target Release:** ACS 4.9.0
* **Feature Status:** Tech Preview, especially concerning kernel vulnerability matching.

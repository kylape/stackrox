# Vulnerability Management for Virtual Machine Status Update

**Author**:

* Gemini
* Kyle Lape

The "Vulnerability Reporting in ACS for Virtual Machines running on OpenShift
Virtualization platform (Tech Preview)" project (ROX-27051) remains in the
"Refinement" phase. The project's core objective is to collect and display CVEs
for RHEL-based VMs on OpenShift Virtualization within the ACS system, aiming to
provide a unified security console experience for both VM and container
workloads.

## **Core Development and Data Flow**

Significant progress is underway in establishing the fundamental data
collection and processing pipeline. A primary focus is on **Data Collection**
(ROX-27667), where the team is actively designing a common interface for ACS to
receive VM data from various sources. The current strategy involves customers
downloading and installing a dedicated VM agent. This agent, likely
distributed as a container image and executable via Podman, is initially
designed to gather package data essential for CVE matching. A Rust-based
proof-of-concept agent has already demonstrated successful component list
uploads using defined interfaces.

The collected data will then be pushed to a new component, the **Aggregator**
(ROX-29576), which is currently in the "Planning" stage. The Aggregator's role
is to receive this data and relay it to Central via Protobuf messages over a
gRPC connection. A key design decision currently under evaluation is whether
this Aggregator will be an extension of the existing Sensor component or a
standalone deployment, with a proof-of-concept for the VSOCK communication
alternative currently in progress to inform this choice6666. To support the
overall data pipeline, the project also includes tasks for defining the
**Persistence** (ROX-27663) data model in Central for VM vulnerability data,
likely requiring new tables for VMs, components, and vulnerabilities7. Finally,

**Matching Vulnerabilities** (ROX-27668) will leverage Scanner V4 to process
the collected component lists against known vulnerabilities, aiming for
consistency across the product8.

## **User Experience and Supporting Infrastructure**

Beyond the core data flow, critical work is in progress to integrate VM
vulnerability management into the user experience and ensure a smooth
development process. The

**API** (ROX-27664) for retrieving VM information and vulnerabilities is in
development, with a prototype API and ephemeral backend currently being
implemented to allow early iteration9. This API's design is dependent on the
ongoing

**UX Design** (HPUX-364) work, which aims to translate user needs and research
findings into a concrete, user-centric design10. The

**UI** (ROX-27666) implementation will then follow the established UX design11.

To ensure a robust system, the project includes efforts to **Populate VM
Inventory by Reading KubeVirt CRs** (ROX-29591), which involves adding a
Kubernetes informer to watch KubeVirt Custom Resources and extract initial VM
facts.

**E2E Testing** (ROX-29577) framework development is also planned to validate
the new features, requiring the deployment of VMs12. Additionally,
considerations for

**Installation and Configuration** (ROX-29580) of the VM integration feature,
including a basic enable/disable option, are on the roadmap. To support the
development team, a task to **Document and Facilitate Dev Environments for VM
Development** (ROX-29579) is also in progress.

## **Strategic Decisions and Future Outlook**

A strategic decision was made to prioritize an in-house VM agent for data
collection over direct integration with third-party tools like CrowdStrike for
the initial MVP. While a spike into **CrowdStrike Integration** (ROX-28301)
successfully demonstrated its API capabilities for fetching host
vulnerabilities and component lists, this approach is not in immediate plans
for the 4.9 release due to complexities in host matching and credential
management. The focus remains on building ACS's native capabilities first. It
is noted that the overall feature might be considered "tech preview" unless a
pending fix for kernel vulnerability advisories (RHELWF-12660) is implemented
in time.

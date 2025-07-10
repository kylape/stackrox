# Design Documents

This directory contains design documents and implementation plans for various projects and improvements to StackRox.

## Active Designs

### Policy Engine Evolution

- [Policy Engine Architecture Analysis](policy-engine-architecture.md) - Deep analysis of StackRox's policy engine structure, criteria system, and context model
- [Universal Resource Policy Engine](universal-resource-policy-engine.md) - Transform StackRox from deployment-centric to resource-agnostic policy evaluation, enabling policies on any Kubernetes resource (ConfigMaps, Services, Ingresses, etc.)
- [PolicyReport API Integration](policyreport-integration.md) - Bidirectional integration with Kubernetes PolicyReport API for interoperability with other policy engines (Kyverno, Falco, OPA)

### Performance Improvements

- [Scanner V4 COPY FROM Optimization](scanner-v4-copy-from-optimization.md) - Performance improvement for vulnerability database loading using PostgreSQL COPY FROM instead of row-by-row inserts. Target: 5-10x performance improvement.

## Design Document Template

When creating new design documents, consider including:
- Overview and problem statement
- Goals and non-goals
- Technical approach
- Implementation phases
- Success criteria
- Alternatives considered
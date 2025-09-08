# Roadmap

## Overview

At Ratify, our mission is to safeguard the container supply chain by ratifying trustworthy and compliant artifacts. We achieve this through a robust and pluggable verification engine that includes built-in verifiers. These verifiers can be customized to validate supply chain metadata associated with artifacts, covering essential aspects such as signatures and attestations (including vulnerability reports, SBOM, provenance data, and VEX documents). As the landscape of supply chain security evolves, we actively develop new verifiers, which can be seamlessly integrated into our verification engine. Additionally, if you have a specific use case, you can create your own verifier following our comprehensive guidance. Each verifier will generate detailed verification reports, which can be consumed by various policy controllers to enforce policies.

Ratify is designed to address several critical scenarios. It seamlessly integrates with OPA Gatekeeper, acting as the Kubernetes policy controller that shields your cluster from untrustworthy and non-compliant container images. As an external data provider for Gatekeeper, Ratify delivers artifact verification results that are in alignment with defined policies. Additionally, Ratify enhances security at the Kubernetes node level by extending its capabilities to container runtime through its plugin interface, which allows for detailed policy evaluations based on artifact verification outcomes. Lastly, incorporating Ratify into your CI/CD pipeline ensures the trustworthiness and compliance of container images prior to their usage.

This document presents the roadmap of Ratify that translates our strategy into practical steps.

## Milestones

The Ratify roadmap is divided into milestones, each with a set of features (high level) and timeline. The milestones marked as `Tentative` are subject to change based on the project’s priorities and the community’s feedback. We will prioritize releases for security or urgent fixes, so the roadmap may be adjusted and new features may be postponed to the next milestone. Any dates and features listed below in a given milestone are subject to change. See the [GitHub milestones](https://github.com/ratify-project/ratify/milestones?state=open) for the most up-to-date issues and their status. We are targeting to release a new Ratify version every 3 or 4 months.

### v1.0

**Status**: Completed

**Released date**: Sep 27, 2023

**Release link**: [v1.0.0 Release Notes](https://github.com/ratify-project/ratify/releases/tag/v1.0.0)

**Major features**

- Ratify as an external Data Provider for Gatekeeper
- Plugin framework for extensibility
- Policies for Notary Project signatures verification at admission control in kubernetes
- Policies for Cosign keyless verification at admission control in kubernetes
- High Availability support in Kubernetes (Experimental)

### v1.1

**Status**: Completed

**Release date**: Dec 12, 2023

**Release link**: [v1.1.0 Release Notes](https://github.com/ratify-project/ratify/releases/tag/v1.1.0)

**Major features**

- Policies for assessing vulnerability reports at admission control in kubernetes
- Policies for assessing software license at admission control in kubernetes
- New diagnostic logs

### v1.2

**Status**: Completed

**Target date**: May 31, 2024

**Release link**: [v1.2.0 Release Notes](https://github.com/ratify-project/ratify/releases/tag/v1.2.0)

**major features**

- Kubernetes multi-tenancy support (Namespace-specific policies)
- OCI v1.1 compliance
- Cosign signatures verification using keys in AKV

See details in [GitHub milestone v1.2.0](https://github.com/ratify-project/ratify/issues?q=is%3Aopen+is%3Aissue+milestone%3Av1.2.0).

### v1.3

**Status**: Completed

**Target date**: Sep 16, 2024

**Release link**: [v1.3.0 Release Notes](https://github.com/ratify-project/ratify/releases/tag/v1.3.0)

**Major features**

- Support of validating Notary Project signatures with timestamping
- Support of periodic retrieval of keys and certificates stored in a Key Management System
- Introducing trust policy configuration for Cosign keyless verification
- Error logs improvements for artifact verification

See details in [GitHub milestone v1.3.0](https://github.com/ratify-project/ratify/issues?q=is%3Aopen+is%3Aissue+milestone%3Av1.3.0).

### v1.4

**Status**: Completed

**Target date**: Nov 30, 2024

**Major features**

- Enable revocation checking using CRL (Certificate Revocation List) for Notary Project signatures
- Add Trusted Signing as a Key Management Provider
- Support retaining multiple previous versions of certificates/keys in Key Management Provider
- Artifact filtering based on annotations

See details in [GitHub milestone v1.4.0](https://github.com/ratify-project/ratify/issues?q=is%3Aopen+is%3Aissue+milestone%3Av1.4.0).

### v2.0.0-alpha.1
**Status**: In procoess  
**Target date**: May 15, 2025  
**Major features**

- Decouple Ratify core functionalities into a separate library([ratify-go](https://github.com/ratify-project/ratify-go)), which could be easily integrated into different projects.
- Design new interfaces for `Verifier`, `Store`, and `PolicyEnforcer` to make them more extensible and flexible.
- Support `notation-verifier` under [ratify-verifier-go](https://github.com/ratify-project/ratify-verifier-go) in terms of the new `Verifier` interface.
- Support Registry Store and local OCI layout in terms of the new `Store` interface.
- Support config based policy in terms of the new `PolicyEnforcer` interface.
- Create new external data provider for Gatekeeper based on the new framework.

#### Note
- V2 milestones will cover a few sub-projects including libraries, CLI tools and external data provider.

### v2.0.0-alpha.2
**Status**: Tentative  
**Target date**: June 30, 2025  
**Major features**
- Support authentication with remote OCI registries.
- Support key/certificate management for verifiers.

### v2.0.0-beta.1
**Status**: Tentative  
**Target date**: TBD  
**Major features**
- Support cache management, considering file system, in-memory and remote cache.
- Improve performance of executor by supporting parallel execution of verifiers.

### v2.0.0-beta.2
**Status**: Tentative  
**Target date**: TBD  
**Major features**
- Support more built-in verifiers to verify different artifact types, including SBOM verifier, vulnerability report verifier, and schema validator.
- Support CRDs for K8s users to configure Ratify add-on natively.
- Support multi-tenancy.


### v2.0.0-beta.3
**Status**: Tentative  
**Target date**: TBD  
**Major features**
- Build new ratify CLI tool with the basic functionalities.
- Support instrumentation and telemetry by exposing pod's metrics to monitoring tools.

### v2.0.0-rc.x
**Status**: Tentative  
**Target date**: TBD  
**Major features**
- Support multiple cloud providers in v1, including Azure, AWS, and Alibaba.
- Add any missing features from v1 to v2.
- Fix any bugs or issues found in the previous versions.

### v2.0.0
**Status**: Tentative  
**Target date**: TBD  
**Major features**
- Make features listed above stable and production-ready. 
- Publish user documentation for v2.0.0.

### v2.x
**Status**: Tentative  
**Target date**: TBD  
**Major features**
- Attestations support
- Kubernetes multi-tenancy support - Verifying Common images across namespaces
- Use Ratify at container runtime
- Use Ratify in CI/CD pipelines
- Support CEL as additional policy language
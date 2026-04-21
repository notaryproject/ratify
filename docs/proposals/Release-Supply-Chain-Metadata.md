# Supply Chain Metadata for Ratify Assets

Ratify currently publishes multiple forms of release assets both for production and development uses. Currently, these assets are not published with accompanying supply chain metadata including signatures, SBOMs, and provenance. Shipping each of these forms of metadata with all binaries and container images produced by Ratify will provide consumers a verifiable way to guarantee integrity of Ratify assets. Furthermore, this will improve Ratify's OSSF scorecard. In general, Ratify will prioritize addressing HIGH, MEDIUM risks surfaced by OSSF scorecard. Learn more about the OSSF checks performed [here](https://github.com/ossf/scorecard/blob/main/docs/checks.md)

## What does Ratify currently publish?

Ratify publishes two types: release and development. Release assets accompany official Ratify Github releases. Development assets are published weekly (or adhoc as needed).

Each publish type includes the following group of assets:

* CRD container image to `ghcr.io/ratify-project`
* Base container image to `ghcr.io/ratify-project`
* Base + plugins container image to `ghcr.io/ratify-project`
* Ratify binaries as a single bundle per OS/arch which includes:
  * ratify binary
  * sbom-verifier plugin binary
  * vulernability-report verifier plugin binary
* `checksums.txt` which contains list of checksum for each binary bundle
* Helm chart
  * Release ONLY: published packaged helm chart to `ratify-project.github.io`
  * Dev ONLY: published packaged helm chart to `ghcr.io/ratify-project`
* Source code (zip + tar ball)

## Signatures

Ratify should support signing all container images and binaries with both Sigstore Cosign and Notary Project.

### Notary Project Image Signatures

Ratify can utilize Notary Project's install and sign github actions published.
Notation requires a KMS to store the signing certificate. There is no support for Github Encrypted Secrets for storing the certificate.

1. Configure Notation action to sign using certificate's associated key stored in AKV.
2. Sign CRD, base, plugin images

#### Certificate Lifecycle Management

Ratify will use a self-signed certificate stored in Azure Key Vault. This certificate is valid for 1 year. A new version is auto-generated after 9.5 months.
The notation signing action will be configured to always use the latest certificate version.

The verification certificate will be published in 2 different directories:

* Ratify website @ `ratify.dev/.well-known/pki-validation/...`
* Root of Ratify github repository @ `https://github.com/notaryproject/ratify/main/.well-known/pki-validation/...`

The verification steps in the security section of Ratify website will recommend downloading certificates from the ratify website.

The latest certificate can always be found at `ratify.dev/.well-known/pki-validation/ratify-verification.crt`. When a new version of the certificate is generated, the `./ratify-verification.crt` content MUST be updated to contain the new certificate. The previous version will be preserved as a separate file following convention: `./ratify-verification_<YYYYMMDD>.crt` where `<YYYYMMDD>` is the last date where that particular certificate version was valid. Ratify will NOT re-sign any dev release assets so older versions of certificates must be published so users can continue to validate those.

NOTE: certificate update operations will be a MANUAL process and maintainers must track certificate regeneration date and make updates accordingly as specified by convention above.

### Cosign Image Signatures

Ratify can utilize Cosign's installer github action to install cosign on the runner. There is no accompanying sign action so the CLI must be directly used. Cosign will be used to generate keyless signatures. Signature will be uploaded to the Sigstore public-good transparency log. Cosign will use Ratify's workflow OIDC identity for signing. This will guarantee that the trusted identity is the Ratify workflow that published the images.

1. Sign CRD, base, plugin images with cosign keyless

### Sign binaries

Notary Project is about to release support for blob signing which allows for all binaries to be signed using the same signing certificate used for container image signing. The public certificate can be appended to the release assets.

Cosign has support for binary signing and Ratify can leverage the built-in GoReleaser support to achieve this. The keyless support will automatically append the `.sig` files as well as `.pem` to use for verification to the release.

## SBOM

There are multiple tools for generating SBOMS such as Syft, Trivy, Microsoft SBOM tool, etc.

### Docker Buildx Attestations

Recently, Ratify added support for generating SBOM in-toto attestations via buildx. Buildx supports generating SBOM via Syft and attaching the attestation as an OCI Image part of the top level image index. Read more [here](https://ratify.dev/docs/next/reference/security#build-attestations).

Other OSS projects such as Gatekeeper publish attestations in a similar fashion. It's very simple to add such support making adoption more widespread.

These attestations produced via buildx adhere to a docker-specific standard for discoverability and verification.

Here's an example image index with an SBOM attestation:

```bash
$ docker buildx imagetools inspect ghcr.io/ratify-project/ratify:v1.3.0
Name:      ghcr.io/ratify-project/ratify:latest
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:f261f5076b8a1fd3f53cfbd10f647899d5875e4fcd40b1854598a18f580b422d
           
Manifests: 
  Name:        ghcr.io/ratify-project/ratify:v1.3.0@sha256:c99c9b5edfe005e0454c4160388a70520844d1856c1fcc3f8557532d6a034f32
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    linux/amd64
               
  Name:        ghcr.io/ratify-project/ratify:v1.3.0@sha256:f1b520af44d5e22b9b8702cbbcd651092df8672ed7822851266b17947c2a0962
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    linux/arm64
               
  Name:        ghcr.io/ratify-project/ratify:v1.3.0@sha256:6105d973c1c672379abfdb63486a0327d612c4fe67bb62e4d20cb910c0008aa9
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    linux/arm/v7
               
  Name:        ghcr.io/ratify-project/ratify:v1.3.0@sha256:836450813252daf7854b0aec1ccafe486bbb1352ec234b9adf105ddc24b0cb37
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    unknown/unknown
  Annotations: 
    vnd.docker.reference.digest: sha256:c99c9b5edfe005e0454c4160388a70520844d1856c1fcc3f8557532d6a034f32
    vnd.docker.reference.type:   attestation-manifest
               
  Name:        ghcr.io/ratify-project/ratify:v1.3.0@sha256:dcfa5faf20c916c9a41dd4636939594d8164f467ebb00d73570ae13cbcbf59ad
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    unknown/unknown
  Annotations: 
    vnd.docker.reference.digest: sha256:f1b520af44d5e22b9b8702cbbcd651092df8672ed7822851266b17947c2a0962
    vnd.docker.reference.type:   attestation-manifest
               
  Name:        ghcr.io/ratify-project/ratify:v1.3.0@sha256:c936d0ed115975ee7fc8196fbc5baff8100e92bff3d401c60df6396b9451e773
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    unknown/unknown
  Annotations: 
    vnd.docker.reference.type:   attestation-manifest
    vnd.docker.reference.digest: sha256:6105d973c1c672379abfdb63486a0327d612c4fe67bb62e4d20cb910c0008aa9
```

You can see the `attestation-manifest` reference-type.

To inspect, it's recommended to use docker's image inspection tool:

```shell
docker buildx imagetools inspect ghcr.io/ratify-project/ratify:v1.3.0 --format '{{ json .SBOM }}'
```

### Referrer Artifacts

Ratify should support generating SBOMs via an OSS tool and attach to the published container images via ORAS. This would be in line with the Ratify verification capabilities supported by the project.

### SBOM Binary Artifacts

Ratify should support publishing an SBOM in a common format like SPDX as a release artifact published next to each OS/arch specific binary.

GoRelease already support automatic SBOM generation and Ratify should update GoReleaser to take advantage of this support. Example [here](https://github.com/goreleaser/goreleaser-example-supply-chain/blob/d6d60f6320dbe97bda24b6351d9afa2035b3a23a/.goreleaser.yaml#L48). 

Ratify should also sign the SBOM using both notation and cosign.

## Provenance

### Docker Buildx Attestation

Please refer to SBOM section for format [details](#docker-buildx-attestations).

Ratify also added SLSA provenance attestation generation support as part of docker buildx. Similar to SBOM support, this adds a SLSA provenance attestation to the image index during image build.

### Referrer Artifacts (TBD)

As a future improvement, Ratify can look into attaching the SLSA build provenance metadata as a referrer artifact attached to the image. This might be in the form of a standalone artifact or packaged in an in-toto attestation.

### Provenance Binary Artifacts

Ratify should support publishing an provenance file for each OS/arch binary. The OSSF scorecard also recommends (and looks for) a provenance file in the release.

This would involve adding an extra workflow to generate the SLSA provenance for each output binary after GoReleaser has finished. Example [here](https://github.com/slsa-framework/slsa-github-generator/blob/main/.github/workflows/generator_generic_slsa3.yml).

Ratify should also sign each Provenance release file with notation and cosign.

## Proposed Dev Implementation

### Questions

1. Is it ok to use a self-signed certificate for Ratify's signing purposes? Yes, we are ok with this.
2. How do we handle certificate revocation scenarios? Is it Ratify's responsibility to resign all the release and dev images? Ratify will follow the supportability promise and only resign the **latest** minor release assets.
3. For binary signing, should Ratify only sign the `checksums.txt` or should Ratify sign all the assets individually? All assets should be signed.
4. Do we need to publish the same artifacts as referrers as well or is it sufficient to use docker buildx attestations? Ratify will consider this in the future as need arises. Right now, other OSS projects, like OPA Gatekeeper. have adopted buildx attestations.

### Stage 1

* Generate SBOM buildx attestations and publish for release and dev images
* Generate SLSA provenance buildx attestation and publish for release and dev images
* Add verification guidance to Ratify website under `Security` section

### Stage 2

* Container image signing using Notation for dev images and chart
  * Generate and store self signed certificate in Azure Key vault
  * AKV is in same subscription used for azure e2e tests
  * Publish verification public cert in the root of the Ratify repo
* Container image signing using Cosign for dev images
  * Keyless support only
  * Publish to rekor public good transparency log
* Signing support only introduced for dev images to test if workflow and approach is what Ratify should adopt long term
* Add SBOM generation to GoReleaser
* Add verification guidance to Ratify website under `Security` section

### Future (TBD)

* Attach SBOMs to release and dev images using Syft (not as in-toto attestations)
* Add Provenance generation after GoReleaser
* Introduce binary signing using Notation and Cosign
* Attach SLSA provenance to release and dev images as referrers

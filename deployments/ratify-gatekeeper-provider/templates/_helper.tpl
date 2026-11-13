{{/*
Expand the name of the chart.
*/}}
{{- define "ratify.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ratify.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Check if the TLS certificates are provided by the user
*/}}
{{- define "ratify.tlsCertsProvided" -}}
{{- if and .Values.provider.tls.crt .Values.provider.tls.key .Values.provider.tls.caCert -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Check if cosign verifier is configured based on certificate identity fields or keys
*/}}
{{- define "ratify.cosignConfigured" -}}
{{- if or (and (or .Values.cosign.certificateIdentity .Values.cosign.certificateIdentityRegex) (or .Values.cosign.certificateOIDCIssuer .Values.cosign.certificateOIDCIssuerRegex)) .Values.cosign.keys -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Check if notation verifier is configured based on certificates
*/}}
{{- define "ratify.notationConfigured" -}}
{{- if .Values.notation.certs -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Returns "true" when any notation certificate is provided by files.
*/}}
{{- define "ratify.notationCertsProvidedByFiles" -}}
{{- $enabled := false -}}
{{- range .Values.notation.certs -}}
{{- if eq (default "" .provider) "files" -}}
{{- $enabled = true -}}
{{- end -}}
{{- end -}}
{{- $enabled -}}
{{- end -}}

{{/*
Returns "true" when any notation certificate is fetched from Azure Key Vault.
*/}}
{{- define "ratify.akvCertsProvided" -}}
{{- $enabled := false -}}
{{- range .Values.notation.certs -}}
{{- if eq (default "" .provider) "azurekeyvault" -}}
{{- $enabled = true -}}
{{- end -}}
{{- end -}}
{{- $enabled -}}
{{- end -}}

{{/*
Notation trust store types, in the order they are rendered. Each
notation.certs entry is loaded into the trust store of its type, which
defaults to "ca".
*/}}
{{- define "ratify.notationTrustStoreTypes" -}}
ca tsa signingAuthority
{{- end -}}

{{/*
Returns the trust store type of a notation.certs entry. It fails on a type
that notation does not support.
*/}}
{{- define "ratify.notationCertType" -}}
{{- $type := default "ca" .type -}}
{{- if not (has $type (splitList " " (include "ratify.notationTrustStoreTypes" .))) -}}
{{- fail (printf "Unsupported notation certificate type: %s. Supported types are ca, tsa and signingAuthority" $type) -}}
{{- end -}}
{{- $type -}}
{{- end -}}

{{/*
Returns the name of the volume that holds the notation certificates provided
by files for the given trust store type. The "ca" name is kept unchanged from
earlier chart versions.
*/}}
{{- define "ratify.notationCertsVolumeName" -}}
{{- if eq . "ca" -}}
notation-certs
{{- else -}}
{{- printf "notation-%s-certs" (lower .) -}}
{{- end -}}
{{- end -}}

{{/*
Returns the directory that the notation certificates provided by files for the
given trust store type are mounted to. The "ca" directory is kept unchanged from
earlier chart versions.
*/}}
{{- define "ratify.notationCertsDir" -}}
{{- if eq . "ca" -}}
/usr/local/notation/certs
{{- else -}}
{{- printf "/usr/local/notation/%s-certs" (lower .) -}}
{{- end -}}
{{- end -}}

{{/*
Returns the space-separated keys of the notation certificates Secret that hold
the certificates provided by files for the given trust store type. It takes a
list of the root context and the trust store type.
*/}}
{{- define "ratify.notationCertFileKeys" -}}
{{- $root := index . 0 -}}
{{- $certType := index . 1 -}}
{{- $keys := list -}}
{{- range $index, $cert := $root.Values.notation.certs -}}
{{- if and (eq (default "" $cert.provider) "files") (eq (include "ratify.notationCertType" $cert) $certType) -}}
{{- $keys = append $keys (printf "ratify%d.crt" $index) -}}
{{- end -}}
{{- end -}}
{{- join " " $keys -}}
{{- end -}}

{{/*
Returns "true" when the provider authenticates to Azure: a store uses the azure
credential provider, or the notation certificates or cosign keys are fetched
from Azure Key Vault. When enabled, the pod is labeled with
azure.workload.identity/use so the Azure workload identity webhook injects the
federated token configuration.
*/}}
{{- define "ratify.azureWorkloadIdentityEnabled" -}}
{{- $enabled := eq (include "ratify.akvCertsProvided" .) "true" -}}
{{- if and .Values.cosign.keys (eq (default "" .Values.cosign.keys.provider) "azurekeyvault") -}}
{{- $enabled = true -}}
{{- end -}}
{{- range .Values.stores -}}
{{- if and .credential (eq (default "" .credential.provider) "azure") -}}
{{- $enabled = true -}}
{{- end -}}
{{- end -}}
{{- $enabled -}}
{{- end -}}

{{/*
Returns "true" when any store uses the azure credential provider with Kubernetes
identity binding enabled. When enabled, the pod is annotated with
azure.workload.identity/use-identity-binding so the AKS workload-identity webhook
injects the identity binding token endpoint configuration.
*/}}
{{- define "ratify.identityBindingEnabled" -}}
{{- $enabled := false -}}
{{- range .Values.stores -}}
{{- if and .credential (eq (default "" .credential.provider) "azure") .credential.identityBinding -}}
{{- if .credential.identityBinding.enabled -}}
{{- $enabled = true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $enabled -}}
{{- end -}}

{{/*
Choose the certificate/key pair to enable TLS for HTTP server
*/}}
{{- define "ratify.tlsSecret" -}}
{{- if eq (include "ratify.tlsCertsProvided" .) "true" }}
tls.crt: {{ .Values.provider.tls.crt | b64enc | quote }}  
tls.key: {{ .Values.provider.tls.key | b64enc | quote }}
ca.crt: {{ .Values.provider.tls.caCert | b64enc | quote }}
{{- end }}
{{- end }}

{{/*
Generate the name of the TLS secret to use
*/}}
{{- define "ratify.tlsSecretName" -}}
{{- printf "%s-tls" (include "ratify.fullname" .) -}}
{{- end -}}

{{/*
Choose the caBundle field for External Data Provider
*/}}
{{- define "ratify.providerCabundle" -}}
{{- $tlsSecretName := (include "ratify.tlsSecretName" .) -}}
{{- if eq (include "ratify.tlsCertsProvided" .) "true" }}
caBundle: {{ .Values.provider.tls.caCert | b64enc | replace "\n" "" }}
{{- else if (lookup "v1" "Secret" .Release.Namespace $tlsSecretName).data }}
caBundle: {{ index (lookup "v1" "Secret" .Release.Namespace $tlsSecretName).data "ca.crt" | replace "\n" "" }}
{{- else }}
{{- $ca := genCA "/O=Ratify/CN=Ratify Root CA" 365 -}}
caBundle: {{ $ca.Cert | b64enc | replace "\n" "" }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ratify.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ratify.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ratify.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ratify.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "ratify.labels" -}}
helm.sh/chart: {{ include "ratify.chart" . }}
{{ include "ratify.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ratify.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Set the namespace exclusions for Assign
*/}}
{{- define "ratify.assignExcludedNamespaces" -}}
{{- $gkNamespace := default "gatekeeper-system" .Values.gatekeeper.namespace -}}
- {{ $gkNamespace | quote}}
- "kube-system"
{{- if and (ne .Release.Namespace $gkNamespace) (ne .Release.Namespace "kube-system") }}
- {{ .Release.Namespace | quote}}
{{- end }}
{{- range .Values.provider.mutationExcludedNamespaces }}
- {{ . | quote }}
{{- end }}
{{- end }}


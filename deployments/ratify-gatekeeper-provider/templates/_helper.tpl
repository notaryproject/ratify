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
Check if notation certificates are provided by files
*/}}
{{- define "ratify.notationCertsProvidedByFiles" -}}
{{- if and (eq (include "ratify.notationConfigured" .) "true") (eq (index .Values.notation.certs 0).provider "files") -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{/*
Check if AKV certificate are provided
*/}}
{{- define "ratify.akvCertsProvided" -}}
{{- if and (eq (include "ratify.notationConfigured" .) "true") (eq (index .Values.notation.certs 0).provider "azurekeyvault") -}}
true
{{- else -}}
false
{{- end -}}
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

{{/*
Render the Executor spec. It is used as the spec of the Executor resource and,
when the CRD manager is disabled, as the executor entry of the mounted
config.json, so both configuration paths stay in sync.
*/}}
{{- define "ratify.executorSpec" -}}
scopes:
  {{- if .Values.executor.scopes }}
  {{- toYaml .Values.executor.scopes | nindent 2 }}
  {{- else }}
  {{- fail "executor.scopes must not be empty" }}
  {{- end }}
concurrency: {{ .Values.executor.concurrency | default 3 }}
stores:
  {{- $root := . -}}
  {{- range .Values.stores }}
  - type: registry-store
    {{- if .scopes }}
    scopes:
      {{- toYaml .scopes | nindent 8 }}
    {{- end }}
    parameters:
      credential:
        provider: "{{ .credential.provider }}"
        {{- if eq .credential.provider "static" }}
        username: "{{ .credential.username }}"
        password: "{{ .credential.password }}"
        {{- end }}
        {{- if eq .credential.provider "azure" }}
        {{- if .credential.clientID }}
        clientID: "{{ .credential.clientID }}"
        {{- end }}
        {{- if .credential.tenantID }}
        tenantID: "{{ .credential.tenantID }}"
        {{- end }}
        {{- if and .credential.identityBinding .credential.identityBinding.enabled }}
        identityBinding:
          enabled: true
        {{- end }}
        {{- end }}
      {{- if .plainHttp }}
      {{- if or .caBase64 .caPem }}
      {{- fail (printf "store with scopes %v: plainHttp cannot be combined with caBase64/caPem (no TLS over plain HTTP)" .scopes) }}
      {{- end }}
      plainHttp: true
      {{- else }}
      {{- if .caPem }}
      caPem: {{ .caPem | quote }}
      {{- end }}
      {{- if .caBase64 }}
      caBase64: {{ .caBase64 | quote }}
      {{- end }}
      {{- end }}
      {{- if eq (include "ratify.cosignConfigured" $root) "true" }}
      allowCosignTag: true
      {{- end }}
  {{- end }}
verifiers:
  {{- if eq (include "ratify.cosignConfigured" .) "true" }}
  - name: cosign-1
    type: cosign
    parameters:
      trustPolicies:
        - {{- if .Values.cosign.scopes }}
          scopes:
            {{- toYaml .Values.cosign.scopes | nindent 12 }}
          {{- end }}
          certificateIdentity: "{{ .Values.cosign.certificateIdentity }}"
          certificateIdentityRegex: "{{ .Values.cosign.certificateIdentityRegex }}"
          certificateOIDCIssuer: "{{ .Values.cosign.certificateOIDCIssuer }}"
          certificateOIDCIssuerRegex: "{{ .Values.cosign.certificateOIDCIssuerRegex }}"
          ignoreTLog: {{ .Values.cosign.ignoreTLog }}
          {{- if not .Values.cosign.keys }}
          ignoreCTLog: {{ .Values.cosign.ignoreCTLog }}
          {{- end }}
          ignoreObserverTimestamps: {{ .Values.cosign.ignoreObserverTimestamps }}
          {{- if .Values.cosign.keys }}
          {{- if eq .Values.cosign.keys.provider "inline" }}
          {{- if .Values.cosign.keys.key }}
          keys:
            inline:
              keys: {{ .Values.cosign.keys.key | quote }}
          {{- end }}
          {{- else if eq .Values.cosign.keys.provider "azurekeyvault" }}
          keys:
            azurekeyvault:
              vaultURL: "{{ .Values.cosign.keys.vaultURL }}"
              {{- if .Values.cosign.keys.clientID }}
              clientID: "{{ .Values.cosign.keys.clientID }}"
              {{- end }}
              {{- if .Values.cosign.keys.tenantID }}
              tenantID: "{{ .Values.cosign.keys.tenantID }}"
              {{- end }}
              keys:
                {{- range .Values.cosign.keys.keys }}
                - name: "{{ .name }}"
                  {{- if .version }}
                  version: "{{ .version }}"
                  {{- end }}
                {{- end }}
          {{- end }}
          {{- end }}
  {{- end }}
  {{- if eq (include "ratify.notationConfigured" .) "true" }}
  - name: notation-1
    type: notation
    parameters:
      {{- if .Values.notation.scopes }}
      scopes:
        {{- toYaml .Values.notation.scopes | nindent 8 }}
      {{- end }}
      {{- if .Values.notation.trustedIdentities }}
      trustedIdentities:
        {{- toYaml .Values.notation.trustedIdentities | nindent 8 }}
      {{- end }}
      certificates:
        - type: "ca"
          {{- if eq (index .Values.notation.certs 0).provider "inline" }}
          inline:
            certs: {{ (index .Values.notation.certs 0).cert | quote }}
          {{- else if eq (index .Values.notation.certs 0).provider "files" }}
          files:
            - "/usr/local/notation/certs"
          {{- else if eq (index .Values.notation.certs 0).provider "azurekeyvault" }}
          azurekeyvault:
            vaultURL: "{{ (index .Values.notation.certs 0).vaultURL }}"
            clientID: "{{ (index .Values.notation.certs 0).clientID }}"
            tenantID: "{{ (index .Values.notation.certs 0).tenantID }}"
            certificates:
              {{- range $cert := (index .Values.notation.certs 0).certificates }}
              - name: "{{ $cert.name }}"
                version: "{{ $cert.version | default "" }}"
              {{- end }}
          {{- else }}
          {{- fail (printf "Unsupported notation certificate provider: %s" (index .Values.notation.certs 0).provider) }}
          {{- end }}
  {{- end }}
policyEnforcer:
  type: "threshold-policy"
  parameters:
    policy:
      threshold: 1
      rules:
        {{- if eq (include "ratify.notationConfigured" .) "true" }}
        - verifierName: "notation-1"
        {{- end }}
        {{- if eq (include "ratify.cosignConfigured" .) "true" }}
        - verifierName: "cosign-1"
        {{- end }}
{{- end }}

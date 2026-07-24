{{/*
Expand the name of the chart.
*/}}
{{- define "ratify.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}


{{- define "ratify.podLabels" -}}
{{- if .Values.podLabels }}
{{- toYaml .Values.podLabels }}
{{- end }}
{{- end }}

{{- define "ratify.podAnnotations" -}}
{{- if .Values.podAnnotations }}
{{- toYaml .Values.podAnnotations }}
{{- end }}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "ratify.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
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
Selector labels
*/}}
{{- define "ratify.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ratify.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "ratify.serviceAccountName" -}}
{{- if or .Values.azureWorkloadIdentity.clientId .Values.serviceAccount.create }}
{{- default (include "ratify.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Choose the Gatekeeper api version for Assign
*/}}
{{- define "ratify.assignGKVersion" -}}
{{- if semverCompare ">= 3.11.0" .Values.gatekeeper.version }}
apiVersion: mutations.gatekeeper.sh/v1
{{- else }}
apiVersion: mutations.gatekeeper.sh/v1beta1
{{- end }}
{{- end }}

{{/*
Choose the Gatekeeper api version for External Data Provider
*/}}
{{- define "ratify.providerGKVersion" -}}
{{- if semverCompare ">= 3.11.0" .Values.gatekeeper.version }}
apiVersion: externaldata.gatekeeper.sh/v1beta1
{{- else }}
apiVersion: externaldata.gatekeeper.sh/v1alpha1
{{- end }}
{{- end }}

{{/*
Check if the TLS certificates are provided by the user
*/}}
{{- define "ratify.tlsCertsProvided" -}}
{{- if and .Values.provider.tls.crt .Values.provider.tls.key .Values.provider.tls.cabundle .Values.provider.tls.caCert .Values.provider.tls.caKey -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

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
{{- $ca := genCA "/O=Ratify/CN=Ratify Root CA" 365 -}}
{{- $tlsSecretName := (include "ratify.tlsSecretName" .) -}}
{{- if eq (include "ratify.tlsCertsProvided" .) "true" }}
caBundle: {{ .Values.provider.tls.cabundle | quote }}
{{- else if (lookup "v1" "Secret" .Release.Namespace $tlsSecretName).data }}
caBundle: {{ index (lookup "v1" "Secret" .Release.Namespace $tlsSecretName).data "ca.crt" | replace "\n" "" }}
{{- else }}
caBundle: {{ $ca.Cert | b64enc | replace "\n" "" }}
{{- end }}
{{- end }}

{{/*
Choose the certificate/key pair to enable TLS for HTTP server
*/}}
{{- define "ratify.tlsSecret" -}}
{{- if eq (include "ratify.tlsCertsProvided" .) "true" }}
tls.crt: {{ .Values.provider.tls.crt | b64enc | quote }}  
tls.key: {{ .Values.provider.tls.key | b64enc | quote }}
ca.crt: {{ .Values.provider.tls.caCert | b64enc | quote }}
ca.key: {{ .Values.provider.tls.caKey | b64enc | quote }}
{{- end }}
{{- end }}

{{/*
Set the namespace exclusions for Assign
*/}}
{{- define "ratify.assignExcludedNamespaces" -}}
{{- $gkNamespace := default "gatekeeper-system" .Values.gatekeeper.namespace -}}
- {{ $gkNamespace | quote}}
- "kube-system"
- "dapr-system"
{{- if and (ne .Release.Namespace $gkNamespace) (ne .Release.Namespace "kube-system") }}
- {{ .Release.Namespace | quote}}
{{- end }}
{{- range .Values.provider.mutationExcludedNamespaces }}
- {{ . | quote }}
{{- end }}
{{- end }}

{{/*
Choose cosign legacy or not. Determined by if cosignKeys are provided or not
OR if azurekeyvault is enabled and keys are provided
OR if keyless is enabled and certificateIdentity, certificateIdentityRegExp, certificateOIDCIssuer, or certificateOIDCIssuerExp are provided
*/}}
{{- define "ratify.cosignLegacy" -}}
{{- $cosignKeysPresent := gt (len .Values.cosignKeys) 0 -}}
{{- $azureKeyVaultEnabled := .Values.azurekeyvault.enabled -}}
{{- $azureKeyVaultKeysPresent := gt (len .Values.azurekeyvault.keys) 0 -}}
{{- if or $cosignKeysPresent (and $azureKeyVaultEnabled $azureKeyVaultKeysPresent) .Values.cosign.keyless.certificateIdentity .Values.cosign.keyless.certificateIdentityRegExp .Values.cosign.keyless.certificateOIDCIssuer .Values.cosign.keyless.certificateOIDCIssuerExp -}}
false
{{- else }}
true
{{- end }}
{{- end }}
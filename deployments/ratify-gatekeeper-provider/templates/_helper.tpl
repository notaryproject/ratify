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
{{- end }}


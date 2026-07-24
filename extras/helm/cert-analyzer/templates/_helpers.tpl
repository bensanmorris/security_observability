{{- define "cert-analyzer.labels" -}}
app: cert-expiry-monitor
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Renders a full "registry/repository:tag" image reference. global.imageRegistry, when
non-empty, replaces the passed-in registry for every image in the chart -- the standard
"set the internal registry host once" convention for air-gapped installs.
Usage: {{ include "cert-analyzer.image" (dict "registry" .Values.image.registry "repository" .Values.image.repository "tag" .Values.image.tag "global" .Values.global.imageRegistry) }}
*/}}
{{- define "cert-analyzer.image" -}}
{{- $registry := .registry -}}
{{- if .global -}}
{{- $registry = .global -}}
{{- end -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry .repository .tag -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}

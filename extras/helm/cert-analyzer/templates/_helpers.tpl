{{- define "cert-analyzer.labels" -}}
app: cert-expiry-monitor
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

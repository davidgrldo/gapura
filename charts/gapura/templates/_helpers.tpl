{{/* Chart name, overridable. */}}
{{- define "gapura.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Release-qualified name, overridable. */}}
{{- define "gapura.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "gapura.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gapura.labels" -}}
helm.sh/chart: {{ include "gapura.chart" . }}
{{ include "gapura.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: gapura
{{- end -}}

{{- define "gapura.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gapura.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "gapura.serviceAccountName" -}}
{{- if (.Values.serviceAccount).create -}}
{{- default (include "gapura.fullname" .) (.Values.serviceAccount).name -}}
{{- else -}}
{{- default "default" (.Values.serviceAccount).name -}}
{{- end -}}
{{- end -}}

{{- define "gapura.consoleImage" -}}
{{- /* Every level guarded with the chart's defaults repeated here: a --reuse-values upgrade from
       a chart without a console section delivers image as null, and an unguarded read renders
       %!s(<nil>) into the image ref instead of failing. */}}
{{- $repository := (((.Values.console).image).repository) | default "ghcr.io/davidgrldo/gapura-control" -}}
{{- if (((.Values.console).image).digest) -}}
{{- printf "%s@%s" $repository (((.Values.console).image).digest) -}}
{{- else -}}
{{- printf "%s:%s" $repository (default .Chart.AppVersion (((.Values.console).image).tag)) -}}
{{- end -}}
{{- end -}}

{{- define "gapura.image" -}}
{{- if (.Values.image).digest -}}
{{- printf "%s@%s" (.Values.image).repository (.Values.image).digest -}}
{{- else -}}
{{- printf "%s:%s" (.Values.image).repository (default .Chart.AppVersion (.Values.image).tag) -}}
{{- end -}}
{{- end -}}

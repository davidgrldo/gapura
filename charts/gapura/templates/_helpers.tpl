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

{{- /* gapura.labels carries app.kubernetes.io/component: gateway through the selector labels.
       An object that is not the gateway -- the console's workloads, the smoke-test fixtures --
       used to append its own component and shipped with the key twice: helm keeps the last
       value and shrugs, but kustomize refuses the document outright, which broke every
       post-renderer that routes through it (#140). This is the same label set with the
       component named by the "component" entry instead: call it with
       (dict "root" . "component" "console"). */}}
{{- define "gapura.componentLabels" -}}
{{- $root := index . "root" -}}
helm.sh/chart: {{ include "gapura.chart" $root }}
app.kubernetes.io/name: {{ include "gapura.name" $root }}
app.kubernetes.io/instance: {{ $root.Release.Name }}
app.kubernetes.io/component: {{ index . "component" }}
app.kubernetes.io/version: {{ $root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ $root.Release.Service }}
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

{{- /* The admin Service's name: the base truncated so the suffix still fits the 63-character
       limit. Both the Service and --gateway-admin must build the name this one way -- with the
       untruncated fullname the console called a Service that does not exist and every route
       read "cannot tell". */}}
{{- define "gapura.adminName" -}}
{{- printf "%s-admin" (include "gapura.fullname" . | trunc 57 | trimSuffix "-") -}}
{{- end -}}

{{- /* The console objects' name base, truncated for the same 63-character limit: a fullname
       long enough to survive it makes <fullname>-control an invalid name on its own. */}}
{{- define "gapura.controlName" -}}
{{- printf "%s-control" (include "gapura.fullname" . | trunc 55 | trimSuffix "-") -}}
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

{{- /* The configuration endpoint's Service name. It carries the longest suffix (-control-config),
       so it truncates its own base; deriving it from gapura.controlName could itself overrun 63.
       The console's Service and the data plane's default --control-plane both build it here. */}}
{{- define "gapura.configName" -}}
{{- printf "%s-control-config" (include "gapura.fullname" . | trunc 48 | trimSuffix "-") -}}
{{- end -}}

{{- /* The data plane's objects (Deployment, Service, ServiceAccount), truncated for the same
       63-character limit. */}}
{{- define "gapura.dataPlaneName" -}}
{{- printf "%s-data-plane" (include "gapura.fullname" . | trunc 52 | trimSuffix "-") -}}
{{- end -}}

{{- /* The pod and container security contexts and the probes, shared by the Kubernetes-mode
       gateway and the data plane: the same binary, bound the same way, healthy by the same
       endpoints. */}}
{{- define "gapura.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- if eq .Values.privilegedPorts "sysctl" }}
sysctls:
- name: net.ipv4.ip_unprivileged_port_start
  value: "0"
{{- end }}
{{- end -}}

{{- define "gapura.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
  {{- if eq .Values.privilegedPorts "capability" }}
  add: ["NET_BIND_SERVICE"]
  {{- end }}
{{- end -}}

{{- /* `--drain-seconds` from preStopDelaySeconds, the name it had while it was a pre-stop sleep.
       The delay comes out of the grace period's budget, so it is cut to what the grace period
       leaves after Pingora's own drain rather than refused: a values file carrying 0.1.0's 75 s
       must keep rendering on upgrade, with the 14 s it has room for. deployment.yaml refuses a
       grace period below 61, so this never goes negative. */ -}}
{{- define "gapura.drainArg" -}}
{{- $grace := int (.Values.terminationGracePeriodSeconds | default 0) -}}
{{- $drain := min (int (.Values.preStopDelaySeconds | default 0)) (sub $grace 61) -}}
{{- if gt $drain 0 }}
- --drain-seconds={{ $drain }}
{{- end }}
{{- end -}}

{{- define "gapura.probes" -}}
readinessProbe:
  httpGet: { path: /readyz, port: admin }
  periodSeconds: 5
  failureThreshold: 3
{{- if eq .Values.livenessPort "http" }}
livenessProbe:
  tcpSocket: { port: http }
  periodSeconds: 10
  failureThreshold: 3
{{- else }}
livenessProbe:
  httpGet: { path: /healthz, port: admin }
  periodSeconds: 10
  failureThreshold: 3
{{- end }}
# On /healthz, not /readyz: readiness waits for the first config, which never arrives when
# the Gateway API CRDs or the RBAC are missing, and a startupProbe on it would turn that
# into CrashLoopBackOff instead of a pod that stays NotReady with readable logs.
startupProbe:
  httpGet: { path: /healthz, port: admin }
  periodSeconds: 2
  failureThreshold: 30
{{- end -}}

{{/*
Log and trace export and debug timing (values: telemetry), shared by the gateway and the data
plane. `part` is "args" for the container's flags, "volumes" for the header and token Secrets and
"mounts" for where they are mounted; each renders nothing while none is on. Call it as
include "gapura.telemetry" (dict "root" . "part" "args").
*/}}
{{- define "gapura.telemetry" -}}
{{- $t := .root.Values.telemetry | default dict }}
{{- $log := $t.httpLog | default dict }}
{{- $logHeaders := $log.headers | default dict }}
{{- $otlp := $t.otlp | default dict }}
{{- $otlpHeaders := $otlp.headers | default dict }}
{{- $logSecret := and $log.url $logHeaders.existingSecret }}
{{- $otlpSecret := and $otlp.tracesUrl $otlpHeaders.existingSecret }}
{{- $debug := $t.debugTiming | default dict }}
{{- if eq .part "args" }}
{{- if $log.url }}
- --http-log-url={{ $log.url }}
{{- if $logSecret }}
- --http-log-headers-file=/etc/gapura-http-log/{{ $logHeaders.key | default "headers" }}
{{- end }}
{{- end }}
{{- if $otlp.tracesUrl }}
- --otlp-traces-url={{ $otlp.tracesUrl }}
{{- if not (kindIs "invalid" $otlp.sampleRatio) }}
- --otlp-sample-ratio={{ $otlp.sampleRatio }}
{{- end }}
{{- if $otlpSecret }}
- --otlp-headers-file=/etc/gapura-otlp/{{ $otlpHeaders.key | default "headers" }}
{{- end }}
{{- end }}
{{- if $debug.existingSecret }}
- --debug-token-file=/etc/gapura-debug-token/{{ $debug.key | default "token" }}
{{- end }}
{{- else if eq .part "volumes" }}
{{- if $logSecret }}
- name: http-log-headers
  secret: { secretName: {{ $logHeaders.existingSecret }} }
{{- end }}
{{- if $otlpSecret }}
- name: otlp-headers
  secret: { secretName: {{ $otlpHeaders.existingSecret }} }
{{- end }}
{{- if $debug.existingSecret }}
- name: debug-token
  secret: { secretName: {{ $debug.existingSecret }} }
{{- end }}
{{- else }}
{{- if $logSecret }}
- { name: http-log-headers, mountPath: /etc/gapura-http-log, readOnly: true }
{{- end }}
{{- if $otlpSecret }}
- { name: otlp-headers, mountPath: /etc/gapura-otlp, readOnly: true }
{{- end }}
{{- if $debug.existingSecret }}
- { name: debug-token, mountPath: /etc/gapura-debug-token, readOnly: true }
{{- end }}
{{- end }}
{{- end -}}

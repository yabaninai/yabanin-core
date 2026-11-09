{{- define "yabanin.fullname" -}}
{{- .Release.Name -}}
{{- end -}}

{{- define "yabanin.labels" -}}
app.kubernetes.io/name: yabanin
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* N11-P02-T03 secret injection: existingSecret wins, else chart-rendered
     Secret. The fail-closed precedence guard lives where the values are read
     (secrets.yaml); workloads only resolve the name here. */}}
{{- define "yabanin.onprem.appSecretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-secrets" .Release.Name) -}}
{{- end -}}

{{- define "yabanin.onprem.kekSecretName" -}}
{{- .Values.kms.existingSecret | default (printf "%s-kek" .Release.Name) -}}
{{- end -}}

{{- define "yabanin.onprem.licenseSecretName" -}}
{{- .Values.license.existingSecret | default (printf "%s-license" .Release.Name) -}}
{{- end -}}

{{/* N11-P02-T03: render one probe (readiness/liveness/startup) from a values
     block supporting httpGet or tcpSocket. `.` is the probe values map.
     Usage: {{ include "yabanin.onprem.probe" (dict "probe" .Values.probes.gateway.startup "style" "startupProbe") | nindent 12 }} */}}
{{- define "yabanin.onprem.probe" -}}
{{- $p := .probe -}}
{{- .style }}:
  {{- if $p.httpGet }}
  httpGet:
    path: {{ $p.httpGet.path }}
    port: {{ $p.httpGet.port }}
  {{- else }}
  tcpSocket:
    port: {{ $p.tcpSocket.port }}
  {{- end }}
  {{- with $p.initialDelaySeconds }}
  initialDelaySeconds: {{ . }}
  {{- end }}
  {{- with $p.periodSeconds }}
  periodSeconds: {{ . }}
  {{- end }}
  {{- with $p.failureThreshold }}
  failureThreshold: {{ . }}
  {{- end }}
{{- end -}}

{{/* N11-P02-T03 migration locking: chart-level guard used by the upgrade
     jobs. Waits while ANOTHER session holds the migration advisory lock
     (hashtext('yabanin:migrations')) — e.g. a concurrent helm run's migrate
     job — and aborts after migration.waitTimeoutSeconds instead of racing it.
     Session-scoped pg_advisory_lock taken INSIDE the migrate runner itself is
     a pkg/migrate follow-up (out of this card's write scope); see
     HA-TOPOLOGY.md "Migration locking" for the exact guarantee boundary. */}}
{{- define "yabanin.onprem.waitMigrationLock" -}}
- name: wait-migration-lock
  image: {{ $.Values.postgres.image }}
  env:
    - name: PG_PASSWORD
      valueFrom:
        secretKeyRef:
          name: {{ include "yabanin.onprem.appSecretName" $ }}
          key: pg_password
  command: ["sh", "-c"]
  args:
    - |
      set -e
      timeout={{ $.Values.migration.waitTimeoutSeconds }}
      deadline=$(( $(date +%s) + timeout ))
      uri="postgres://yabanin:$PG_PASSWORD@{{ $.Release.Name }}-postgres:5432/yabanin?sslmode=disable"
      echo "waiting for migration lock ({{ $.Values.migration.lockTag }}), timeout ${timeout}s"
      while [ "$(psql "$uri" -Atqc "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objid = hashtext('{{ $.Values.migration.lockTag }}')")" != "0" ]; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
          echo "migration lock still held after ${timeout}s — refusing to run concurrent migrations" >&2
          exit 1
        fi
        sleep 2
      done
      echo "migration lock free"
{{- end -}}

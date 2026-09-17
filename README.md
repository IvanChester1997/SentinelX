# SentinelX

**Defensive Security Monitoring & Detection Platform**

SentinelX is a defensive monitoring platform that processes security events, detects suspicious activity, correlates detections into incidents, calculates risk, and manages alerts.

## Architecture

```text
Collectors → Event Normalizer → Detection Engine → Correlation
→ Risk Engine → Alert / Incident Manager → REST API / Dashboard
```

## Detection coverage

- SSH brute-force
- Password spraying
- Suspicious root login
- Privilege escalation
- Privileged account creation

## Local development

Requirements: Python 3.13+

Run tests:

```bash
.venv/bin/pytest -q --cov=app --cov-report=term-missing
```

Run Ruff:

```bash
.venv/bin/ruff check .
```

## Docker security lab

The repository contains an isolated disposable SSH target for defensive monitoring demonstrations.

```text
SSH client
    ↓
security-target
    ↓
rsyslog
    ↓
/shared/auth.log
    ↓ read-only
SentinelX
    ↓
LinuxAuthLogCollector
    ↓
Detection → Incident → Risk → Alert
```

Start the lab:

```bash
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8000/health
```

Generate an SSH authentication event:

```bash
ssh -p 2222 -o PreferredAuthentications=password -o PubkeyAuthentication=no labuser@127.0.0.1
```

Inspect the target log:

```bash
docker exec sentinelx-security-target cat /shared/auth.log
```

Process the log through SentinelX:

```bash
docker exec sentinelx python -c "from app.collectors.linux_auth import LinuxAuthLogCollector; from app.services.monitoring import MonitoringService; collector=LinuxAuthLogCollector(\"/shared/auth.log\"); service=MonitoringService(); [print(service.process_collected_event(event).model_dump_json(indent=2)) for event in collector.collect()]"
```

Dashboard:

`http://127.0.0.1:8000/dashboard`

Stop the lab:

```bash
docker compose down
```

Remove volumes as well:

```bash
docker compose down -v
```

## Security properties

- SentinelX runs as a non-root user.
- All Linux capabilities are dropped.
- `no-new-privileges` is enabled.
- Application state uses a named volume.
- The target authentication log is mounted read-only into SentinelX.

## CI

GitHub Actions runs Ruff, pytest, coverage, and pip-audit.

## Scope

SentinelX is a defensive monitoring and detection project. The Docker lab exists only to generate controlled authentication telemetry for authorized testing.

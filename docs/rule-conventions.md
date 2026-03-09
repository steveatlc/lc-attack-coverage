# Rule Naming and Metadata Conventions

## Rule Naming

All auto-generated rules follow the pattern:

```
attack-{technique_id}-{short-name}
```

Examples:
- `attack-T1059.001-powershell-execution`
- `attack-T1053.005-scheduled-task`
- `attack-T1547.001-registry-run-keys`

### Naming rules

- Technique ID is always uppercase (T1059, not t1059)
- Short name is lowercase, hyphen-separated
- Maximum total length: 80 characters
- Sub-technique IDs include the dot notation (T1059.001)

## Metadata Standard

Every rule's respond block includes a `report` action with structured metadata:

```yaml
respond:
  - action: report
    name: "attack-T1059.001-powershell-execution"
    priority: 5
    metadata:
      mitre_attack_id: "T1059.001"
      mitre_technique: "Command and Scripting Interpreter: PowerShell"
      mitre_tactic: "execution"
      mitre_url: "https://attack.mitre.org/techniques/T1059/001/"
      atomic_test_ref: "T1059.001-1"
      data_sources: "Process Creation"
      platforms: "windows"
      author: "attack-coverage-generator"
      version: "1.0"
      confidence: "medium"
    detect_data:
      command_line: "{{ .event.COMMAND_LINE }}"
      file_path: "{{ .event.FILE_PATH }}"
      hostname: "{{ .routing.hostname }}"
      sensor_id: "{{ .routing.sid }}"
```

### Metadata fields

| Field | Required | Description |
|-------|----------|-------------|
| `mitre_attack_id` | Yes | ATT&CK technique ID (e.g., T1059.001) |
| `mitre_technique` | Yes | Full technique name including sub-technique |
| `mitre_tactic` | Yes | Primary tactic (lowercase, hyphenated) |
| `mitre_url` | Yes | Direct link to ATT&CK technique page |
| `atomic_test_ref` | No | Reference to Atomic Red Team test used for indicators |
| `data_sources` | Yes | ATT&CK data components this rule relies on |
| `platforms` | Yes | Target platforms (windows, linux, macos) |
| `author` | Yes | Always "attack-coverage-generator" for auto-generated rules |
| `version` | Yes | Rule version (increment on manual tuning) |
| `confidence` | Yes | low, medium, or high |

### Detect data fields

The `detect_data` section captures key event fields using template variables. This data is included in the detection output for downstream consumption (AI correlation, SIEM export, etc.).

## Priority Weighting

| Factor | Impact |
|--------|--------|
| Base priority | 3 (configurable in config.yaml) |
| Used by 5+ threat groups | +2 |
| Used by 1-4 threat groups | +1 |
| Requires elevated privileges | +1 |
| Maximum cap | 10 |

## Suppression

Every rule includes suppression to prevent alert fatigue:

```yaml
- action: suppression
  max_count: 5
  period: 1h
  is_global: false
  keys:
    - "{{ .routing.sid }}"
    - "attack-T{id}"
```

- Suppresses after 5 occurrences per sensor per hour per technique
- Not global (per-sensor suppression)
- Adjustable in config.yaml

## Tags

All auto-generated rules are tagged with:
- `attack-coverage` — identifies all rules from this system
- The primary tactic name (e.g., `execution`, `persistence`)
- `auto-generated` — distinguishes from manually authored rules
- `placeholder` — added to rules that detect only by event type (need tuning)

## Confidence Levels

| Level | Meaning | Use When |
|-------|---------|----------|
| `low` | Broad detection, high false-positive risk | Event-type-only rules (placeholders) |
| `medium` | Reasonable detection with some FP expected | Indicator-based rules from Atomic Red Team |
| `high` | Precise detection, low FP risk | Rules tuned with specific, validated patterns |

Rules start at `medium` by default. Tuning should move them to `high` or back to `low` as appropriate.

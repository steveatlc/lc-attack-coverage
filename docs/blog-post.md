# Automating MITRE ATT&CK Detection Coverage with LimaCharlie

If you've ever stared at the ATT&CK matrix and wondered "how much of this can I actually detect?" — and then immediately felt the weight of 700+ techniques — you're not alone. Mapping detection coverage to ATT&CK is one of those tasks every security team knows they should do, but the manual effort keeps it perpetually on the backlog.

We built an open-source project that automates the entire pipeline: pulling ATT&CK data, mapping it to LimaCharlie telemetry, generating detection rules, deploying them, and producing a gap analysis — all in five Python scripts you can run in sequence. Then it goes a step further: an AI correlation layer that watches for multi-tactic attack progression and automatically creates investigation tickets.

This post walks through what the project does, how it works, and how you can use it in your own LimaCharlie environment.

The code and documentation are available at [github.com/steveatlc/lc-attack-coverage](https://github.com/steveatlc/lc-attack-coverage).

## The Problem

ATT&CK coverage mapping is typically a manual, point-in-time exercise. You open a spreadsheet, cross-reference technique descriptions against your telemetry, write some rules, and by the time you're done the matrix has a new version. The result is often a Navigator layer that's outdated before it's published, and a set of hand-written rules that cover maybe 20-30 techniques.

The gap between "what ATT&CK defines" and "what your EDR can see" is also rarely quantified. Teams know they have blind spots, but not which blind spots matter most or what data sources would close them.

## What This Project Does

The pipeline has five phases, each a standalone Python script:

### Phase 1: Data Acquisition

The first script downloads two machine-readable data sources:

- **MITRE ATT&CK STIX bundle** — the full enterprise matrix in structured JSON, including techniques, tactics, data sources, data components, and threat group relationships
- **Atomic Red Team** — Red Canary's library of 1,770+ test definitions, each tied to an ATT&CK technique with executable commands and observable indicators

The script parses both into cached structures. From Atomic Red Team, it extracts observable indicators using pattern matching: file paths, registry keys, known tool names (mimikatz, rubeus, certutil, etc.), command-line patterns (encoded PowerShell, `Invoke-Expression`, lateral movement commands), IP addresses, and domains. In our run, it extracted 4,201 indicators across 328 techniques.

### Phase 2: Telemetry Mapping

This is where LimaCharlie-specific knowledge comes in. A hand-authored YAML file maps LimaCharlie event types to ATT&CK data components:

```yaml
NEW_PROCESS:
  data_components:
    - "Process Creation"
  fields:
    command_line: "event/COMMAND_LINE"
    file_path: "event/FILE_PATH"
    parent: "routing/parent"
    user: "event/USER_NAME"
  platforms: [windows, linux, macos]

REGISTRY_WRITE:
  data_components:
    - "Windows Registry Key Modification"
  fields:
    key: "event/REGISTRY_KEY"
    value: "event/VALUE"
  platforms: [windows]

DNS_REQUEST:
  data_components:
    - "Network Traffic Content"
  fields:
    domain: "event/DOMAIN_NAME"
  platforms: [windows, linux, macos]
```

The mapping covers 26 LimaCharlie event types across 19 ATT&CK data components. The script then assesses every technique: does LimaCharlie have telemetry for the required data components? Techniques are classified as fully covered, partially covered, or not covered.

**Our results against the current ATT&CK matrix:**

| Status | Techniques | Percentage |
|--------|-----------|------------|
| Fully covered | 42 | 7.9% |
| Partially covered | 333 | 62.2% |
| Not covered | 160 | 29.9% |

The 62% partial coverage is the interesting number — these are techniques where LimaCharlie has *some* of the required telemetry but not all. The gap analysis identifies exactly which data components are missing and what you'd need to enable to close the gap.

### Phase 3: Rule Generation

For every technique with sufficient telemetry *and* extractable indicators from Atomic Red Team, the script generates LimaCharlie D&R rules. The logic maps indicator types to detection approaches:

| Indicator Type | LC Event | Detection Approach |
|---|---|---|
| Command-line pattern | `NEW_PROCESS` | Regex on `event/COMMAND_LINE` |
| Suspicious process name | `NEW_PROCESS` | Match on `event/FILE_PATH` |
| File creation in path | `FILE_CREATE` | Path contains/starts-with |
| Registry key modification | `REGISTRY_WRITE` | Key path contains |
| DNS to known domain | `DNS_REQUEST` | Domain match |
| Network connection | `NEW_TCP4_CONNECTION` | IP match |

Each rule includes:
- **Platform filtering** via `routing/platform` so Windows rules don't fire on Linux sensors
- **ATT&CK metadata** in the report action (technique ID, tactic, URL, confidence level, data sources)
- **Priority weighting** — base priority adjusted upward for techniques used by many threat groups or requiring elevated privileges
- **Suppression** — 5 occurrences per sensor per hour per technique to prevent alert floods

Here's what a generated rule looks like:

```yaml
name: attack-T1059.001-powershell-bloodhound
detect:
  event: NEW_PROCESS
  op: and
  rules:
  - op: is
    path: routing/platform
    value: windows
  - op: matches
    path: event/FILE_PATH
    re: .*bloodhound.*
respond:
- action: report
  name: attack-T1059.001-powershell-bloodhound
  priority: 5
  metadata:
    mitre_attack_id: T1059.001
    mitre_technique: PowerShell
    mitre_tactic: execution
    mitre_url: https://attack.mitre.org/techniques/T1059/001
    data_sources: Module Load, Process Creation
    platforms: windows
    author: attack-coverage-generator
    version: '1.0'
    confidence: medium
  suppression:
    max_count: 5
    period: 1h
    is_global: false
    keys:
    - '{{ .routing.sid }}'
    - attack-T1059.001
```

**Our run produced 1,156 rules** across all 12 ATT&CK tactics, with the heaviest coverage in defense-evasion (348 rules), persistence (184), and execution (124).

### Phase 4: Deployment

The deployment script pushes rules to a LimaCharlie org via the Hive API (`dr-general`). It supports:

- `--dry-run` for validation without deployment
- `--filter-technique T1059` to deploy only specific techniques
- `--filter-tactic execution` to deploy by tactic
- `--clean` to remove all existing `attack-coverage` tagged rules before deploying

All rules are tagged `attack-coverage` and `auto-generated`, making them easy to identify, filter, and remove as a group.

### Phase 5: Coverage Report

The final script produces two outputs:

1. **A markdown gap analysis** with coverage breakdowns by tactic and platform, a full list of partially-covered techniques with what's missing, and a prioritized list of data source recommendations

2. **An ATT&CK Navigator layer** (JSON) you can upload to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) for visual heatmap reporting — green for covered, yellow for partial, red for gaps

The data source recommendations are particularly actionable. For example, "Command Execution" is the most impactful missing component (270 techniques benefit from it), and the recommendation is specific: enable PowerShell ScriptBlock Logging and forward Event ID 4104 via WEL.

## AI-Driven Correlation

Rules that fire individually are useful. Rules that fire in combination tell a story.

The project includes an AI correlation layer that watches for multi-tactic attack progression on a single host. When any `attack-*` detection fires, a D&R rule triggers a LimaCharlie AI Session that:

1. Queries all `attack-*` detections on the same sensor from the last 24 hours
2. Counts distinct ATT&CK tactics observed
3. Scores severity based on tactic diversity and kill-chain progression
4. Creates or updates an investigation ticket with a correlated timeline

The scoring model:

| Condition | Priority |
|-----------|----------|
| 2 distinct tactics | Medium (4) |
| 3 distinct tactics | High (6) |
| 4+ distinct tactics | Critical (8) |
| Kill-chain progression (e.g., Initial Access &rarr; Execution &rarr; Persistence) | +2 |
| Same technique across 3+ hosts | +1 |

The trigger rule:

```yaml
detect:
  event: _detect
  op: starts with
  path: detect/name
  value: "attack-"

respond:
  - action: start ai session
    prompt: "<see ai/correlation_prompt.md>"
    anthropic_secret: "hive://secret/anthropic-api-key"
    idempotent_key: "correlation-{{ .routing.sid }}-{{ .detect.name }}"
    profile:
      model: claude-sonnet-4-6
      max_turns: 10
      max_budget_usd: 0.50
      tools:
        - sensor_timeline
        - search_detections
        - get_ticket
        - create_ticket
        - update_ticket
        - add_ticket_note
```

The full correlation prompt is in [`ai/correlation_prompt.md`](ai/correlation_prompt.md) — it instructs the AI session on how to query recent detections, score tactic diversity, and create or update investigation tickets. The `idempotent_key` prevents duplicate AI sessions for the same detection event. The budget cap keeps costs predictable.

A parallel configuration is included for the LimaCharlie AI Agent Engine (Gemini-based), so you can choose whichever AI integration fits your environment.

## What You'll Learn from the Gap Analysis

Running this against your own environment will surface patterns like:

**The biggest telemetry gaps are consistent across organizations.** "Command Execution" (script-level content, not just process creation) affects 270 techniques. "OS API Execution" affects 99. These aren't gaps you can close with endpoint telemetry alone — they require additional log sources like PowerShell ScriptBlock Logging, Sysmon, or auditd.

**Network and cloud techniques have the lowest coverage.** LimaCharlie's native EDR telemetry is strongest for process, file, and registry activity. Network-layer and cloud-plane techniques require supplementary data from cloud audit logs, proxy logs, or network sensors — all of which LimaCharlie can ingest via adapters and cloud sensors, but they need to be configured.

**Partial coverage is more common than no coverage.** 62% of techniques are partially covered, meaning LimaCharlie sees *some* of the required data. The gap analysis tells you exactly which additional data component would promote each technique from partial to full coverage.

## Getting Started

```bash
git clone https://github.com/steveatlc/lc-attack-coverage.git
cd lc-attack-coverage
pip install -r requirements.txt

# Configure your org
# Edit config.yaml with your org ID, or set LC_OID and LC_API_KEY env vars

# Run the pipeline
python 01_fetch_attack_data.py    # Download ATT&CK + Atomic Red Team data
python 02_map_telemetry.py        # Assess telemetry coverage
python 03_generate_rules.py       # Generate D&R rules
python 04_deploy_rules.py --dry-run  # Validate (review output/rules/ first!)
python 04_deploy_rules.py         # Deploy to your org
python 05_coverage_report.py      # Generate gap analysis
```

The entire pipeline runs in under 5 minutes. Review the generated rules before deploying — they're starting points, not finished detections. Many will need tuning for your environment: tightening regex patterns, adjusting suppression thresholds, or adding exclusions for known-good activity.

The telemetry mapping (`mappings/lc_event_to_datasource.yaml`) is the file you'll want to maintain over time. As LimaCharlie adds new event types or you enable new data sources, update this mapping and re-run the pipeline.

## What This Is and Isn't

**This is** a framework for bootstrapping ATT&CK-aligned detection coverage, quantifying gaps, and automating the tedious mapping work. It gives you a baseline you can build on.

**This is not** a replacement for detection engineering. Auto-generated rules from Atomic Red Team indicators are a starting point — many patterns are generic (matching tool names or common command-line flags) and will need tuning. The value is in having 1,000+ rules deployed as a starting baseline rather than starting from zero, and in having a repeatable pipeline that updates as ATT&CK evolves.

## Extending the Naming Convention for Custom Rules

The generated rules use a structured naming pattern — `attack-{TECHNIQUE_ID}-{short-name}` — that enables the AI correlation layer, suppression keying, and tag-based filtering to work automatically. You can extend this for your own hand-authored detections without conflicting with the auto-generated set.

The approach: insert a namespace segment between `attack-` and the technique ID:

```
attack-{namespace}-{TECHNIQUE_ID}-{short-name}
```

For example, if your organization is Acme Corp and you write a custom detection for T1059.001 based on your own threat intelligence:

```
attack-acme-T1059.001-encoded-iex-stager
```

This preserves everything that makes the convention efficient:

- **AI correlation still triggers.** The correlation rule matches on `starts with "attack-"`, so namespaced rules are automatically included in multi-tactic scoring without changing the trigger configuration.
- **Suppression keys remain isolated.** The suppression key uses the full rule name, so `attack-acme-T1059.001-encoded-iex-stager` and `attack-T1059.001-powershell-bloodhound` suppress independently — both can fire without interfering with each other.
- **Tag-based filtering stays clean.** Tag your custom rules with `attack-coverage` (so they appear in coverage reports) and your namespace (e.g., `acme`) instead of `auto-generated`. You can then filter on `auto-generated` vs `acme` to manage each set independently, while queries for `attack-coverage` still return the full picture.
- **Metadata carries through.** Use the same metadata fields (`mitre_attack_id`, `mitre_tactic`, `confidence`, etc.) but set `author` to your namespace instead of `attack-coverage-generator`. The correlation layer and coverage report consume these fields regardless of who authored the rule.

A custom rule following this pattern:

```yaml
name: attack-acme-T1059.001-encoded-iex-stager
detect:
  event: NEW_PROCESS
  op: and
  rules:
  - op: is
    path: routing/platform
    value: windows
  - op: matches
    path: event/COMMAND_LINE
    re: .*-[eE][nN][cC]\s+[A-Za-z0-9+/=]{40,}.*[iI][eE][xX].*
respond:
- action: report
  name: attack-acme-T1059.001-encoded-iex-stager
  priority: 7
  metadata:
    mitre_attack_id: T1059.001
    mitre_technique: "Command and Scripting Interpreter: PowerShell"
    mitre_tactic: execution
    author: acme
    version: '1.0'
    confidence: high
  suppression:
    max_count: 5
    period: 1h
    is_global: false
    keys:
    - '{{ .routing.sid }}'
    - attack-acme-T1059.001
```

This rule will be picked up by the correlation layer alongside the auto-generated rules, show up in coverage reports under T1059.001, and remain independently manageable via its `acme` tag and author field. When you re-run the generator, your namespaced rules are untouched — the pipeline only manages rules with the `auto-generated` tag.

The code is MIT-licensed and available at [github.com/steveatlc/lc-attack-coverage](https://github.com/steveatlc/lc-attack-coverage). Contributions welcome — especially improvements to the telemetry mapping and indicator extraction logic.

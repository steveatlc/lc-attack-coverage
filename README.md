# LimaCharlie ATT&CK Detection Coverage

Automated MITRE ATT&CK detection coverage for [LimaCharlie](https://limacharlie.io): generates D&R rules from ATT&CK + Atomic Red Team data, produces a telemetry gap analysis, and includes an AI correlation layer for multi-tactic attack detection.

**Read the full writeup:** [Automating MITRE ATT&CK Detection Coverage with LimaCharlie](docs/blog-post.md)

## What It Does

1. **Downloads** MITRE ATT&CK STIX data and Atomic Red Team test definitions
2. **Maps** ATT&CK data components to LimaCharlie event types
3. **Generates** D&R rules with ATT&CK metadata, platform filtering, and suppression
4. **Deploys** rules to a LimaCharlie org via the Hive API
5. **Reports** coverage gaps with actionable data source recommendations
6. **Correlates** detections via AI to identify multi-tactic attack progression

## Results

Against the current ATT&CK Enterprise matrix:

- **1,156 D&R rules** generated across 12 tactics
- **42 techniques** fully covered, **333 partially** covered
- **ATT&CK Navigator layer** for visual reporting
- Prioritized recommendations for closing coverage gaps

## Quick Start

```bash
pip install -r requirements.txt

# Set your LimaCharlie credentials
export LC_OID="your-org-id"
export LC_API_KEY="your-api-key"

# Run the pipeline
python 01_fetch_attack_data.py      # Download ATT&CK + Atomic Red Team
python 02_map_telemetry.py          # Assess telemetry coverage
python 03_generate_rules.py         # Generate D&R rules
python 04_deploy_rules.py --dry-run # Validate before deploying
python 04_deploy_rules.py           # Deploy to your org
python 05_coverage_report.py        # Generate gap analysis + Navigator layer
```

## Project Structure

```
├── 01_fetch_attack_data.py     # Phase 1: Download and parse ATT&CK + Atomic RT
├── 02_map_telemetry.py         # Phase 2: Map data sources → LC events
├── 03_generate_rules.py        # Phase 3: Generate D&R rules from indicators
├── 04_deploy_rules.py          # Phase 4: Deploy rules to LC org
├── 05_coverage_report.py       # Phase 5: Gap analysis + Navigator layer
├── config.yaml                 # Configuration (org ID, thresholds, URLs)
├── requirements.txt            # Python dependencies
│
├── lib/
│   ├── attack_parser.py        # Parse ATT&CK STIX bundles
│   ├── atomic_parser.py        # Parse Atomic Red Team YAML + extract indicators
│   ├── rule_generator.py       # D&R rule generation logic
│   └── lc_client.py            # LimaCharlie SDK wrapper (Hive API)
│
├── mappings/
│   └── lc_event_to_datasource.yaml  # LC event → ATT&CK data component map
│
├── ai/
│   ├── correlation_prompt.md   # AI prompt for multi-tactic correlation
│   ├── ai_session_profile.yaml # D&R rule to trigger AI Sessions (Claude)
│   └── ai_agent_config.yaml    # AI Agent Engine config (Gemini)
│
├── docs/
│   ├── blog-post.md            # Full project writeup
│   ├── workflow.md             # Step-by-step operator guide
│   ├── rule-conventions.md     # Rule naming and metadata standards
│   └── data-gaps.md            # Living document of telemetry gaps
│
└── output/                     # Generated (gitignored)
    ├── rules/                  # Individual D&R rule YAML files
    ├── all_rules.yaml          # Consolidated rule file
    ├── coverage_report.md      # Gap analysis report
    └── navigator_layer.json    # ATT&CK Navigator layer
```

## Key Files

### `mappings/lc_event_to_datasource.yaml`

The hand-authored mapping of LimaCharlie events to ATT&CK data components. This is the critical reference file — update it when LC adds new event types or you enable additional telemetry sources. Covers 26 event types including `NEW_PROCESS`, `FILE_CREATE`, `REGISTRY_WRITE`, `DNS_REQUEST`, `MODULE_LOAD`, `WEL`, `SSH_LOGIN`, and more.

### `ai/correlation_prompt.md`

AI prompt that instructs an LimaCharlie AI Session to correlate detections across a host. When 2+ ATT&CK tactics are observed on the same sensor within 24 hours, it scores severity and creates/updates investigation tickets. Kill-chain progression (e.g., Initial Access → Execution → Persistence) triggers escalation.

### Deployment Options

**Deploy all rules:**
```bash
python 04_deploy_rules.py
```

**Deploy specific tactics or techniques:**
```bash
python 04_deploy_rules.py --filter-tactic execution
python 04_deploy_rules.py --filter-technique T1059
```

**Clean and redeploy:**
```bash
python 04_deploy_rules.py --clean
```

## AI Correlation Setup

### Option A: AI Sessions (Claude)

1. Store your Anthropic API key:
   ```bash
   limacharlie hive set secret anthropic-api-key --data '{"secret": "sk-ant-your-key-here"}'
   ```
2. Deploy the trigger rule from `ai/ai_session_profile.yaml`

### Option B: AI Agent Engine (Gemini)

```bash
limacharlie extension ai-agent-engine --action deploy --config ai/ai_agent_config.yaml
```

## Requirements

- Python 3.10+
- Git (for Atomic Red Team sparse checkout)
- LimaCharlie organization with API access
- `limacharlie` Python SDK (v4.11+)

## License

MIT — see [LICENSE](LICENSE).

This project downloads and processes data from [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) at runtime. See [NOTICES](NOTICES) for their respective licenses and attribution.

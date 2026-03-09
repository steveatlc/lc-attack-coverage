# ATT&CK Detection Coverage — End-to-End Workflow

## Prerequisites

- Python 3.10+
- Git (for Atomic Red Team sparse checkout)
- LimaCharlie organization with API access
- Anthropic API key (for AI correlation sessions)

## Initial Setup

```bash
cd /home/steve/support/automation/attack-coverage

# Install Python dependencies
pip install -r requirements.txt

# Configure your org
# Edit config.yaml:
#   - Set deployment.org_id to your test org ID
#   - Set deployment.api_key_env to the env var holding your API key

# Set environment variables
export LC_OID="your-org-id-here"
export LC_API_KEY="your-api-key-here"
```

## Step-by-Step Workflow

### Step 1: Fetch ATT&CK Data

Download the ATT&CK STIX bundle and Atomic Red Team test definitions:

```bash
python 01_fetch_attack_data.py
```

This will:
- Download `enterprise-attack.json` (~30 MB) to `data/`
- Sparse-checkout Atomic Red Team `atomics/` to `data/atomics/`
- Parse STIX data into structured format (`data/parsed_attack.json`)
- Parse Atomic Red Team tests and extract indicators (`data/parsed_atomics.json`)

**Re-run** this step whenever ATT&CK releases a new version or you want to pick up new Atomic Red Team tests.

### Step 2: Review Telemetry Mapping

The file `mappings/lc_event_to_datasource.yaml` maps LimaCharlie event types to ATT&CK data components. This is hand-authored and should be reviewed when:

- LimaCharlie adds new event types
- You enable new telemetry sources (e.g., new WEL channels)
- ATT&CK adds new data components

### Step 3: Map Telemetry Coverage

Assess which ATT&CK techniques LimaCharlie can detect:

```bash
python 02_map_telemetry.py
```

Output: `mappings/technique_rules.yaml` with coverage status per technique.

Review the console summary for:
- Overall coverage percentages
- Top missing data components
- Which data sources would give you the most coverage improvement

### Step 4: Generate D&R Rules

Produce detection rules for every coverable technique:

```bash
python 03_generate_rules.py
```

Output:
- Individual rule files in `output/rules/`
- Consolidated `output/all_rules.yaml`

**Human review step:** Examine 5-10 generated rules in `output/rules/` before deployment. Check for:
- Correct event types and field paths
- Reasonable regex patterns (not too broad, not too narrow)
- Appropriate priority levels
- Correct platform targeting

### Step 5: Validate Rules (Dry Run)

Test deployment without actually writing rules to the org:

```bash
python 04_deploy_rules.py --dry-run
```

This validates rule structure and LC API connectivity.

### Step 6: Deploy Rules

Deploy to your test org:

```bash
# Deploy all rules
python 04_deploy_rules.py

# Or deploy only specific tactics
python 04_deploy_rules.py --filter-tactic execution

# Or deploy only specific techniques
python 04_deploy_rules.py --filter-technique T1059

# Clean existing rules before deploying
python 04_deploy_rules.py --clean
```

Verify rules appear in the LimaCharlie web UI under D&R Rules.

### Step 7: Generate Coverage Report

Produce the gap analysis report and Navigator layer:

```bash
python 05_coverage_report.py
```

Output:
- `output/coverage_report.md` — Full gap analysis with recommendations
- `output/navigator_layer.json` — Upload to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visualization

### Step 8: Deploy AI Correlation

Choose **one** of the two AI approaches:

#### Option A: AI Sessions (Claude-based)

1. Store your Anthropic API key in the org's secrets:
   ```bash
   limacharlie hive set secret anthropic-api-key --data '{"secret": "sk-ant-your-key-here"}'
   ```

2. Deploy the D&R trigger rule from `ai/ai_session_profile.yaml`. The detect/respond blocks can be deployed manually or added to `04_deploy_rules.py`.

3. When any `attack-*` detection fires, an AI session will:
   - Query recent detections on the same host
   - Correlate ATT&CK tactics
   - Create/update investigation tickets

#### Option B: AI Agent Engine (Gemini-based)

Deploy the agent configuration:
```bash
limacharlie extension ai-agent-engine --action deploy --config ai/ai_agent_config.yaml
```

### Step 9: Verify End-to-End

1. Run Atomic Red Team tests against a test sensor
2. Verify detections fire in the LimaCharlie UI
3. Verify the AI session/agent triggers
4. Check that a correlation ticket is created when 2+ tactics are detected

## Periodic Maintenance

| Task | Frequency | Command |
|------|-----------|---------|
| Update ATT&CK data | Quarterly (on new ATT&CK release) | `python 01_fetch_attack_data.py` (delete `data/enterprise-attack.json` first) |
| Update Atomic Red Team | Monthly | `cd data/atomic-red-team && git pull` |
| Review telemetry mapping | When LC adds events | Edit `mappings/lc_event_to_datasource.yaml` |
| Regenerate rules | After any data update | `python 02_map_telemetry.py && python 03_generate_rules.py` |
| Re-deploy rules | After regeneration | `python 04_deploy_rules.py --clean` |
| Update coverage report | After any change | `python 05_coverage_report.py` |
| Review AI ticket quality | Weekly | Check tickets in LC Ticketing for accuracy |

## Troubleshooting

### "Parsed ATT&CK data not found"
Run `01_fetch_attack_data.py` first.

### Rules deploy but don't fire
- Verify the event type exists in your org's telemetry
- Check platform filter matches your sensors
- Review suppression settings (may be suppressing after first few hits)

### AI session doesn't trigger
- Verify the D&R trigger rule is deployed and enabled
- Check that `hive://secret/anthropic-api-key` is set
- Look for AI session errors in the org's audit log

### Low coverage percentages
- Many ATT&CK techniques require data sources LC doesn't natively provide
- Review `output/coverage_report.md` data source recommendations
- Enable additional WEL channels, syslog forwarding, or cloud adapters

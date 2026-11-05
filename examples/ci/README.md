# Consuming the effectiveness gate from CI

The gate is a plain command with a three-value exit contract. Nothing in this
directory is part of XAMMU's own CI; `scripts/gate-demo.sh` is the version this
repository runs, and the files here show how a consuming pipeline wires the same
command into GitHub, GitLab, Azure Pipelines or Jenkins.

## Contract

| exit | meaning | what a pipeline should do |
| --- | --- | --- |
| `0` | every applicable check met the policy | continue |
| `1` | a check failed; this is a result about the target | publish the SARIF, then fail the job |
| `2` | the gate could not evaluate: unusable CLI, unreadable bundle, invalid policy, missing evidence | fail the job and treat the *tool* as broken, not the target |

`gate --format sarif --out DIR` writes `DIR/results.sarif`. The JSON document
(`--format json`) is authoritative: every field appears there, the YAML
rendering indexes the same values, and the SARIF carries one result per failed
check or per sealed C-16 finding. SARIF is validated structurally against 2.1.0
in the unit tests; the ingestion below is the step that validates it for real.

A sealed delivery (`--format all --out DIR --signing-key FILE`) additionally
writes `publication.json`. Verify it with
`xammu verify --publication DIR --trust-key FILE`; exit `0` proves the files
still match the envelope and that the envelope was signed by that key, not that
the readings are correct.

## GitHub Actions

`github-actions-effectiveness.yml` is a complete workflow. The parts that matter:

```yaml
permissions:
  contents: read
  security-events: write        # upload-sarif needs it

- name: evaluate the policy
  id: gate
  continue-on-error: true       # keep the SARIF even when the gate exits 1
  run: ./build/xammu gate --store runs/<run-id> --policy policies/<file>.yaml \
         --format sarif --out build/gate

- name: upload SARIF to GitHub Code Scanning
  if: always() && hashFiles('build/gate/results.sarif') != ''
  uses: github/codeql-action/upload-sarif@9418214df1f2c4b8128c770156c409013b07d6b9 # v3
  with:
    sarif_file: build/gate/results.sarif
    category: xammu-waf-effectiveness

- name: fail the job when the policy failed
  if: steps.gate.outcome == 'failure'
  run: exit 1
```

The action is pinned by the commit the moving `v3` tag pointed to when this
example was written (2026-11-05). Re-resolve it with
`gh api repos/github/codeql-action/git/ref/tags/v3` when you update it; do not
replace the SHA with a tag.

Point `--store` at `runs/waf-effectiveness-2026-11-05-r6` to see the failure
path: the gate exits 1, Code Scanning shows one `error` result on
`effectiveness.tpr`, and the job stops after uploading it.

## GitLab CI

GitLab reads a SARIF report from `artifacts:reports:sarif`. Keep the artifact on
failure, because a gate that exits 1 is exactly when the report matters:

```yaml
waf-effectiveness:
  image: golang:1.27
  script:
    - go build -o build/xammu ./cmd/xammu
    - ./build/xammu verify --store runs/<run-id> --rederive --trust-key trust/<key>.pub
    - ./build/xammu gate --store runs/<run-id> --policy policies/<file>.yaml \
        --format sarif --out build/gate
  artifacts:
    when: always
    paths:
      - build/gate/results.sarif
    reports:
      sarif: build/gate/results.sarif
```

The job fails when the gate exits 1 or 2; the SARIF is attached in both cases.

## Azure Pipelines

SARIF ingestion in Azure DevOps needs the Microsoft Security DevOps extension
(`AdvancedSecurity-Publish`). Without it, keep the document as a build artifact:

```yaml
- script: go build -o build/xammu ./cmd/xammu
  displayName: build xammu

# Capture the exit code instead of relying on the agent's issue tracking, so
# the fail step below is explicit about what it reacts to.
- script: |
    set +e
    ./build/xammu gate --store runs/<run-id> --policy policies/<file>.yaml \
      --format sarif --out build/gate
    code=$?
    echo "##vso[task.setvariable variable=gateExitCode]$code"
    exit 0
  displayName: gate

- publish: build/gate/results.sarif
  artifact: xammu-sarif
  condition: always()

- script: |
    echo "gate exit code $(gateExitCode)"
    exit 1
  displayName: fail when the gate did not pass
  condition: and(succeeded(), ne(variables['gateExitCode'], '0'))
```

The `AdvancedSecurity-Publish` task, when installed, takes
`SarifPath: build/gate/results.sarif` instead of the `publish` step. That task is
not exercised by this repository, so it is described here and not claimed as
tested.

## Jenkins

The Warnings Next Generation plugin reads SARIF:

```groovy
stage('gate') {
  steps {
    sh 'go build -o build/xammu ./cmd/xammu'
    catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
      sh './build/xammu gate --store runs/<run-id> --policy policies/<file>.yaml ' +
         '--format sarif --out build/gate'
    }
    recordIssues tools: [sarif(pattern: 'build/gate/results.sarif')], qualityGates: []
  }
}
```

## Local demonstration

`scripts/gate-demo.sh` builds the tool and checks the whole contract without
sending a packet: r6 exits 1, r7 exits 0, the SARIF documents declare every rule
they cite, and both committed deliveries verify against
`trust/waf-effectiveness.pub`. It also runs inside `scripts/ci-local.sh` and the
active workflow, so the demonstration cannot rot silently.

What the demonstration does not prove: that r7's numbers describe any WAF other
than the repository's reference fixture, or that Code Scanning, GitLab, Azure or
Jenkins ingest the document — that ingestion is the consumer's own check.

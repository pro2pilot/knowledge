#!/usr/bin/env node
'use strict';

const fs = require('fs');
const crypto = require('crypto');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const {
  bindStepDecision,
  canonicalReleaseEnv,
  sourceBootstrapStep,
  validateFlowLogEvidence,
  satisfiedImpactGatesForMode
} = require('./release-gate');
const { classify } = require('./classify-release-impact');
const { evaluatePublicConsistency } = require('./check-public-consistency');
const { acquireTeamLock, teamLockStatus } = require('./lib/team-store');
const { gate00Result } = require('../benchmarks/run-benchmarks');
const {
  buildPackageEntries
} = require('./package-release');
const {
  matchesExpectedFailure
} = require('./conformance-install-smoke');
const {
  assertAcceptedGateReport,
  assertSourceBootstrapLogCorrelation,
  assertStepDecisionCorrelation,
  assertStepLogHash,
  assertSyntheticStepLogCorrelation,
  readStableRegularFile,
  sha256: evidenceSha256
} = require('./lib/release-step-evidence');
const {
  commitJsonTransaction,
  recoverTransactions,
  treeGuardHash
} = require('./lib/json-transaction');
const {
  __test: evidenceFinalizer
} = require(
  '../docs/release/3.3.0/finalize-evidence-pack'
);
const {
  UPDATER_EVIDENCE_PATHS,
  buildExactUpgradeProofAssertions,
  snapshotJsonEvidenceFile
} = require(
  '../docs/release/3.3.0/test-evidence/release-gates/capture-exact-upgrade'
);

const LEGACY_EXACT_UPGRADE_SCHEMA_VERSION = '3.2.11';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function main() {
  const canonicalGate = gate00Result({ status: 'pass', steps: [{ id: 'one' }] });
  const legacyGate = gate00Result({ status: 'passed', steps: [{ id: 'one' }] });
  assert(canonicalGate.status === 'pass' && canonicalGate.metrics.release_gate_passed === 1, 'GATE-00 did not accept canonical release status pass');
  assert(legacyGate.status === 'diagnostic' && legacyGate.metrics.release_gate_passed === 0, 'GATE-00 still accepts legacy status passed');
  const expectedFailurePayload = {
    status: 'error',
    code: 'EXPECTED_BLOCK'
  };
  assert(
    matchesExpectedFailure(
      { exit_code: 1 },
      expectedFailurePayload,
      'EXPECTED_BLOCK'
    ) &&
      !matchesExpectedFailure(
        { exit_code: null },
        expectedFailurePayload,
        'EXPECTED_BLOCK'
      ) &&
      !matchesExpectedFailure(
        { exit_code: 0 },
        expectedFailurePayload,
        'EXPECTED_BLOCK'
      ) &&
      !matchesExpectedFailure(
        { exit_code: '1' },
        expectedFailurePayload,
        'EXPECTED_BLOCK'
      ) &&
      !matchesExpectedFailure(
        { exit_code: 1 },
        expectedFailurePayload,
        'OTHER_BLOCK'
      ),
    'conformance expected-failure matcher accepted an absent, non-integer, zero, or mismatched exit'
  );
  const acceptedPlanFixture = {
    steps: [{ id: 'one' }]
  };
  const acceptedClosureFixture = {
    aggregate_sha256: 'a'.repeat(64)
  };
  const acceptedReportFixture = {
    schema_version: 'release-gate-report.v2',
    package_version: '3.3.0',
    status: 'pass',
    mode: 'full',
    failures: [],
    skipped: [],
    steps: [{
      id: 'one',
      status: 'pass',
      exit_code: 0,
      json_contract_errors: []
    }],
    producer_source_unchanged: true,
    step_plan: acceptedPlanFixture,
    producer_closure: acceptedClosureFixture,
    producer_closure_after_sha256:
      acceptedClosureFixture.aggregate_sha256
  };
  assertAcceptedGateReport(
    acceptedReportFixture,
    acceptedPlanFixture,
    acceptedClosureFixture
  );
  for (const tampered of [
    {
      ...acceptedReportFixture,
      failures: [{ id: 'one' }]
    },
    {
      ...acceptedReportFixture,
      skipped: [{ id: 'one' }]
    },
    {
      ...acceptedReportFixture,
      steps: [{
        ...acceptedReportFixture.steps[0],
        status: 'fail'
      }]
    },
    {
      ...acceptedReportFixture,
      steps: [{
        ...acceptedReportFixture.steps[0],
        exit_code: 2
      }]
    },
    {
      ...acceptedReportFixture,
      schema_version: 'release-gate-report.v1'
    },
    {
      ...acceptedReportFixture,
      package_version: '3.2.12'
    }
  ]) {
    let rejected = false;
    try {
      assertAcceptedGateReport(
        tampered,
        acceptedPlanFixture,
        acceptedClosureFixture
      );
    } catch {
      rejected = true;
    }
    assert(
      rejected,
      'accepted capture contract admitted a failed, skipped, nonzero, or unsupported report envelope'
    );
  }
  const acceptedIndexEnvelope = {
    schema_version:
      'knowledge-release-gate-evidence-index.v1',
    runs: []
  };
  const acceptedManifestEnvelope = {
    schema_version:
      'knowledge-evidence-manifest.v1',
    classification: 'accepted'
  };
  const acceptedCaptureEnvelope = {
    schema_version:
      'knowledge-release-gate-evidence.v1',
    classification: 'accepted'
  };
  evidenceFinalizer.assertFullGateEnvelopeSchemas(
    acceptedIndexEnvelope,
    acceptedManifestEnvelope,
    acceptedCaptureEnvelope
  );
  for (const [index, manifest, capture] of [
    [
      {
        ...acceptedIndexEnvelope,
        schema_version: 'legacy-index'
      },
      acceptedManifestEnvelope,
      acceptedCaptureEnvelope
    ],
    [
      acceptedIndexEnvelope,
      {
        ...acceptedManifestEnvelope,
        classification: 'rejected'
      },
      acceptedCaptureEnvelope
    ],
    [
      acceptedIndexEnvelope,
      acceptedManifestEnvelope,
      {
        ...acceptedCaptureEnvelope,
        schema_version: 'legacy-capture'
      }
    ]
  ]) {
    let rejected = false;
    try {
      evidenceFinalizer
        .assertFullGateEnvelopeSchemas(
          index,
          manifest,
          capture
        );
    } catch {
      rejected = true;
    }
    assert(
      rejected,
      'finalizer accepted an unsupported full-gate evidence envelope'
    );
  }
  const exactAssertions = Object.fromEntries(
    evidenceFinalizer.EXACT_UPGRADE_ASSERTION_KEYS.map((key) =>
      [key, true])
  );
  assert(
    evidenceFinalizer.exactTrueAssertions(exactAssertions),
    'exact-upgrade finalizer rejected the complete assertion set'
  );
  assert(
    !evidenceFinalizer.exactTrueAssertions({}) &&
      !evidenceFinalizer.exactTrueAssertions([]) &&
      !evidenceFinalizer.exactTrueAssertions({
        ...exactAssertions,
        extra: true
      }) &&
      !evidenceFinalizer.exactTrueAssertions({
        ...exactAssertions,
        [evidenceFinalizer.EXACT_UPGRADE_ASSERTION_KEYS[0]]: false
      }) &&
      !evidenceFinalizer.exactTrueAssertions(
        Object.fromEntries(
          Object.entries(exactAssertions).slice(1)
        )
      ),
    'exact-upgrade finalizer accepted an incomplete or widened assertion set'
  );
  const executableReleaseExtensions = new Set([
    '.js',
    '.cjs',
    '.mjs',
    '.ps1',
    '.vbs'
  ]);
  assert(
    Object.values(UPDATER_EVIDENCE_PATHS).length === 3 &&
      new Set(Object.values(UPDATER_EVIDENCE_PATHS)).size === 3 &&
      Object.values(UPDATER_EVIDENCE_PATHS).every(
        (relativePath) =>
          relativePath.startsWith('raw/updaters/') &&
          !executableReleaseExtensions.has(
            path.extname(relativePath).toLowerCase()
          )
      ),
    'exact-upgrade updater snapshots can enter the release producer closure'
  );
  const validOperatorCanary = {
    upgrade_preservation_probe: {
      source: 'public-3.2.11-exact-asset',
      expected: 'unchanged'
    }
  };
  assert(
    evidenceFinalizer.operatorProfileCanaryOk(
      validOperatorCanary
    ) &&
      !evidenceFinalizer.operatorProfileCanaryOk({}) &&
      !evidenceFinalizer.operatorProfileCanaryOk({
        upgrade_preservation_probe: {
          ...validOperatorCanary.upgrade_preservation_probe,
          extra: true
        }
      }) &&
      !evidenceFinalizer.operatorProfileCanaryOk({
        upgrade_preservation_probe: {
          source: 'public-3.2.11-exact-asset',
          expected: 'changed'
        }
      }) &&
      evidenceFinalizer.exactUpgradePathOk(
        '3.2.11 -> 3.3.0'
      ) &&
      !evidenceFinalizer.exactUpgradePathOk(
        '3.2.12 -> 3.3.0'
      ),
    'exact-upgrade preservation canary or public path failed open'
  );
  const makeRuntimeProof = (proofSource) => ({
    status: 'preserved',
    proof_source: proofSource,
    backup_path: 'bounded-backup-path',
    required_paths: [
      ...evidenceFinalizer.EXACT_RUNTIME_REQUIRED_PATHS
    ],
    paths:
      evidenceFinalizer.EXACT_RUNTIME_REQUIRED_PATHS
        .map((runtimePath) => ({
          path: runtimePath,
          backup_exists: false,
          current_exists: false,
          before_files: 0,
          after_files: 0,
          changed_files: [],
          removed_files: [],
          added_files: []
        })),
    changed_files: [],
    changed_files_count: 0,
    removed_files: [],
    removed_files_count: 0,
    added_files: [],
    added_files_count: 0,
    hash_set_unchanged: true,
    ...(proofSource === 'reconstructed_legacy_backup'
      ? {
          reconstructed_at:
            '2026-01-01T00:00:00.000Z',
          legacy_report_schema_version:
            LEGACY_EXACT_UPGRADE_SCHEMA_VERSION,
          legacy_report_phase: 'apply'
        }
      : {})
  });
  const reconstructedProof = makeRuntimeProof(
    'reconstructed_legacy_backup'
  );
  const revalidatedProof = makeRuntimeProof(
    'previous_update_report_revalidated'
  );
  const validProvenance = {
    schema_version:
      'knowledge-runtime-proof-provenance.v1',
    source: 'reconstructed_legacy_backup',
    reconstructed_at: '2026-01-01T00:00:01.000Z',
    apply_report_sha256_before_enrichment:
      'a'.repeat(64),
    backup_path: reconstructedProof.backup_path
  };
  const runtimeCheck = (source, revalidated) => ({
    check: 'runtime_evidence_preservation_proof',
    status: 'pass',
    proof_source: source,
    recovery_status: revalidated
      ? null
      : 'reconstructed',
    recovery_reason: null,
    validation_status: revalidated
      ? 'revalidated'
      : null,
    validation_reason: null,
    validation_errors: [],
    changed_files: 0,
    removed_files: 0,
    added_files: 0
  });
  const commandSemanticBase = {
    status: 'ok',
    source_version: '3.3.0',
    schema_version: '3.3.0',
    phase: 'verify_upgrade',
    mode: 'verify_upgrade',
    installed_version: '3.3.0'
  };
  const firstVerifySemantic = {
    ...commandSemanticBase,
    backup_path: reconstructedProof.backup_path,
    runtime_preservation_proof: reconstructedProof,
    verify: {
      runtime_preservation_proof: reconstructedProof,
      runtime_proof_source:
        'reconstructed_legacy_backup',
      runtime_proof_validation: null,
      legacy_recovery: {
        status: 'reconstructed',
        proof: reconstructedProof
      },
      checks: [
        runtimeCheck(
          'reconstructed_legacy_backup',
          false
        )
      ]
    }
  };
  const repeatVerifySemantic = {
    ...commandSemanticBase,
    backup_path: revalidatedProof.backup_path,
    runtime_preservation_proof: revalidatedProof,
    verify: {
      runtime_preservation_proof: revalidatedProof,
      runtime_proof_source:
        'previous_update_report_revalidated',
      runtime_proof_validation: {
        status: 'revalidated',
        reason: null,
        proof: revalidatedProof
      },
      legacy_recovery: null,
      checks: [
        runtimeCheck(
          'previous_update_report_revalidated',
          true
        )
      ]
    }
  };
  const persistedProofReport = {
    schema_version: LEGACY_EXACT_UPGRADE_SCHEMA_VERSION,
    status: 'ok',
    phase: 'apply',
    mode: 'apply',
    source_version: '3.3.0',
    installed_version: '3.3.0',
    backup_path: reconstructedProof.backup_path,
    runtime_preservation_proof: reconstructedProof,
    runtime_proof_provenance: validProvenance
  };
  assert(
    evidenceFinalizer.runtimePreservationProofOk(
      reconstructedProof,
      'reconstructed_legacy_backup'
    ) &&
      evidenceFinalizer.runtimePreservationProofOk(
        revalidatedProof,
        'previous_update_report_revalidated'
      ) &&
      evidenceFinalizer.persistedApplyReportOk(
        persistedProofReport,
        true,
        'a'.repeat(64)
      ) &&
      evidenceFinalizer.exactUpgradeCommandSemanticOk(
        '04-new-updater-verify',
        firstVerifySemantic
      ) &&
      evidenceFinalizer.exactUpgradeCommandSemanticOk(
        '05-new-updater-verify-repeat',
        repeatVerifySemantic
      ) &&
      !evidenceFinalizer.runtimePreservationProofOk(
        { ...reconstructedProof, status: 'unknown' },
        'reconstructed_legacy_backup'
      ) &&
      !evidenceFinalizer.runtimePreservationProofOk(
        {
          ...reconstructedProof,
          changed_files_count: 1
        },
        'reconstructed_legacy_backup'
      ) &&
      !evidenceFinalizer.runtimePreservationProofOk(
        {
          ...reconstructedProof,
          required_paths: [
            ...reconstructedProof.required_paths,
            reconstructedProof.required_paths[0]
          ]
        },
        'reconstructed_legacy_backup'
      ) &&
      !evidenceFinalizer.runtimePreservationProofOk(
        {
          ...reconstructedProof,
          paths: reconstructedProof.paths.map(
            (row, index) => index === 0
              ? {
                  ...row,
                  before_files: 1,
                  after_files: 1
                }
              : row
          )
        },
        'reconstructed_legacy_backup'
      ) &&
      !evidenceFinalizer.persistedApplyReportOk(
        {
          ...persistedProofReport,
          runtime_preservation_proof: {
            proof_source:
              'reconstructed_legacy_backup'
          }
        },
        true,
        'a'.repeat(64)
      ) &&
      !evidenceFinalizer.exactUpgradeCommandSemanticOk(
        '04-new-updater-verify',
        {
          ...firstVerifySemantic,
          runtime_preservation_proof: {
            ...reconstructedProof,
            removed_files: ['lost.json'],
            removed_files_count: 1
          }
        }
      ),
    'exact-upgrade runtime preservation proof failed open'
  );
  const applyWithoutProof = {
    schema_version: LEGACY_EXACT_UPGRADE_SCHEMA_VERSION,
    status: 'ok',
    phase: 'apply',
    mode: 'apply',
    source_version: '3.3.0',
    installed_version: '3.3.0',
    backup_path: reconstructedProof.backup_path
  };
  assert(
    evidenceFinalizer.exactRuntimeProofChainOk({
      firstVerify: firstVerifySemantic,
      repeatVerify: repeatVerifySemantic,
      afterApply: applyWithoutProof,
      afterFirst: persistedProofReport,
      afterRepeat: JSON.parse(
        JSON.stringify(persistedProofReport)
      ),
      afterApplySha: 'a'.repeat(64)
    }) &&
      !evidenceFinalizer.exactRuntimeProofChainOk({
        firstVerify: {
          ...firstVerifySemantic,
          backup_path: 'different-backup',
          runtime_preservation_proof: {
            ...reconstructedProof,
            backup_path: 'different-backup'
          }
        },
        repeatVerify: repeatVerifySemantic,
        afterApply: applyWithoutProof,
        afterFirst: persistedProofReport,
        afterRepeat: JSON.parse(
          JSON.stringify(persistedProofReport)
        ),
        afterApplySha: 'a'.repeat(64)
      }) &&
      !evidenceFinalizer.persistedApplyReportOk(
        {
          ...persistedProofReport,
          runtime_proof_provenance: {
            ...validProvenance,
            apply_report_sha256_before_enrichment:
              'b'.repeat(64)
          }
        },
        true,
        'a'.repeat(64)
      ),
    'exact-upgrade runtime proof artifacts are not cross-bound'
  );
  const captureProofFixture = {
    verifyParsed: firstVerifySemantic,
    verifyAgainParsed: repeatVerifySemantic,
    persistedAfterApply: applyWithoutProof,
    persistedAfterFirstVerify: persistedProofReport,
    persistedAfterRepeat: JSON.parse(
      JSON.stringify(persistedProofReport)
    ),
    persistedAfterApplySha: 'a'.repeat(64),
    persistedAfterFirstVerifySha: 'c'.repeat(64),
    persistedAfterRepeatSha: 'c'.repeat(64),
    persistedAfterApplyBindingSha: 'a'.repeat(64),
    persistedAfterFirstVerifyBindingSha: 'c'.repeat(64),
    persistedAfterRepeatBindingSha: 'c'.repeat(64)
  };
  const validCaptureProofAssertions =
    buildExactUpgradeProofAssertions(captureProofFixture);
  const repeatProofDifferentBackup = {
    ...revalidatedProof,
    backup_path: 'different-backup'
  };
  const repeatVerifyDifferentBackup = {
    ...repeatVerifySemantic,
    backup_path: 'different-backup',
    runtime_preservation_proof: repeatProofDifferentBackup,
    verify: {
      ...repeatVerifySemantic.verify,
      runtime_preservation_proof:
        repeatProofDifferentBackup,
      runtime_proof_validation: {
        ...repeatVerifySemantic.verify
          .runtime_proof_validation,
        proof: repeatProofDifferentBackup
      }
    }
  };
  const invalidCaptureProofFixtures = [
    {
      verifyParsed: {
        ...firstVerifySemantic,
        runtime_preservation_proof: {
          proof_source: 'reconstructed_legacy_backup'
        }
      }
    },
    {
      persistedAfterFirstVerify: {
        ...persistedProofReport,
        runtime_preservation_proof: {
          proof_source: 'reconstructed_legacy_backup'
        }
      }
    },
    {
      persistedAfterFirstVerify: {
        ...persistedProofReport,
        runtime_proof_provenance: {
          ...validProvenance,
          apply_report_sha256_before_enrichment:
            'b'.repeat(64)
        }
      }
    },
    {
      verifyAgainParsed: {
        ...repeatVerifySemantic,
        runtime_preservation_proof: {
          proof_source:
            'previous_update_report_revalidated'
        }
      }
    },
    {
      verifyAgainParsed: repeatVerifyDifferentBackup
    },
    {
      persistedAfterRepeat: {
        ...persistedProofReport,
        backup_path: 'different-backup'
      }
    }
  ];
  assert(
    Object.values(validCaptureProofAssertions)
      .every((value) => value === true) &&
      evidenceFinalizer.exactTrueAssertions({
        ...exactAssertions,
        ...validCaptureProofAssertions
      }) &&
      invalidCaptureProofFixtures.every((mutation) => {
        const assertions =
          buildExactUpgradeProofAssertions({
            ...captureProofFixture,
            ...mutation
          });
        return !evidenceFinalizer.exactTrueAssertions({
          ...exactAssertions,
          ...assertions
        });
      }),
    'standalone exact-upgrade capture proof wiring failed open'
  );
  const commandCwd = path.resolve('exact-upgrade-fixture', 'target');
  const commandState = {
    context: {
      cwd: commandCwd,
      candidate_knowledge: path.resolve(
        path.dirname(commandCwd),
        'candidate',
        '.knowledge'
      ),
      runtime: {
        node_executable: process.execPath,
        node_executable_sha256: sha256(
          fs.readFileSync(process.execPath)
        ),
        node_version: process.version,
        platform: process.platform,
        arch: process.arch
      }
    },
    updater_entrypoints: {
      old_3_2_11: { sha256: 'a'.repeat(64) },
      installed_3_3_0: { sha256: 'b'.repeat(64) }
    }
  };
  const commandResult = {
    schema_version: 'knowledge-evidenced-command.v1',
    label: '01-old-updater-dry-run',
    command: [
      process.execPath,
      path.join(
        commandCwd,
        '.knowledge',
        'tools',
        'update-system-files.js'
      ),
      '--from',
      commandState.context.candidate_knowledge,
      '--json',
      '--dry-run'
    ],
    cwd: commandCwd,
    entrypoint_sha256: 'a'.repeat(64),
    runtime: {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      exec_path: process.execPath,
      exec_sha256:
        commandState.context.runtime.node_executable_sha256
    },
    started_at: '2026-01-01T00:00:00.000Z',
    completed_at: '2026-01-01T00:00:00.125Z',
    duration_ms: 125
  };
  assert(
    evidenceFinalizer.exactCommandRecordOk(
      commandResult.label,
      commandResult,
      commandState
    ) &&
      !evidenceFinalizer.exactCommandRecordOk(
        commandResult.label,
        {
          ...commandResult,
          command: [
            ...commandResult.command.slice(0, -2),
            '--dry-run',
            '--json'
          ]
        },
        commandState
      ) &&
      !evidenceFinalizer.exactCommandRecordOk(
        commandResult.label,
        { ...commandResult, cwd: `${commandCwd}-other` },
        commandState
      ) &&
      !evidenceFinalizer.exactCommandRecordOk(
        commandResult.label,
        { ...commandResult, schema_version: 'legacy' },
        commandState
      ) &&
      !evidenceFinalizer.exactCommandRecordOk(
        commandResult.label,
        { ...commandResult, entrypoint_sha256: 'b'.repeat(64) },
        commandState
      ),
    'exact-upgrade command/cwd/entrypoint contract failed open'
  );

  const sourceKnowledgeRoot = path.resolve(__dirname, '..');
  const hostileTargetRoot = path.join(
    path.dirname(sourceKnowledgeRoot),
    'ambient-target'
  );
  const isolatedReleaseEnv = canonicalReleaseEnv(
    {
      KNOWLEDGE_AGENT_ID:
        'release-gate-source-bootstrap',
      KNOWLEDGE_TARGET_ROOT: hostileTargetRoot
    },
    {
      PATH: process.env.PATH,
      knowledge_mode: 'team',
      Knowledge_System_Root: hostileTargetRoot,
      knowledge_target_root: hostileTargetRoot,
      Knowledge_Project_Knowledge_Root:
        hostileTargetRoot,
      knowledge_state_root: path.join(
        hostileTargetRoot,
        'state'
      ),
      knowledge_team_root: path.join(
        hostileTargetRoot,
        'team'
      ),
      Knowledge_Workspace_Id: 'ambient-workspace',
      knowledge_repo_id: 'ambient-repo',
      Knowledge_Agent_Id: 'ambient-agent',
      knowledge_disable_git_discovery: '1',
      Knowledge_Flow_No_Open: '0',
      knowledge_inspector_no_open: '0',
      knowledge_spark_battle_report:
        path.join(hostileTargetRoot, 'spark.json'),
      Knowledge_Memory_Battle_Report:
        path.join(hostileTargetRoot, 'memory.json'),
      knowledge_memory_battle_max_age_hours: '999'
    }
  );
  assert(
    isolatedReleaseEnv.KNOWLEDGE_MODE === 'repo' &&
      path.resolve(
        isolatedReleaseEnv.KNOWLEDGE_SYSTEM_ROOT
      ) === sourceKnowledgeRoot &&
      path.resolve(
        isolatedReleaseEnv.KNOWLEDGE_TARGET_ROOT
      ) === path.dirname(sourceKnowledgeRoot) &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT'
      ) &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_STATE_ROOT'
      ) &&
      isolatedReleaseEnv.KNOWLEDGE_AGENT_ID ===
        'release-gate-source-bootstrap' &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_TEAM_ROOT'
      ) &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_WORKSPACE_ID'
      ) &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_REPO_ID'
      ) &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_SPARK_BATTLE_REPORT'
      ) &&
      !Object.hasOwn(
        isolatedReleaseEnv,
        'KNOWLEDGE_MEMORY_BATTLE_REPORT'
      ),
    'release-gate child environment accepted ambient identity, target, state, or optional-evidence overrides'
  );
  const controlledEnvironmentKeys = new Set([
    'KNOWLEDGE_MODE',
    'KNOWLEDGE_SYSTEM_ROOT',
    'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT',
    'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_AGENT_ID',
    'KNOWLEDGE_DISABLE_GIT_DISCOVERY',
    'KNOWLEDGE_FLOW_NO_OPEN',
    'KNOWLEDGE_INSPECTOR_NO_OPEN',
    'KNOWLEDGE_TEAM_ROOT',
    'KNOWLEDGE_WORKSPACE_ID',
    'KNOWLEDGE_REPO_ID',
    'KNOWLEDGE_SPARK_BATTLE_REPORT',
    'KNOWLEDGE_MEMORY_BATTLE_REPORT',
    'KNOWLEDGE_MEMORY_BATTLE_MAX_AGE_HOURS'
  ]);
  assert(
    Object.keys(isolatedReleaseEnv)
      .filter((key) =>
        controlledEnvironmentKeys.has(
          key.toUpperCase()
        )
      )
      .every((key) => key === key.toUpperCase()),
    'release-gate child environment retained a mixed-case alias for a controlled key'
  );
  const childEnvironmentProbe = spawnSync(
    process.execPath,
    [
      '-e',
      [
        `const {resolveKnowledgeContext}=require(${JSON.stringify(path.join(sourceKnowledgeRoot, 'tools', 'lib', 'path-context.js'))});`,
        'const context=resolveKnowledgeContext({__skipCli:true});',
        'process.stdout.write(JSON.stringify({',
        'mode:context.mode,',
        'target:context.targetRoot,',
        'project:context.projectKnowledgeRoot,',
        'state:context.stateRoot,',
        'agent:context.agentId,',
        'projectAlias:process.env.KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT||null,',
        'stateAlias:process.env.KNOWLEDGE_STATE_ROOT||null,',
        'team:process.env.KNOWLEDGE_TEAM_ROOT||null,',
        'workspace:process.env.KNOWLEDGE_WORKSPACE_ID||null,',
        'repo:process.env.KNOWLEDGE_REPO_ID||null,',
        'spark:process.env.KNOWLEDGE_SPARK_BATTLE_REPORT||null,',
        'memory:process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT||null',
        '}));'
      ].join('')
    ],
    {
      env: isolatedReleaseEnv,
      encoding: 'utf8',
      windowsHide: true,
      timeout: 30000
    }
  );
  const childEnvironment = JSON.parse(
    String(childEnvironmentProbe.stdout || '{}')
  );
  assert(
    childEnvironmentProbe.status === 0 &&
      childEnvironment.mode === 'repo' &&
      path.resolve(childEnvironment.target) ===
        path.dirname(sourceKnowledgeRoot) &&
      path.resolve(childEnvironment.state) ===
        sourceKnowledgeRoot &&
      path.resolve(childEnvironment.project) ===
        sourceKnowledgeRoot &&
      childEnvironment.agent ===
        'release-gate-source-bootstrap' &&
      childEnvironment.projectAlias === null &&
      childEnvironment.stateAlias === null &&
      childEnvironment.team === null &&
      childEnvironment.workspace === null &&
      childEnvironment.repo === null &&
      childEnvironment.spark === null &&
      childEnvironment.memory === null,
    `spawned release child observed a case-aliased ambient override: ${childEnvironmentProbe.stderr || childEnvironmentProbe.stdout}`
  );
  const currentConsistency = evaluatePublicConsistency(sourceKnowledgeRoot);
  assert(currentConsistency.status === 'pass', `current public copy is inconsistent: ${currentConsistency.errors.join('; ')}`);

  const docsImpact = classify(['README.md'], { classificationComplete: true });
  assert(
    docsImpact.mode === 'quick'
      && docsImpact.required_gates.includes('public-consistency')
      && !docsImpact.required_gates.includes('full'),
    `documentation impact was routed incorrectly: ${JSON.stringify(docsImpact)}`
  );
  const releaseInfrastructureImpact = classify(['tools/check-public-consistency.js'], { classificationComplete: true });
  assert(
    releaseInfrastructureImpact.mode === 'full'
      && releaseInfrastructureImpact.required_gates.includes('full')
      && releaseInfrastructureImpact.required_gates.includes('conformance-suite'),
    `release infrastructure impact was routed incorrectly: ${JSON.stringify(releaseInfrastructureImpact)}`
  );

  const quickCapabilities = satisfiedImpactGatesForMode('quick');
  const fullCapabilities = satisfiedImpactGatesForMode('full');
  assert(
    quickCapabilities.has('quick')
      && quickCapabilities.has('public-consistency')
      && !quickCapabilities.has('full')
      && fullCapabilities.has('full')
      && fullCapabilities.has('conformance-suite')
      && !fullCapabilities.has('unknown-gate'),
    'release-gate mode capability mapping does not fail closed'
  );

  const prWorkflow = fs.readFileSync(path.join(sourceKnowledgeRoot, '.github', 'workflows', 'pr-fast.yml'), 'utf8');
  assert(
    /RELEASE_GATE_MODE:\s*\$\{\{\s*needs\.classify\.outputs\.mode\s*\}\}/.test(prWorkflow),
    'PR Fast workflow does not consume the classifier mode'
  );
  assert(
    /release-gate\.js\s+--mode\s+["']?\$RELEASE_GATE_MODE["']?/.test(prWorkflow)
      && !/release-gate\.js\s+--mode\s+quick\b/.test(prWorkflow),
    'PR Fast workflow still hard-codes quick instead of running the classified mode'
  );
  assert(
    (prWorkflow.match(/fetch-depth:\s*0/g) || []).length === 2,
    'PR Fast routed job lacks full git history for its in-gate impact classifier'
  );
  const compatibilityWorkflow = fs.readFileSync(
    path.join(sourceKnowledgeRoot, '.github', 'workflows', 'compatibility-gate.yml'),
    'utf8'
  );
  assert(
    compatibilityWorkflow.includes("'.github/workflows/**'")
      && compatibilityWorkflow.includes("'internal/**'"),
    'compatibility workflow does not trigger for workflow/internal release-infrastructure changes'
  );
  const preferredTempBase = process.env.KNOWLEDGE_TEST_TMP_ROOT
    || (process.platform === 'win32' && fs.existsSync('C:\\tmp') ? 'C:\\tmp' : os.tmpdir());
  let fixtureRoot;
  try {
    fixtureRoot = fs.mkdtempSync(path.join(preferredTempBase, 'knowledge-release-gate-p0-'));
  } catch (error) {
    if (preferredTempBase === os.tmpdir() || !['EACCES', 'EPERM'].includes(error.code)) throw error;
    fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-release-gate-p0-'));
  }
  try {
    const bootstrapStdoutBody = Buffer.from(
      JSON.stringify({
        status: 'pass',
        bootstrap_action: 'noop',
        project_index_path: 'project_index.json',
        errors: []
      }, null, 2) + '\n',
      'utf8'
    );
    const bootstrapStderrBody = Buffer.from('', 'utf8');
    const bootstrapStep = {
      id: 'source-bootstrap',
      status: 'pass',
      json_status: 'pass',
      bootstrap_action: 'noop',
      project_index_path: 'project_index.json',
      json_contract_errors: [],
      stdout_sha256: evidenceSha256(bootstrapStdoutBody),
      stderr_sha256: evidenceSha256(bootstrapStderrBody)
    };
    assertStepLogHash(
      bootstrapStep,
      'stdout',
      bootstrapStdoutBody
    );
    assertStepLogHash(
      bootstrapStep,
      'stderr',
      bootstrapStderrBody
    );
    assertSourceBootstrapLogCorrelation(
      bootstrapStep,
      bootstrapStdoutBody,
      bootstrapStderrBody
    );
    const ingestPayload = {
      generated_at: '2026-01-01T00:00:00.000Z',
      modules_detected: 1,
      modules_total: 1,
      ignored_source_checkouts: [],
      technologies: [],
      root_module: true,
      mode: 'merge',
      routing_bundle: null,
      search_documents: null,
      auto_track: {
        enabled: false,
        limit: 25,
        added: 0,
        considered: 0,
        capped: false,
        tracked_total: 0
      }
    };
    const ingestStdoutBody = Buffer.from(
      `${JSON.stringify(ingestPayload)}\n`,
      'utf8'
    );
    const ingestStep = {
      id: 'source-bootstrap',
      status: 'pass',
      exit_code: 0,
      json_status: null,
      bootstrap_action: 'ingest',
      project_index_path: 'project_index.json',
      json_contract_errors: []
    };
    assertSourceBootstrapLogCorrelation(
      ingestStep,
      ingestStdoutBody,
      bootstrapStderrBody
    );
    const decisionLogDir = path.join(
      fixtureRoot,
      'step-decisions'
    );
    const failedIngestStep = {
      ...ingestStep,
      status: 'fail',
      exit_code: 2,
      json_contract_errors: [
        'source bootstrap project_index.json is invalid'
      ],
      stdout_path: 'logs/source-bootstrap.stdout.txt',
      stderr_path: 'logs/source-bootstrap.stderr.txt',
      stdout_sha256: evidenceSha256(ingestStdoutBody),
      stderr_sha256: evidenceSha256(bootstrapStderrBody),
      stdout_tail: ingestStdoutBody.toString('utf8'),
      stderr_tail: ''
    };
    assertSourceBootstrapLogCorrelation(
      failedIngestStep,
      Buffer.from('producer failed before JSON\n', 'utf8'),
      bootstrapStderrBody
    );
    let forgedFailedIngestRejected = false;
    try {
      assertSourceBootstrapLogCorrelation(
        {
          ...failedIngestStep,
          exit_code: 0
        },
        Buffer.from(
          'producer failed before JSON\n',
          'utf8'
        ),
        bootstrapStderrBody
      );
    } catch {
      forgedFailedIngestRejected = true;
    }
    const decisionBoundIngest = bindStepDecision(
      failedIngestStep,
      { logDir: decisionLogDir }
    );
    const decisionBody = readStableRegularFile(
      path.join(
        decisionLogDir,
        'source-bootstrap.decision.json'
      )
    );
    assertStepLogHash(
      decisionBoundIngest,
      'decision',
      decisionBody
    );
    assertStepDecisionCorrelation(
      decisionBoundIngest,
      decisionBody
    );
    let promotedIngestDecisionRejected = false;
    try {
      assertStepDecisionCorrelation(
        {
          ...decisionBoundIngest,
          status: 'pass',
          exit_code: 0,
          json_contract_errors: []
        },
        decisionBody
      );
    } catch {
      promotedIngestDecisionRejected = true;
    }
    const syntheticSemanticStep = {
      id: 'memory-battle-report',
      name: 'synthetic decision fixture',
      command: '<validate supplied report>',
      status: 'pass',
      exit_code: 0,
      duration_ms: 1,
      json_status: 'pass',
      json_contract_errors: [],
      report_file: 'fixture.json',
      report_sha256: 'a'.repeat(64)
    };
    const syntheticStdoutBody = Buffer.from(
      `${JSON.stringify({
        schema_version:
          'release-gate-validator-step-stream.v1',
        step: syntheticSemanticStep
      }, null, 2)}\n`,
      'utf8'
    );
    const syntheticStep = {
      ...syntheticSemanticStep,
      stdout_path: 'logs/memory-battle-report.stdout.txt',
      stderr_path: 'logs/memory-battle-report.stderr.txt',
      stdout_sha256: evidenceSha256(
        syntheticStdoutBody
      ),
      stderr_sha256: evidenceSha256(
        bootstrapStderrBody
      ),
      stdout_tail: syntheticStdoutBody
        .toString('utf8')
        .slice(-3000),
      stderr_tail: ''
    };
    assertSyntheticStepLogCorrelation(
      syntheticStep,
      syntheticStdoutBody,
      bootstrapStderrBody
    );
    let syntheticReportTamperRejected = false;
    try {
      assertSyntheticStepLogCorrelation(
        {
          ...syntheticStep,
          report_sha256: 'b'.repeat(64)
        },
        syntheticStdoutBody,
        bootstrapStderrBody
      );
    } catch {
      syntheticReportTamperRejected = true;
    }
    let emptyIngestRejected = false;
    try {
      assertSourceBootstrapLogCorrelation(
        ingestStep,
        Buffer.from('{}\n', 'utf8'),
        bootstrapStderrBody
      );
    } catch {
      emptyIngestRejected = true;
    }
    let forgedIngestRejected = false;
    try {
      assertSourceBootstrapLogCorrelation(
        ingestStep,
        Buffer.from(
          `${JSON.stringify({
            ...ingestPayload,
            status: 'pass'
          })}\n`,
          'utf8'
        ),
        bootstrapStderrBody
      );
    } catch {
      forgedIngestRejected = true;
    }
    let bootstrapHashTamperRejected = false;
    try {
      assertStepLogHash(
        bootstrapStep,
        'stdout',
        Buffer.from(
          bootstrapStdoutBody.toString('utf8')
            .replace('"pass"', '"fail"'),
          'utf8'
        )
      );
    } catch {
      bootstrapHashTamperRejected = true;
    }
    let bootstrapSemanticTamperRejected = false;
    try {
      const tamperedStep = {
        ...bootstrapStep,
        stdout_sha256: evidenceSha256(
          Buffer.from(
            bootstrapStdoutBody.toString('utf8')
              .replace('"pass"', '"fail"'),
            'utf8'
          )
        )
      };
      assertSourceBootstrapLogCorrelation(
        tamperedStep,
        Buffer.from(
          bootstrapStdoutBody.toString('utf8')
            .replace('"pass"', '"fail"'),
          'utf8'
        ),
        bootstrapStderrBody
      );
    } catch {
      bootstrapSemanticTamperRejected = true;
    }
    const stableLogPath = path.join(
      fixtureRoot,
      'stable-step.log'
    );
    const stableLogAlias = path.join(
      fixtureRoot,
      'stable-step-alias.log'
    );
    fs.writeFileSync(stableLogPath, bootstrapStdoutBody);
    assert(
      readStableRegularFile(stableLogPath)
        .equals(bootstrapStdoutBody),
      'stable step-log reader changed physical bytes'
    );
    fs.linkSync(stableLogPath, stableLogAlias);
    let multiplyLinkedLogRejected = false;
    try {
      readStableRegularFile(stableLogPath);
    } catch {
      multiplyLinkedLogRejected = true;
    }
    fs.unlinkSync(stableLogAlias);
    assert(
      bootstrapHashTamperRejected &&
        bootstrapSemanticTamperRejected &&
        multiplyLinkedLogRejected &&
        emptyIngestRejected &&
        forgedIngestRejected &&
        forgedFailedIngestRejected &&
        promotedIngestDecisionRejected &&
        syntheticReportTamperRejected,
      'release step-log evidence accepted hash, semantic, or physical alias tampering'
    );
    const snapshotSource = path.join(
      fixtureRoot,
      'persisted-source.json'
    );
    const snapshotEvidenceRoot = path.join(
      fixtureRoot,
      'persisted-snapshots'
    );
    fs.writeFileSync(
      snapshotSource,
      '{"state":"old"}\n',
      'utf8'
    );
    const stableSnapshot = snapshotJsonEvidenceFile(
      snapshotSource,
      snapshotEvidenceRoot,
      'raw/state/report.json'
    );
    fs.writeFileSync(
      snapshotSource,
      '{"state":"new"}\n',
      'utf8'
    );
    const stableSnapshotBody = fs.readFileSync(
      path.join(
        snapshotEvidenceRoot,
        'raw',
        'state',
        'report.json'
      ),
      'utf8'
    );
    assert(
      stableSnapshot.value.state === 'old' &&
        stableSnapshot.binding.sha256 ===
          stableSnapshot.sha256 &&
        stableSnapshot.binding.bytes ===
          Buffer.byteLength(stableSnapshotBody) &&
        JSON.parse(stableSnapshotBody).state === 'old',
      'persisted JSON parsing and evidence binding did not use one byte snapshot'
    );
    const publicationRoot = path.join(
      fixtureRoot,
      'evidence-publication'
    );
    fs.mkdirSync(publicationRoot, { recursive: true });
    const publicationPack = path.join(
      publicationRoot,
      'evidence-pack.json'
    );
    const publicationManifest = path.join(
      publicationRoot,
      'evidence-pack-manifest.json'
    );
    const publicationGuard = path.join(
      publicationRoot,
      'producer.js'
    );
    const oldPack = '{"state":"old-pack"}\n';
    const oldManifest = '{"state":"old-manifest"}\n';
    fs.writeFileSync(publicationPack, oldPack, 'utf8');
    fs.writeFileSync(publicationManifest, oldManifest, 'utf8');
    fs.writeFileSync(publicationGuard, 'old-producer\n', 'utf8');
    const staleGuardSha = sha256(
      fs.readFileSync(publicationGuard)
    );
    fs.writeFileSync(publicationGuard, 'new-producer\n', 'utf8');
    let driftCode = null;
    try {
      evidenceFinalizer.commitEvidencePublication({
        stateRoot: publicationRoot,
        containmentRoot: publicationRoot,
        transactionId: 'evidence-publication-guard-drift',
        writes: [
          { path: publicationPack, value: { state: 'new-pack' } },
          {
            path: publicationManifest,
            value: { state: 'new-manifest' }
          }
        ],
        guards: [{
          path: publicationGuard,
          containmentRoot: publicationRoot,
          expected_sha256: staleGuardSha
        }]
      });
    } catch (error) {
      driftCode = error.code || error.message;
    }
    assert(
      driftCode === 'transaction_guard_drift' &&
        fs.readFileSync(publicationPack, 'utf8') === oldPack &&
        fs.readFileSync(publicationManifest, 'utf8') ===
          oldManifest,
      'producer drift published a partial or accepted-looking evidence pair'
    );
    const freshGuardSha = sha256(
      fs.readFileSync(publicationGuard)
    );
    const publication = evidenceFinalizer
      .commitEvidencePublication({
        stateRoot: publicationRoot,
        containmentRoot: publicationRoot,
        transactionId: 'evidence-publication-success',
        writes: [
          { path: publicationPack, value: { state: 'new-pack' } },
          {
            path: publicationManifest,
            value: { state: 'new-manifest' }
          }
        ],
        guards: [{
          path: publicationGuard,
          containmentRoot: publicationRoot,
          expected_sha256: freshGuardSha
        }]
      });
    assert(
      publication.status === 'committed' &&
        JSON.parse(fs.readFileSync(
          publicationPack,
          'utf8'
        )).state === 'new-pack' &&
        JSON.parse(fs.readFileSync(
          publicationManifest,
          'utf8'
        )).state === 'new-manifest',
      'evidence publication transaction did not commit an all-new pair'
    );
    const publicationTreeRoot = path.join(
      fixtureRoot,
      'evidence-publication-tree'
    );
    fs.mkdirSync(publicationTreeRoot, { recursive: true });
    const treePack = path.join(
      publicationTreeRoot,
      'evidence-pack.json'
    );
    const treeManifest = path.join(
      publicationTreeRoot,
      'evidence-pack-manifest.json'
    );
    const treeProducer = path.join(
      publicationTreeRoot,
      'producer.js'
    );
    const treeAddition = path.join(
      publicationTreeRoot,
      'late-producer.js'
    );
    const treeOldPack = '{"state":"tree-old-pack"}\n';
    const treeOldManifest =
      '{"state":"tree-old-manifest"}\n';
    const treeExclusions = [
      'maintenance/transactions',
      'evidence-pack.json',
      'evidence-pack-manifest.json'
    ];
    fs.writeFileSync(treePack, treeOldPack, 'utf8');
    fs.writeFileSync(
      treeManifest,
      treeOldManifest,
      'utf8'
    );
    fs.writeFileSync(treeProducer, 'producer-v1\n', 'utf8');
    const publicationTreeSha = treeGuardHash(
      publicationTreeRoot,
      treeExclusions
    );
    fs.writeFileSync(
      treeAddition,
      'late-producer-v1\n',
      'utf8'
    );
    let treeAdditionDriftCode = null;
    try {
      evidenceFinalizer.commitEvidencePublication({
        stateRoot: publicationTreeRoot,
        containmentRoot: publicationTreeRoot,
        transactionId:
          'evidence-publication-tree-addition',
        writes: [
          {
            path: treePack,
            value: { state: 'tree-new-pack' }
          },
          {
            path: treeManifest,
            value: { state: 'tree-new-manifest' }
          }
        ],
        guards: [{
          kind: 'tree',
          path: publicationTreeRoot,
          containmentRoot: publicationTreeRoot,
          expected_sha256: publicationTreeSha,
          excluded_paths: treeExclusions
        }]
      });
    } catch (error) {
      treeAdditionDriftCode = error.code || error.message;
    }
    assert(
      treeAdditionDriftCode ===
        'transaction_guard_drift' &&
        fs.readFileSync(treePack, 'utf8') ===
          treeOldPack &&
        fs.readFileSync(treeManifest, 'utf8') ===
          treeOldManifest,
      'a late package-tree addition was not rejected all-old'
    );
    fs.unlinkSync(treeAddition);
    const recoveryTreeSha = treeGuardHash(
      publicationTreeRoot,
      treeExclusions
    );
    let partialTreeFault = null;
    try {
      commitJsonTransaction({
        stateRoot: publicationTreeRoot,
        transactionId:
          'evidence-publication-tree-recovery',
        writes: [
          {
            path: treePack,
            value: { state: 'tree-partial-pack' }
          },
          {
            path: treeManifest,
            value: { state: 'tree-partial-manifest' }
          }
        ],
        guards: [{
          kind: 'tree',
          path: publicationTreeRoot,
          containmentRoot: publicationTreeRoot,
          expected_sha256: recoveryTreeSha,
          excluded_paths: treeExclusions
        }],
        faultAt: 'after_promote_0'
      });
    } catch (error) {
      partialTreeFault = error.code || error.message;
    }
    assert(
      partialTreeFault === 'transaction_fault_injected',
      'tree-guard recovery fixture did not stop after a partial promote'
    );
    fs.writeFileSync(
      treeAddition,
      'late-during-recovery\n',
      'utf8'
    );
    const treeRecovery = recoverTransactions(
      publicationTreeRoot
    );
    assert(
      treeRecovery.some((item) =>
        item.transaction_id ===
          'evidence-publication-tree-recovery' &&
        item.status === 'guard_failed') &&
        fs.readFileSync(treePack, 'utf8') ===
          treeOldPack &&
        fs.readFileSync(treeManifest, 'utf8') ===
          treeOldManifest,
      'post-intent tree drift was not recovered to all-old'
    );
    fs.writeFileSync(publicationPack, oldPack, 'utf8');
    fs.writeFileSync(
      publicationManifest,
      oldManifest,
      'utf8'
    );
    let preIntentFault = null;
    try {
      evidenceFinalizer.commitEvidencePublication({
        stateRoot: publicationRoot,
        containmentRoot: publicationRoot,
        transactionId:
          'evidence-publication-pre-intent-fault',
        writes: [
          {
            path: publicationPack,
            value: { state: 'pre-intent-new-pack' }
          },
          {
            path: publicationManifest,
            value: { state: 'pre-intent-new-manifest' }
          }
        ],
        guards: [],
        faultAt: 'after_stage_0'
      });
    } catch (error) {
      preIntentFault = error.message;
    }
    assert(
      /Injected transaction fault/.test(
        String(preIntentFault)
      ) &&
        fs.readFileSync(publicationPack, 'utf8') ===
          oldPack &&
        fs.readFileSync(publicationManifest, 'utf8') ===
          oldManifest,
      'pre-intent evidence publication fault was not recovered to all-old'
    );
    let postIntentFault = null;
    try {
      evidenceFinalizer.commitEvidencePublication({
        stateRoot: publicationRoot,
        containmentRoot: publicationRoot,
        transactionId:
          'evidence-publication-post-intent-fault',
        writes: [
          {
            path: publicationPack,
            value: { state: 'post-intent-new-pack' }
          },
          {
            path: publicationManifest,
            value: { state: 'post-intent-new-manifest' }
          }
        ],
        guards: [],
        faultAt: 'after_promote_0'
      });
    } catch (error) {
      postIntentFault = error.message;
    }
    assert(
      /Injected transaction fault/.test(
        String(postIntentFault)
      ) &&
        JSON.parse(fs.readFileSync(
          publicationPack,
          'utf8'
        )).state === 'post-intent-new-pack' &&
        JSON.parse(fs.readFileSync(
          publicationManifest,
          'utf8'
        )).state === 'post-intent-new-manifest',
      'post-intent evidence publication fault was not recovered to all-new'
    );
    const publicationLock = path.join(
      publicationRoot,
      'publisher.lock'
    );
    const containedPublicationLock = path.join(
      publicationRoot,
      'locks',
      'v1',
      'evidence-publication.lock'
    );
    let publicationLockObserved = false;
    let secondPublisherTimedOut = false;
    evidenceFinalizer.withEvidencePublicationLock(
      () => {
        publicationLockObserved =
          fs.existsSync(containedPublicationLock);
        try {
          evidenceFinalizer.withEvidencePublicationLock(
            () => {},
            publicationLock,
            {
              timeoutMs: 20,
              retryMs: 2,
              staleMs: 60_000
            }
          );
        } catch (error) {
          secondPublisherTimedOut =
            error.code === 'lock_timeout';
        }
      },
      publicationLock
    );
    assert(
      publicationLockObserved &&
        secondPublisherTimedOut &&
        !fs.existsSync(containedPublicationLock),
      'evidence publication lock did not serialize writers'
    );
    let publicationLockPackageLeaks = [];
    evidenceFinalizer.withEvidencePublicationLock(() => {
      publicationLockPackageLeaks =
        buildPackageEntries(sourceKnowledgeRoot).entries
          .filter((entry) =>
            entry.name.includes(
              'maintenance/evidence-publication/'
            ))
          .map((entry) => entry.name);
    });
    assert(
      publicationLockPackageLeaks.length === 0,
      `evidence publication lock entered package closure: ${publicationLockPackageLeaks.join(', ')}`
    );
    const projectRoot = path.join(fixtureRoot, 'project');
    const knowledgeRoot = path.join(projectRoot, '.knowledge');
    const logDir = path.join(fixtureRoot, 'logs');
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.cpSync(sourceKnowledgeRoot, knowledgeRoot, {
      recursive: true,
      filter: (sourcePath) => {
        const relative = path.relative(sourceKnowledgeRoot, sourcePath).replace(/\\/g, '/');
        return !relative.startsWith('.qa-tmp/') && !relative.startsWith('dist/');
      }
    });
    fs.rmSync(path.join(knowledgeRoot, 'project_index.json'), { force: true });

    const first = sourceBootstrapStep(
      { logDir },
      {
        knowledgeRoot,
        projectRoot,
        ingestPath: path.join(knowledgeRoot, 'tools', 'ingest-existing-project.js')
      }
    );
    assert(first.status === 'pass', `real source bootstrap failed: ${(first.json_contract_errors || []).join('; ')}`);
    assert(first.bootstrap_action === 'ingest', 'clean source bootstrap did not run ingest');

    const projectIndexPath = path.join(knowledgeRoot, 'project_index.json');
    assert(fs.existsSync(projectIndexPath), 'real source bootstrap did not create project_index.json');
    const projectIndex = JSON.parse(fs.readFileSync(projectIndexPath, 'utf8'));
    assert(projectIndex.generated_by === 'release-gate-source-bootstrap', 'source bootstrap did not use the stable release-gate agent id');

    const doctor = spawnSync(process.execPath, [path.join(knowledgeRoot, 'tools', 'doctor.js'), '--json'], {
      cwd: projectRoot,
      env: canonicalReleaseEnv(
        { KNOWLEDGE_AGENT_ID: 'release-gate-source-bootstrap' },
        process.env,
        {
          knowledgeRoot,
          targetRoot: projectRoot,
          systemRoot: knowledgeRoot
        }
      ),
      encoding: 'utf8',
      windowsHide: true,
      timeout: 120000
    });
    assert(doctor.status === 0, `doctor failed after source bootstrap: ${doctor.stderr || doctor.stdout}`);
    const doctorReport = JSON.parse(String(doctor.stdout || '').trim());
    const doctorIssues = Array.isArray(doctorReport.issues) ? doctorReport.issues : [];
    assert(!['broken', 'fail', 'failed', 'error'].includes(String(doctorReport.status || '')), `doctor broke after bootstrap: ${doctorReport.status}`);
    assert(
      !doctorIssues.some((issue) => /project_index/i.test(`${issue.code || ''} ${issue.message || ''} ${issue.artifact || ''}`)),
      `doctor still reports a project_index defect after bootstrap: ${JSON.stringify(doctorIssues)}`
    );

    const second = sourceBootstrapStep(
      { logDir },
      {
        knowledgeRoot,
        projectRoot,
        ingestPath: path.join(knowledgeRoot, 'tools', 'ingest-existing-project.js')
      }
    );
    assert(second.status === 'pass', `source bootstrap noop failed: ${(second.json_contract_errors || []).join('; ')}`);
    assert(second.bootstrap_action === 'noop', 'existing project_index.json did not produce a noop');

    const stateRoot = path.join(projectRoot, '.knowledge-state');
    const flowLogRoot = path.join(stateRoot, 'maintenance', 'flow-logs');
    const flowLogPath = path.join(flowLogRoot, 'doctor-fixture.json');
    fs.mkdirSync(flowLogRoot, { recursive: true });
    const flowPayload = {
      flow: 'doctor',
      context: {
        mode: 'repo',
        systemRoot: stateRoot,
        targetRoot: projectRoot,
        projectKnowledgeRoot: stateRoot,
        stateRoot
      },
      started_at: '2026-07-28T00:00:00.000Z',
      duration_total_ms: 42,
      steps_total: 1,
      steps_ok: 1,
      overall_status: 'ok',
      steps: [{
        step: 'doctor',
        command: 'doctor.js',
        exit: 0,
        success: true,
        status: 'pass',
        json_status: 'pass',
        semantic_errors: [],
        duration_ms: 42,
        parsed: {
          status: 'pass',
          detail: 'alpha'
        },
        stdout:
          '{"status":"pass","detail":"alpha"}',
        stderr: ''
      }]
    };
    fs.writeFileSync(flowLogPath, JSON.stringify(flowPayload, null, 2) + '\n', 'utf8');
    const flowLogFixtureBody =
      fs.readFileSync(flowLogPath);
    const flowOutput = {
      ...flowPayload,
      steps: flowPayload.steps.map((step) => ({
        step: step.step,
        command: step.command,
        exit: step.exit,
        success: step.success,
        status: step.status,
        json_status: step.json_status,
        semantic_errors: step.semantic_errors,
        duration_ms: step.duration_ms
      })),
      status: 'ok',
      mode: 'repo',
      target_root: projectRoot,
      project_knowledge_root: stateRoot,
      state_root: stateRoot,
      flow_log: path.relative(projectRoot, flowLogPath).replace(/\\/g, '/'),
      flow_log_bytes: flowLogFixtureBody.length,
      flow_log_sha256:
        evidenceSha256(flowLogFixtureBody),
      flow_log_status: 'written'
    };
    const validFlowErrors = [];
    const flowLogBinding =
      validateFlowLogEvidence(
        flowOutput,
        validFlowErrors,
        {
          expectedMode: 'repo',
          expectedTargetRoot: projectRoot,
          expectedProjectKnowledgeRoot: stateRoot,
          expectedStateRoot: stateRoot,
          expectedSystemRoot: stateRoot
        }
      );
    assert(
      validFlowErrors.length === 0 &&
        flowLogBinding?.bytes ===
          fs.readFileSync(flowLogPath).length &&
        flowLogBinding?.sha256 ===
          evidenceSha256(
            fs.readFileSync(flowLogPath)
          ),
      `release gate rejected or failed to bind correlated flow log evidence: ${validFlowErrors.join('; ')}`
    );
    const tamperedFlowErrors = [];
    validateFlowLogEvidence({ ...flowOutput, started_at: '2000-01-01T00:00:00.000Z' }, tamperedFlowErrors);
    assert(tamperedFlowErrors.some((error) => /started_at/.test(error)), 'release gate accepted a tampered flow log correlation field');
    const wrongRootErrors = [];
    validateFlowLogEvidence(
      flowOutput,
      wrongRootErrors,
      {
        expectedTargetRoot: path.join(
          projectRoot,
          'wrong-target'
        ),
        expectedStateRoot: stateRoot
      }
    );
    assert(
      wrongRootErrors.some(
        (error) => /target_root/.test(error)
      ),
      'release gate accepted flow evidence from another target root'
    );
    const tamperedContextPayload = {
      ...flowPayload,
      context: {
        ...flowPayload.context,
        targetRoot: path.join(
          projectRoot,
          'wrong-target'
        )
      }
    };
    fs.writeFileSync(
      flowLogPath,
      JSON.stringify(
        tamperedContextPayload,
        null,
        2
      ) + '\n',
      'utf8'
    );
    const tamperedContextErrors = [];
    validateFlowLogEvidence(
      flowOutput,
      tamperedContextErrors
    );
    assert(
      tamperedContextErrors.some(
        (error) => /context targetRoot/.test(error)
      ),
      'release gate accepted a flow log whose persisted context targeted another project'
    );
    fs.writeFileSync(
      flowLogPath,
      JSON.stringify(flowPayload, null, 2) + '\n',
      'utf8'
    );
    const tamperedSupportingPayload = {
      ...flowPayload,
      steps: [{
        ...flowPayload.steps[0],
        parsed: {
          ...flowPayload.steps[0].parsed,
          detail: 'bravo'
        },
        stdout:
          '{"status":"pass","detail":"bravo"}'
      }]
    };
    fs.writeFileSync(
      flowLogPath,
      JSON.stringify(
        tamperedSupportingPayload,
        null,
        2
      ) + '\n',
      'utf8'
    );
    const tamperedSupportingErrors = [];
    validateFlowLogEvidence(
      flowOutput,
      tamperedSupportingErrors
    );
    assert(
      tamperedSupportingErrors.some(
        (error) => /SHA-256/.test(error)
      ),
      'release gate accepted substituted persisted-only flow details after child readback'
    );
    fs.writeFileSync(
      flowLogPath,
      JSON.stringify(flowPayload, null, 2) + '\n',
      'utf8'
    );
    const tamperedStepPayload = {
      ...flowPayload,
      steps: [{
        ...flowPayload.steps[0],
        exit: 1,
        success: false,
        status: 'fail'
      }]
    };
    fs.writeFileSync(
      flowLogPath,
      JSON.stringify(tamperedStepPayload, null, 2) + '\n',
      'utf8'
    );
    const tamperedStepErrors = [];
    validateFlowLogEvidence(
      flowOutput,
      tamperedStepErrors
    );
    assert(
      tamperedStepErrors.some(
        (error) =>
          /persisted semantic failure|step outcomes|steps\[0\]/.test(
            error
          )
      ),
      'release gate accepted a substituted nested flow step with unchanged aggregates'
    );
    fs.writeFileSync(
      flowLogPath,
      JSON.stringify(flowPayload, null, 2) + '\n',
      'utf8'
    );

    const copiedReleaseNote = path.join(knowledgeRoot, '.release-notes', 'v3.3.0.md');
    fs.appendFileSync(copiedReleaseNote, '\nPreparation only.\n', 'utf8');
    const provisionalConsistency = evaluatePublicConsistency(knowledgeRoot);
    assert(
      provisionalConsistency.status === 'fail'
        && provisionalConsistency.errors.some((error) => /provisional release markers/.test(error)),
      'public consistency checker accepted a provisional current release note'
    );

    const lockContext = {
      teamRoot: path.join(fixtureRoot, 'team-lock-contract'),
      repoId: 'release-gate-p0',
      workspaceId: 'contender',
      agentId: 'p0-contender',
      targetRoot: projectRoot
    };
    fs.mkdirSync(lockContext.teamRoot, { recursive: true });
    const releaseTeamLock = acquireTeamLock(lockContext, 'flow', { timeoutMs: 100, staleMs: 1000, retryMs: 2 });
    const activeTeamLock = teamLockStatus(lockContext);
    assert(activeTeamLock.status === 'active' && activeTeamLock.current?.owner?.pid === process.pid,
      'team flow did not expose a sanitized active lock status');
    let teamLockTimedOut = false;
    try {
      acquireTeamLock(lockContext, 'flow', { timeoutMs: 30, staleMs: 1, retryMs: 2 });
    } catch (error) {
      teamLockTimedOut = error.code === 'lock_timeout' && /Lock "team-flow" is held/.test(error.message)
        && !error.message.includes(projectRoot);
    }
    assert(teamLockTimedOut, 'live team flow lock was reclaimed or disclosed an unsafe path instead of timing out');
    releaseTeamLock();
    assert(teamLockStatus(lockContext).status === 'safe', 'released team flow lock remained active');

    return {
      schema_version: 'release-gate-p0-self-test.v1',
      status: 'pass',
      cases: [
        { id: 'gate-00-canonical-pass-status', status: 'pass' },
        { id: 'conformance-expected-failure-exit-exact', status: 'pass' },
        { id: 'release-step-log-binding-fail-closed', status: 'pass' },
        { id: 'accepted-envelope-schema-exact', status: 'pass' },
        { id: 'clean-source-real-ingest', status: 'pass' },
        { id: 'strict-doctor-project-index-check-after-bootstrap', status: 'pass' },
        { id: 'existing-project-index-noop', status: 'pass' },
        { id: 'stable-bootstrap-agent-id', status: 'pass' },
        { id: 'release-child-environment-isolated', status: 'pass' },
        { id: 'flow-log-evidence-correlation', status: 'pass' },
        { id: 'flow-log-tamper-rejected', status: 'pass' },
        { id: 'public-consistency-current-copy', status: 'pass' },
        { id: 'public-consistency-provisional-note-rejected', status: 'pass' },
        { id: 'docs-impact-routes-public-consistency', status: 'pass' },
        { id: 'release-infrastructure-routes-full-conformance', status: 'pass' },
        { id: 'pr-workflow-consumes-classifier-mode', status: 'pass' },
        { id: 'pr-workflow-routed-job-fetches-impact-baseline', status: 'pass' },
        { id: 'compatibility-workflow-covers-release-infrastructure', status: 'pass' },
        { id: 'mode-capabilities-fail-closed', status: 'pass' },
        { id: 'exact-upgrade-assertion-set-exact', status: 'pass' },
        { id: 'exact-upgrade-updater-snapshots-inert', status: 'pass' },
        { id: 'exact-upgrade-preservation-canary-and-path-exact', status: 'pass' },
        { id: 'exact-upgrade-runtime-proof-semantics-exact', status: 'pass' },
        { id: 'exact-upgrade-runtime-proof-chain-bound', status: 'pass' },
        { id: 'exact-upgrade-capture-standalone-semantics-fail-closed', status: 'pass' },
        { id: 'exact-upgrade-state-snapshot-read-once-bound', status: 'pass' },
        { id: 'exact-upgrade-command-contract-exact', status: 'pass' },
        { id: 'evidence-publication-drift-all-old', status: 'pass' },
        { id: 'evidence-publication-success-all-new', status: 'pass' },
        { id: 'evidence-publication-tree-addition-all-old', status: 'pass' },
        { id: 'evidence-publication-tree-recovery-all-old', status: 'pass' },
        { id: 'evidence-publication-fault-recovery-all-old-new', status: 'pass' },
        { id: 'evidence-publication-lock-serialized', status: 'pass' },
        { id: 'evidence-publication-lock-package-inert', status: 'pass' },
        { id: 'team-live-old-lock-preserved', status: 'pass' },
        { id: 'team-dead-stale-lock-reclaimed', status: 'pass' },
        { id: 'team-release-requires-owner-identity', status: 'pass' }
      ]
    };
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    console.log(JSON.stringify(main(), null, 2));
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;

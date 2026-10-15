'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  bindPublicApprovalReview,
  freezePublicApprovalFromEnvironment,
  parseStrictJson,
} = require('../src/public-approval');

const SHA64 = 'a'.repeat(64);

function authority() {
  return {
    schemaVersion: 1,
    status: 'PROVISIONED',
    repository: 'itcustomsolution/winrove-approval-authority',
    workflowPath: '.github/workflows/approve.yml',
    sourceRef: 'refs/heads/main',
    policySourceCommitSha: '0'.repeat(40),
    dispatchActor: {
      login: 'winrove-approval-dispatcher[bot]',
      id: 9001,
    },
    requiredReviewer: {
      login: 'Lu-ITC',
      id: 197497370,
    },
    environment: {
      name: 'winrove-staging-approval',
      id: 5001,
    },
  };
}

function environment() {
  return {
    INPUT_APPROVAL_ID: 'b'.repeat(64),
    INPUT_COMMITMENT: SHA64,
    INPUT_PRIVATE_SOURCE_COMMIT_SHA: '1'.repeat(40),
    INPUT_ENVIRONMENT: 'staging',
    INPUT_EXPIRES_AT: '2026-07-30T00:00:00.000Z',
    GITHUB_REPOSITORY: 'itcustomsolution/winrove-approval-authority',
    GITHUB_RUN_ID: '7001',
    GITHUB_RUN_ATTEMPT: '1',
    GITHUB_SHA: '2'.repeat(40),
    GITHUB_ACTOR: 'winrove-approval-dispatcher[bot]',
    GITHUB_ACTOR_ID: '9001',
  };
}

test('freeze emits only opaque public bindings and rejects any non-App dispatcher', () => {
  const frozen = freezePublicApprovalFromEnvironment({
    env: environment(),
    authority: authority(),
    now: Date.parse('2026-07-29T16:00:00.000Z'),
    comparePolicy: () => true,
  });

  assert.deepEqual(Object.keys(frozen.record).sort(), [
    'approvalId',
    'commitment',
    'dispatchActor',
    'environment',
    'expiresAt',
    'githubRunAttempt',
    'githubRunId',
    'privateSourceCommitSha',
    'protectedEnvironment',
    'purpose',
    'repository',
    'schemaVersion',
    'sourceRef',
    'workflowCommitSha',
    'workflowPath',
  ]);
  assert.equal(frozen.bytes.includes(Buffer.from('cohort')), false);
  assert.equal(frozen.bytes.includes(Buffer.from('deployment')), false);
  assert.throws(() => freezePublicApprovalFromEnvironment({
    env: { ...environment(), GITHUB_ACTOR: 'Lu-ITC', GITHUB_ACTOR_ID: '197497370' },
    authority: authority(),
    now: Date.parse('2026-07-29T16:00:00.000Z'),
    comparePolicy: () => true,
  }), /dispatcher/i);
  assert.throws(() => freezePublicApprovalFromEnvironment({
    env: environment(),
    authority: authority(),
    now: Date.parse('2026-07-29T16:00:00.000Z'),
    comparePolicy: () => false,
  }), /source-pinned policy/i);
});

test('review binding requires exactly one approval from Fela for the exact environment', () => {
  const config = authority();
  const frozen = freezePublicApprovalFromEnvironment({
    env: environment(),
    authority: config,
    now: Date.parse('2026-07-29T16:00:00.000Z'),
    comparePolicy: () => true,
  });
  const approved = [{
    state: 'approved',
    environments: [{ id: 5001, name: 'winrove-staging-approval' }],
    user: { login: 'Lu-ITC', id: 197497370, type: 'User', site_admin: false },
  }];
  const bound = bindPublicApprovalReview({
    publicBytes: frozen.bytes,
    reviewHistory: approved,
    authority: config,
    runId: 7001,
    runAttempt: 1,
  });

  assert.equal(bound.record.publicApprovalSha256, frozen.digest);
  assert.deepEqual(bound.record.review, {
    environmentId: 5001,
    environmentName: 'winrove-staging-approval',
    reviewerId: 197497370,
    reviewerLogin: 'Lu-ITC',
    state: 'approved',
  });
  assert.throws(() => bindPublicApprovalReview({
    publicBytes: frozen.bytes,
    reviewHistory: [...approved, ...approved],
    authority: config,
    runId: 7001,
    runAttempt: 1,
  }), /exactly one/i);
});

for (const { name, user, accepted } of [
  {
    name: 'accepts Lu-ITC with numeric id 197497370',
    user: { login: 'Lu-ITC', id: 197497370 },
    accepted: true,
  },
  {
    name: 'rejects the stale login with the correct id',
    user: { login: 'lu' + '745', id: 197497370 },
    accepted: false,
  },
  {
    name: 'rejects Lu-ITC with the wrong id',
    user: { login: 'Lu-ITC', id: 1 },
    accepted: false,
  },
  {
    name: 'rejects Lu-ITC with a string id',
    user: { login: 'Lu-ITC', id: '197497370' },
    accepted: false,
  },
]) {
  test(`review binding ${name}`, () => {
    const config = require('../config/authority.json');
    const frozen = freezePublicApprovalFromEnvironment({
      env: {
        ...environment(),
        GITHUB_ACTOR: config.dispatchActor.login,
        GITHUB_ACTOR_ID: String(config.dispatchActor.id),
      },
      authority: config,
      now: Date.parse('2026-07-29T16:00:00.000Z'),
      comparePolicy: () => true,
    });
    const bind = () => bindPublicApprovalReview({
      publicBytes: frozen.bytes,
      reviewHistory: [{
        state: 'approved',
        environments: [{ id: config.environment.id, name: config.environment.name }],
        user: { ...user, type: 'User', site_admin: false },
      }],
      authority: config,
      runId: 7001,
      runAttempt: 1,
    });

    if (accepted) {
      const bound = bind();
      assert.equal(bound.record.publicApprovalSha256, frozen.digest);
      assert.equal(bound.record.review.reviewerLogin, 'Lu-ITC');
      assert.equal(bound.record.review.reviewerId, 197497370);
    } else {
      assert.throws(bind, /exactly one protected-environment approval/i);
    }
  });
}

test('review-history parser rejects duplicate JSON keys before binding', () => {
  assert.throws(
    () => parseStrictJson('[{"state":"approved","state":"rejected"}]', 'review history'),
    /duplicate key state/i,
  );
});

test('exploit: shell metacharacters in expires_at are rejected before the summary step', () => {
  // Date.parse accepts "2026-10-16 $(id)"; it used to reach a bash run: block via ${{ inputs.expires_at }}.
  const now = Date.parse('2026-10-15T12:00:00Z');
  for (const bad of ['2026-10-16 $(id)', '10/16/2026 (x$(id))', 'Fri Oct 16 2026 10:00:00 GMT-0400 (EDT $(id))']) {
    assert.throws(() => freezePublicApprovalFromEnvironment({
      env: { ...environment(), INPUT_EXPIRES_AT: bad },
      authority: authority(),
      now,
      comparePolicy: () => true,
    }), /invalid/);
  }
});

'use strict';

const crypto = require('node:crypto');

const HEX40 = /^[a-f0-9]{40}$/;
const HEX64 = /^[a-f0-9]{64}$/;
// Strict UTC ISO-8601 only. Date.parse alone accepts strings like "2026-10-16 $(id)".
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function stableBytes(value) {
  return Buffer.from(JSON.stringify(stable(value)));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function parseStrictJson(text, label = 'JSON') {
  if (typeof text !== 'string') throw new Error(`${label} must be JSON text`);
  let position = 0;
  const whitespace = () => {
    while (/\s/.test(text[position] || '')) position += 1;
  };
  const stringToken = () => {
    const start = position;
    if (text[position] !== '"') throw new Error(`${label} expected a JSON string`);
    position += 1;
    while (position < text.length) {
      if (text[position] === '\\') position += 2;
      else if (text[position] === '"') {
        position += 1;
        return JSON.parse(text.slice(start, position));
      } else position += 1;
    }
    throw new Error(`${label} contains an unterminated JSON string`);
  };
  const value = () => {
    whitespace();
    if (text[position] === '{') {
      position += 1;
      whitespace();
      const keys = new Set();
      if (text[position] === '}') {
        position += 1;
        return;
      }
      while (position < text.length) {
        const key = stringToken();
        if (keys.has(key)) throw new Error(`${label} contains duplicate key ${key}`);
        keys.add(key);
        whitespace();
        if (text[position] !== ':') throw new Error(`${label} expected a colon`);
        position += 1;
        value();
        whitespace();
        if (text[position] === '}') {
          position += 1;
          return;
        }
        if (text[position] !== ',') throw new Error(`${label} expected an object comma`);
        position += 1;
        whitespace();
      }
    } else if (text[position] === '[') {
      position += 1;
      whitespace();
      if (text[position] === ']') {
        position += 1;
        return;
      }
      while (position < text.length) {
        value();
        whitespace();
        if (text[position] === ']') {
          position += 1;
          return;
        }
        if (text[position] !== ',') throw new Error(`${label} expected an array comma`);
        position += 1;
      }
    } else if (text[position] === '"') {
      stringToken();
    } else {
      const token = text.slice(position)
        .match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/)?.[0];
      if (!token) throw new Error(`${label} contains an invalid JSON value`);
      position += token.length;
    }
  };
  value();
  whitespace();
  if (position !== text.length) throw new Error(`${label} contains trailing JSON data`);
  return JSON.parse(text);
}

function configuredAuthority(authority) {
  if (authority?.schemaVersion !== 1
    || authority?.status !== 'PROVISIONED'
    || authority?.repository !== 'itcustomsolution/winrove-approval-authority'
    || authority?.workflowPath !== '.github/workflows/approve.yml'
    || authority?.sourceRef !== 'refs/heads/main'
    || !HEX40.test(authority?.policySourceCommitSha || '')
    || typeof authority?.dispatchActor?.login !== 'string'
    || !Number.isSafeInteger(authority?.dispatchActor?.id)
    || typeof authority?.requiredReviewer?.login !== 'string'
    || !Number.isSafeInteger(authority?.requiredReviewer?.id)
    || authority.dispatchActor.login === authority.requiredReviewer.login
    || authority.dispatchActor.id === authority.requiredReviewer.id
    || authority?.environment?.name !== 'winrove-staging-approval'
    || !Number.isSafeInteger(authority?.environment?.id)) {
    throw new Error('public approval authority is unprovisioned or invalid');
  }
  return authority;
}

function freezePublicApprovalFromEnvironment({
  env,
  authority,
  now = Date.now(),
  comparePolicy,
}) {
  const config = configuredAuthority(authority);
  const expiresAt = Date.parse(env.INPUT_EXPIRES_AT);
  const runId = Number(env.GITHUB_RUN_ID);
  const runAttempt = Number(env.GITHUB_RUN_ATTEMPT);
  const actorId = Number(env.GITHUB_ACTOR_ID);
  if (env.GITHUB_REPOSITORY !== config.repository
    || env.INPUT_ENVIRONMENT !== 'staging'
    || !HEX64.test(env.INPUT_APPROVAL_ID || '')
    || !HEX64.test(env.INPUT_COMMITMENT || '')
    || !HEX40.test(env.INPUT_PRIVATE_SOURCE_COMMIT_SHA || '')
    || !HEX40.test(env.GITHUB_SHA || '')
    || !ISO_UTC.test(env.INPUT_EXPIRES_AT || '')
    || !Number.isFinite(expiresAt)
    || expiresAt <= now
    || expiresAt > now + (24 * 60 * 60 * 1000)
    || !Number.isSafeInteger(runId)
    || runId < 1
    || runAttempt !== 1
    || env.GITHUB_ACTOR !== config.dispatchActor.login
    || actorId !== config.dispatchActor.id) {
    throw new Error('public approval input or dedicated App dispatcher is invalid');
  }
  if (typeof comparePolicy !== 'function'
    || comparePolicy(config.policySourceCommitSha, env.GITHUB_SHA) !== true) {
    throw new Error('source-pinned policy comparison failed');
  }
  const record = {
    schemaVersion: 1,
    purpose: 'winrove_digest_only_staging_approval',
    approvalId: env.INPUT_APPROVAL_ID,
    commitment: env.INPUT_COMMITMENT,
    privateSourceCommitSha: env.INPUT_PRIVATE_SOURCE_COMMIT_SHA,
    environment: 'staging',
    expiresAt: env.INPUT_EXPIRES_AT,
    repository: config.repository,
    workflowPath: config.workflowPath,
    sourceRef: config.sourceRef,
    workflowCommitSha: env.GITHUB_SHA,
    githubRunId: runId,
    githubRunAttempt: runAttempt,
    dispatchActor: {
      login: config.dispatchActor.login,
      id: config.dispatchActor.id,
    },
    protectedEnvironment: {
      name: config.environment.name,
      id: config.environment.id,
    },
  };
  const bytes = stableBytes(record);
  return { bytes, digest: sha256(bytes), record };
}

function bindPublicApprovalReview({
  publicBytes,
  reviewHistory,
  authority,
  runId,
  runAttempt,
}) {
  const config = configuredAuthority(authority);
  const bytes = Buffer.isBuffer(publicBytes) ? publicBytes : Buffer.from(publicBytes || '');
  const publicRecord = JSON.parse(bytes.toString('utf8'));
  if (!bytes.equals(stableBytes(publicRecord))
    || publicRecord.repository !== config.repository
    || publicRecord.workflowPath !== config.workflowPath
    || publicRecord.sourceRef !== config.sourceRef
    || publicRecord.githubRunId !== runId
    || publicRecord.githubRunAttempt !== runAttempt
    || runAttempt !== 1
    || publicRecord.dispatchActor?.login !== config.dispatchActor.login
    || publicRecord.dispatchActor?.id !== config.dispatchActor.id
    || publicRecord.protectedEnvironment?.name !== config.environment.name
    || publicRecord.protectedEnvironment?.id !== config.environment.id) {
    throw new Error('public approval run or canonical record binding is invalid');
  }
  const approvals = Array.isArray(reviewHistory) ? reviewHistory.filter((review) => (
    review?.state === 'approved'
      && review?.user?.login === config.requiredReviewer.login
      && review?.user?.id === config.requiredReviewer.id
      && review?.user?.type === 'User'
      && review?.user?.site_admin === false
      && Array.isArray(review?.environments)
      && review.environments.length === 1
      && review.environments[0]?.id === config.environment.id
      && review.environments[0]?.name === config.environment.name
  )) : [];
  if (approvals.length !== 1 || reviewHistory.length !== 1) {
    throw new Error('exactly one protected-environment approval from the required reviewer is required');
  }
  const review = {
    state: 'approved',
    reviewerLogin: config.requiredReviewer.login,
    reviewerId: config.requiredReviewer.id,
    environmentName: config.environment.name,
    environmentId: config.environment.id,
  };
  const record = {
    schemaVersion: 1,
    purpose: publicRecord.purpose,
    publicApprovalSha256: sha256(bytes),
    approvalId: publicRecord.approvalId,
    commitment: publicRecord.commitment,
    environment: publicRecord.environment,
    githubRunId: runId,
    githubRunAttempt: runAttempt,
    dispatchActor: publicRecord.dispatchActor,
    review,
    reviewBindingSha256: sha256(stableBytes(review)),
    publicApproval: publicRecord,
  };
  return {
    bytes: stableBytes(record),
    record,
  };
}

module.exports = {
  bindPublicApprovalReview,
  freezePublicApprovalFromEnvironment,
  parseStrictJson,
  stableBytes,
};

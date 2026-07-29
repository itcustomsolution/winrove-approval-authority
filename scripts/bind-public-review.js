#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  bindPublicApprovalReview,
  parseStrictJson,
} = require('../src/public-approval');
const { writeExclusive } = require('./freeze-public-approval');

const ROOT = path.resolve(__dirname, '..');
const AUTHORITY_PATH = path.join(ROOT, 'config', 'authority.json');

function options(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith('--') || !argv[index + 1]) {
      throw new Error('arguments must be flag/value pairs');
    }
    parsed[argv[index].slice(2)] = argv[index + 1];
  }
  for (const name of ['approval', 'review-history', 'out']) {
    if (!parsed[name]) throw new Error(`--${name} is required`);
  }
  return parsed;
}

function main(argv = process.argv.slice(2), env = process.env) {
  const input = options(argv);
  const authority = parseStrictJson(fs.readFileSync(AUTHORITY_PATH, 'utf8'), 'authority');
  const publicBytes = fs.readFileSync(path.resolve(input.approval));
  const reviewHistory = parseStrictJson(
    fs.readFileSync(path.resolve(input['review-history']), 'utf8'),
    'review history',
  );
  const bound = bindPublicApprovalReview({
    publicBytes,
    reviewHistory,
    authority,
    runId: Number(env.GITHUB_RUN_ID),
    runAttempt: Number(env.GITHUB_RUN_ATTEMPT),
  });
  writeExclusive(path.resolve(input.out), bound.bytes);
  process.stdout.write(
    `WINROVE_PUBLIC_APPROVAL_REVIEW_PASS digest=${bound.record.publicApprovalSha256}\n`,
  );
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`WINROVE_PUBLIC_APPROVAL_REVIEW_FAIL ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  main,
  options,
};


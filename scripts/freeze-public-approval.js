#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const {
  freezePublicApprovalFromEnvironment,
} = require('../src/public-approval');

const ROOT = path.resolve(__dirname, '..');
const AUTHORITY_PATH = path.join(ROOT, 'config', 'authority.json');
const POLICY_PATHS = [
  '.github/workflows/approve.yml',
  'src/public-approval.js',
  'scripts/freeze-public-approval.js',
  'scripts/bind-public-review.js',
];

function options(argv) {
  if (argv.length !== 2 || argv[0] !== '--out' || !argv[1]) {
    throw new Error('usage: freeze-public-approval.js --out <path>');
  }
  return { out: path.resolve(argv[1]) };
}

function comparePolicy(base, head) {
  try {
    execFileSync('git', ['merge-base', '--is-ancestor', base, head], {
      cwd: ROOT,
      stdio: 'ignore',
    });
    execFileSync('git', ['diff', '--quiet', base, head, '--', ...POLICY_PATHS], {
      cwd: ROOT,
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

function writeExclusive(file, bytes) {
  const parent = path.dirname(file);
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  fs.chmodSync(parent, 0o700);
  const descriptor = fs.openSync(file, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
  } finally {
    fs.closeSync(descriptor);
  }
}

function main(argv = process.argv.slice(2), env = process.env) {
  const input = options(argv);
  const authority = JSON.parse(fs.readFileSync(AUTHORITY_PATH, 'utf8'));
  if (JSON.stringify(authority.policyPaths) !== JSON.stringify(POLICY_PATHS)) {
    throw new Error('configured policy paths do not match the executable policy set');
  }
  const frozen = freezePublicApprovalFromEnvironment({
    env,
    authority,
    comparePolicy,
  });
  writeExclusive(input.out, frozen.bytes);
  process.stdout.write(`WINROVE_PUBLIC_APPROVAL_FREEZE_PASS digest=${frozen.digest}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`WINROVE_PUBLIC_APPROVAL_FREEZE_FAIL ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  comparePolicy,
  main,
  options,
  writeExclusive,
};


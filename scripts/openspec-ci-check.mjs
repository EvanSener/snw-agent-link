#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

function isFile(value) {
  try { return fs.statSync(value).isFile(); } catch { return false; }
}

function isDirectory(value) {
  try { return fs.statSync(value).isDirectory(); } catch { return false; }
}

const root = process.cwd();
const required = [
  'openspec/config.yaml',
  'openspec/schemas/spec-driven-zh/schema.yaml',
  'openspec/specs',
  'openspec/changes',
];

const errors = required.filter((entry) => {
  const target = path.join(root, entry);
  return entry.endsWith('.yaml') ? !isFile(target) : !isDirectory(target);
}).map((entry) => `缺少 OpenSpec 项目：${entry}`);

const changesRoot = path.join(root, 'openspec/changes');
if (isDirectory(changesRoot)) {
  for (const entry of fs.readdirSync(changesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.name === 'archive') continue;
    for (const artifact of ['proposal.md', 'design.md', 'tasks.md']) {
      if (!isFile(path.join(changesRoot, entry.name, artifact))) {
        errors.push(`active change ${entry.name} 缺少 ${artifact}`);
      }
    }
  }
}

for (const error of errors) console.error(`ERROR: ${error}`);
if (errors.length > 0) process.exit(1);
console.log('OpenSpec governance check passed.');

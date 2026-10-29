#!/usr/bin/env node
// Proves that a re-platformed paginated report changed only its data layer.
//   node hardening/scripts/rdl-compare.mjs <old.rdl> <new.rdl> [--ignore <Element>]...
// Removes <DataSources> and <DataSets> (and any --ignore element) from both files, normalizes line endings and a byte
// order mark, and requires the rest to be identical: layout, parameters, page setup, code and expressions.
// Exit 0: identical outside the data layer. Exit 1: a difference (the first one is printed). Exit 2: usage or read error.

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const DATA_LAYER = ['DataSources', 'DataSets'];

function strip(text, elements) {
  let out = String(text).replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  for (const name of elements) {
    // Report-level containers are not nested inside themselves, so a non-greedy match is exact.
    out = out.replace(new RegExp(`<${name}(?:\\s[^>]*)?(?:/>|>[\\s\\S]*?</${name}>)`, 'g'), `<${name} [data layer removed] />`);
  }
  return out;
}

/** Compares two RDL texts outside the data layer. Returns { same, line?, old?, new? }. */
export function compareOutsideDataLayer(oldText, newText, ignore = []) {
  const elements = [...DATA_LAYER, ...ignore];
  const a = strip(oldText, elements).split('\n');
  const b = strip(newText, elements).split('\n');
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) return { same: false, line: i + 1, old: a[i] ?? '(end of file)', new: b[i] ?? '(end of file)' };
  }
  return { same: true };
}

function main(argv) {
  const ignore = [];
  const files = [];
  let bad = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--ignore' && /^[A-Za-z][\w:]*$/.test(argv[i + 1] ?? '')) ignore.push(argv[++i]);
    else if (argv[i].startsWith('--')) bad = true;
    else files.push(argv[i]);
  }
  if (bad || files.length !== 2) {
    console.error('usage: node hardening/scripts/rdl-compare.mjs <old.rdl> <new.rdl> [--ignore <Element>]...');
    return 2;
  }
  let texts;
  try {
    texts = files.map((f) => fs.readFileSync(f, 'utf8'));
  } catch (err) {
    console.error(`rdl-compare: ${err.message}`);
    return 2;
  }
  const result = compareOutsideDataLayer(texts[0], texts[1], ignore);
  const skipped = [...DATA_LAYER, ...ignore].join(', ');
  if (result.same) {
    console.log(`Identical outside the data layer (${skipped} not compared): ${path.basename(files[0])} → ${path.basename(files[1])}`);
    return 0;
  }
  const cut = (s) => (s.length > 200 ? `${s.slice(0, 200)}…` : s);
  console.log(`Different outside the data layer (${skipped} not compared), first difference at line ${result.line} of the compared text:`);
  console.log(`  old: ${cut(result.old.trim())}`);
  console.log(`  new: ${cut(result.new.trim())}`);
  console.log('Keep every Field Name, report item and parameter as they were; change only data sources and datasets. A difference you');
  console.log('accept must be recorded in the report\'s decisions (or excluded with --ignore <Element>, with the reason).');
  return 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}

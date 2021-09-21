#!/usr/bin/env node

import * as curlconverter from '../index.js'

import fs from 'fs'

// used to map languages to functions
// NOTE: make sure to update this when adding language support
const translate = {
  ansible: 'toAnsible',
  browser: 'toBrowser',
  dart: 'toDart',
  elixir: 'toElixir',
  go: 'toGo',
  java: 'toJava',
  json: 'toJsonString',
  matlab: 'toMATLAB',
  node: 'toNodeFetch',
  'node-request': 'toNodeRequest',
  php: 'toPhp',
  python: 'toPython',
  r: 'toR',
  rust: 'toRust',
  strest: 'toStrest'
}

const USAGE = `Usage: curlconverter [<language>] [curl_options...]

language: the language to convert the curl command to. The choices are
  ansible
  browser
  dart
  elixir
  go
  java
  json
  matlab
  node
  node-request
  php
  python
  r
  rust
  strest

If no <curl_options> are passed, the script will read from stdin.`

let language = 'python'
let argv = process.argv.slice(2)
if (argv.includes('--help') || argv.includes('-h')) {
  console.log(USAGE.trim())
  process.exit(0)
}
if (Object.prototype.hasOwnProperty.call(translate, argv[0])) {
  [language, ...argv] = argv
}

const curl = argv.length ? ['curl', ...argv] : fs.readFileSync(0, 'utf8')
const generator = curlconverter[translate[language]]
const code = generator(curl)
process.stdout.write(code)

import * as curlconverter from './index.js'
import * as utils from './util.js'

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
export const fixturesDir = path.resolve(__dirname, 'fixtures')

// TODO: move this (or something like this) to index.js?
const converters = {
  ansible: {
    name: 'Ansible',
    extension: '.yml',
    converter: curlconverter.toAnsible
  },
  r: {
    name: 'R',
    extension: '.r',
    converter: curlconverter.toR
  },
  python: {
    name: 'Python',
    extension: '.py',
    converter: curlconverter.toPython
  },
  browser: {
    name: 'Browser',
    extension: '.js',
    converter: curlconverter.toBrowser
  },
  'node-fetch': {
    name: 'Node',
    extension: '.js',
    converter: curlconverter.toNodeFetch
  },
  node: {
    name: 'Node',
    extension: '.js',
    converter: curlconverter.toNodeRequest
  },
  php: {
    name: 'PHP',
    extension: '.php',
    converter: curlconverter.toPhp
  },
  go: {
    name: 'Go',
    extension: '.go',
    converter: curlconverter.toGo
  },
  rust: {
    name: 'Rust',
    extension: '.rs',
    converter: curlconverter.toRust
  },
  strest: {
    name: 'Strest',
    extension: '.strest.yml',
    converter: curlconverter.toStrest
  },
  json: {
    name: 'Json',
    extension: '.json',
    converter: curlconverter.toJsonString
  },
  dart: {
    name: 'Dart',
    extension: '.dart',
    converter: curlconverter.toDart
  },
  elixir: {
    name: 'Elixir',
    extension: '.ex',
    converter: curlconverter.toElixir
  },
  matlab: {
    name: 'MATLAB',
    extension: '.m',
    converter: curlconverter.toMATLAB
  },
  java: {
    name: 'Java',
    extension: '.java',
    converter: curlconverter.toJava
  }
}

// Check that we have at least one test for every generator
// https://github.com/NickCarneiro/curlconverter/pull/299
const testedConverters = Object.entries(converters).map(c => c[1].converter.name)
const availableConverters = Object.entries(curlconverter).map(c => c[1].name)
const missing = availableConverters.filter(c => !testedConverters.includes(c))
const extra = testedConverters.filter(c => !availableConverters.includes(c))
if (missing.length) {
  console.error('these converters are not tested: ' + missing.join(', '))
}
if (extra.length) {
  console.error('these non-existant converters are being tested: ' + extra.join(', '))
}
for (const [converterName, converter] of Object.entries(converters)) {
  const testDir = path.resolve(fixturesDir, converterName)
  if (fs.existsSync(testDir)) {
    const dirContents = fs.readdirSync(testDir)
    if (!dirContents.length) {
      console.error(testDir + " doesn't contain any files")
    } else if (!dirContents.filter(f => f.endsWith(converter.extension)).length) { // TODO: early stopping
      console.error(testDir + " doesn't have any files ending with '" + converter.extension + "'")
    }
  } else {
    console.error(converterName + " doesn't have a corresponding directory in fixtures/")
  }
}

// Special case that returns the parsed argument object
const toParser = (curl) => {
  const parserOutput = utils.parseCurlCommand(curl)
  const code = JSON.stringify(parserOutput, null, 2)
  return code + '\n'
}
converters.parser = {
  name: 'Parser',
  extension: '.json',
  converter: toParser
}

export { converters }

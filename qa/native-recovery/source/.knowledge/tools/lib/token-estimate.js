'use strict';

// routing bundle, baseline orientation, README metrics, and benchmark
// outputs so reported numbers compare apples to apples.
//
// Method (intentionally simple, dependency-free):
//   words = text.match(/\S+/g).length
//   chars = text.length
//   tokens_words = ceil(words * 1.33)
//   tokens_chars = ceil(chars / 4)
//   tokens_approx = max(tokens_words, tokens_chars)
//
// max() avoids the bug where a JSON file with little whitespace
// produced a 107-token estimate for a 7 KB payload.

const fs = require('fs');

function countWords(text) {
  const matches = String(text || '').match(/\S+/g);
  return matches ? matches.length : 0;
}

function estimateTokens(text) {
  const str = String(text || '');
  const words = countWords(str);
  const chars = str.length;
  const tokensWords = Math.ceil(words * 1.33);
  const tokensChars = Math.ceil(chars / 4);
  return Math.max(tokensWords, tokensChars);
}

function estimateForFile(absPath) {
  if (!fs.existsSync(absPath) || !fs.statSync(absPath).isFile()) {
    return { bytes: 0, words: 0, tokens_approx: 0 };
  }
  const text = fs.readFileSync(absPath, 'utf8');
  return {
    bytes: Buffer.byteLength(text, 'utf8'),
    words: countWords(text),
    tokens_approx: estimateTokens(text)
  };
}

function summarize(text) {
  const str = String(text || '');
  return {
    bytes: Buffer.byteLength(str, 'utf8'),
    chars: str.length,
    words: countWords(str),
    tokens_approx: estimateTokens(str)
  };
}

module.exports = {
  countWords,
  estimateTokens,
  estimateForFile,
  summarize,
  METHOD_ID: 'local_max_words_chars_v1',
  METHOD_DESCRIPTION: 'max(ceil(words*1.33), ceil(chars/4)) — local, dependency-free, order-of-magnitude only.'
};

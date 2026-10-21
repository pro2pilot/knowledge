'use strict';

// Shared, read-only admission for public caller data. Keep this dependency free
// of filesystem, transaction and writer modules so strict evidence readers can
// reject active values before any I/O. The historical error code is retained
// for the transaction API's compatibility contract.
const { types } = require('util');

function inputError(message) {
  const error = new Error(message);
  Object.defineProperty(error, 'code', dataDescriptor('transaction_input_invalid'));
  return error;
}

// These APIs admit caller data inside an already loaded runtime. A changed
// intrinsic prototype must not run a caller iterator/getter during admission.
// Capture the runtime's actual descriptors, rather than a Node-version list.
const DATA_INTRINSICS = [Object.prototype, Array.prototype].map(prototype => ({
  prototype, keys: Reflect.ownKeys(prototype), descriptors: Object.getOwnPropertyDescriptors(prototype)
}));
function assertDataIntrinsics() {
  for (let p = 0; p < DATA_INTRINSICS.length; p++) {
    const original = DATA_INTRINSICS[p], keys = Reflect.ownKeys(original.prototype);
    if (keys.length !== original.keys.length) throw inputError('Runtime data prototypes changed');
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      if (key !== original.keys[i]) throw inputError('Runtime data prototypes changed');
      const current = Object.getOwnPropertyDescriptor(original.prototype, key);
      const prior = Object.getOwnPropertyDescriptor(original.descriptors, key).value;
      const fields = ['value', 'get', 'set', 'enumerable', 'writable', 'configurable'];
      for (let j = 0; j < fields.length; j++) {
        const field = fields[j];
        const left = Object.getOwnPropertyDescriptor(current, field), right = Object.getOwnPropertyDescriptor(prior, field);
        if (Boolean(left) !== Boolean(right) || (left && left.value !== right.value)) {
          throw inputError('Runtime data prototypes changed');
        }
      }
    }
  }
}

function dataDescriptor(value, enumerable = true) {
  const descriptor = Object.create(null);
  descriptor.value = value;
  descriptor.enumerable = enumerable;
  descriptor.configurable = true;
  descriptor.writable = true;
  return descriptor;
}

// Public data admission. Context/root capabilities are separate from caller
// request data. No iterator, getter, proxy trap or inherited policy is invoked.
function copyPlainData(input, allowBuffers = false, checkBudget = null, maxSerializedBytes = null) {
  if (checkBudget) checkBudget();
  assertDataIntrinsics();
  let nodes = 0, bytes = 0, serializedBytes = 0;
  const visiting = new Set();
  const invalid = () => { throw inputError('Expected bounded inert own enumerable data'); };
  const accountString = value => {
    bytes += value.length * 2;
    // JSON escaping uses at most six bytes per UTF-16 code unit. Bound work
    // before stringify, including property names, without scanning huge text.
    serializedBytes += value.length * 6 + 3;
    if (bytes > 32 * 1024 * 1024 || maxSerializedBytes !== null && serializedBytes > maxSerializedBytes) invalid();
  };
  function copy(value, depth) {
    if (checkBudget) checkBudget();
    if (++nodes > 100000 || depth > 64) invalid();
    serializedBytes += 32;
    if (maxSerializedBytes !== null && serializedBytes > maxSerializedBytes) invalid();
    if (value === null || value === undefined || typeof value === 'boolean') return value;
    if (typeof value === 'string') { accountString(value); return value; }
    if (typeof value === 'number') { if (!Number.isFinite(value)) invalid(); return value; }
    if (typeof value !== 'object' || types.isProxy(value)) invalid();
    // isProxy precedes ALL reflection, including for revoked/transparent proxies.
    const prototype = Object.getPrototypeOf(value), keys = Reflect.ownKeys(value);
    if (keys.length > 100001) invalid();
    if (keys.some(key => typeof key !== 'string')) invalid();
    if (allowBuffers && prototype === Buffer.prototype && Buffer.isBuffer(value)) {
      bytes += keys.length;
      if (bytes > 32 * 1024 * 1024) invalid();
      const output = Buffer.alloc(keys.length);
      for (let i = 0; i < keys.length; i++) {
        if (keys[i] !== String(i)) invalid();
        const descriptor = Object.getOwnPropertyDescriptor(value, keys[i]);
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || !descriptor.enumerable ||
            !Number.isInteger(descriptor.value) || descriptor.value < 0 || descriptor.value > 255) invalid();
        output[i] = descriptor.value;
      }
      return output;
    }
    const array = Array.isArray(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) invalid();
    if (visiting.has(value)) invalid();
    visiting.add(value);
    const output = array ? [] : Object.create(null);
    if (array) {
      const length = Object.getOwnPropertyDescriptor(value, 'length');
      if (!length || !Object.prototype.hasOwnProperty.call(length, 'value') || length.enumerable ||
          !Number.isInteger(length.value) || length.value < 0 || length.value > 100000 || keys.length !== length.value + 1) invalid();
      for (let i = 0; i < length.value; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || !descriptor.enumerable) invalid();
        Object.defineProperty(output, String(i), dataDescriptor(copy(descriptor.value, depth + 1)));
      }
    } else {
      for (const key of keys) {
        accountString(key);
        if (['__proto__', 'prototype', 'constructor'].includes(key)) invalid();
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') || !descriptor.enumerable) invalid();
        Object.defineProperty(output, key, dataDescriptor(copy(descriptor.value, depth + 1)));
      }
    }
    visiting.delete(value);
    return output;
  }
  return copy(input, 0);
}

function copyInertData(value, checkBudget = null, maxSerializedBytes = null) { return copyPlainData(value, false, checkBudget, maxSerializedBytes); }

module.exports = { copyPlainData, copyInertData, dataDescriptor };

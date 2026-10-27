'use strict';

const path = require('path');
const { types } = require('util');
const { copyInertData, dataDescriptor } = require('./inert-data');
const ownedCommands = new WeakSet();
const MAX_COMMAND_BYTES = 32 * 1024 * 1024;

function commandInputError() {
  return Object.assign(new Error('Expected bounded inert command data'), { code: 'command_input_invalid' });
}

function processEnvironmentData(checkBudget) {
  const environment = Object.create(null);
  // Node's actual process.env is an exotic object. Read its native own data
  // descriptors, never a caller iterator/getter or coercion method.
  for (const key of Reflect.ownKeys(process.env)) {
    checkBudget?.();
    const descriptor = Object.getOwnPropertyDescriptor(process.env, key);
    if (typeof key !== 'string' || !descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable ||
        typeof descriptor.value !== 'string') throw commandInputError();
    Object.defineProperty(environment, key, dataDescriptor(descriptor.value));
  }
  return environment;
}

function freezeData(value, checkBudget) {
  checkBudget?.();
  if (!value || typeof value !== 'object') return value;
  for (const key of Reflect.ownKeys(value)) freezeData(Object.getOwnPropertyDescriptor(value, key).value, checkBudget);
  return Object.freeze(value);
}

function snapshotCommand(command, checkBudget = null) {
  checkBudget?.();
  if (command && typeof command === 'object' && ownedCommands.has(command)) return command;
  if (!command || typeof command !== 'object' || types.isProxy(command)) throw commandInputError();
  const prototype = Object.getPrototypeOf(command);
  if (prototype !== Object.prototype && prototype !== null) throw commandInputError();
  const candidate = Object.create(null);
  const keys = Reflect.ownKeys(command);
  if (keys.length > 100000) throw commandInputError();
  for (const key of keys) {
    checkBudget?.();
    const descriptor = Object.getOwnPropertyDescriptor(command, key);
    if (typeof key !== 'string' || !descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) throw commandInputError();
    Object.defineProperty(candidate, key, dataDescriptor(key === 'env' && descriptor.value === process.env
      ? processEnvironmentData(checkBudget) : descriptor.value));
  }
  if (!Object.hasOwn(candidate, 'env') || candidate.env === undefined) {
    Object.defineProperty(candidate, 'env', dataDescriptor(processEnvironmentData(checkBudget)));
  }
  let snapshot;
  try { snapshot = copyInertData(candidate, checkBudget, MAX_COMMAND_BYTES); }
  catch (error) { if (error.code === 'transaction_input_invalid') throw commandInputError();throw error; }
  checkBudget?.();
  freezeData(snapshot, checkBudget);
  ownedCommands.add(snapshot);
  return snapshot;
}

function invalidTarget() {
  const error = new Error('Nested command authority target is not an installed Knowledge entry');
  error.code = 'command_authority_target_invalid';
  return error;
}

function argsAreValid(args) {
  return Array.isArray(args) && args.every(value => typeof value === 'string' && !value.includes('\0'));
}

function installedAuthorityEntry(command) {
  if (command?.executable !== process.execPath || !argsAreValid(command?.args)) return null;
  const targets = new Map([
    [path.resolve(__dirname, '../flow.js'), 'flow'],
    [path.resolve(__dirname, '../evaluation-harness.js'), 'evaluation']
  ]);
  const target = command.args[0];
  if (typeof target !== 'string' || !path.isAbsolute(target)) return null;
  return targets.get(target) || null;
}

function validateCommandAuthority(command) {
  const elevated = command?.nestedAuthority === true;
  if (!argsAreValid(command?.args)) {
    if (elevated) throw invalidTarget();
    const error = new Error('Command arguments must be NUL-free strings');
    error.code = 'command_invalid';
    throw error;
  }
  if (!elevated) return null;
  const entry = installedAuthorityEntry(command);
  if (!entry) throw invalidTarget();
  return entry;
}

module.exports = { installedAuthorityEntry, validateCommandAuthority, snapshotCommand };

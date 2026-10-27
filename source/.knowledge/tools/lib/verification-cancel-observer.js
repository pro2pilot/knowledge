'use strict';

// Fixed read-only child of the already-admitted outer verification scope.
// It can revoke that scope; it cannot publish owner state, command results,
// cleanup proof or acceptance. A blocked read is contained by the same native
// owner and must actually end before the public caller can receive an ACK.
const { copyInertData } = require('./inert-data');
let admitted = false, reporter, stopped = false;
process.on('disconnect', () => process.exit(1));
process.once('message', async input => {
  try {
    if (admitted) throw new Error('duplicate observer admission');
    admitted = true;
    const message = copyInertData(input, null, 65536);
    if (message?.type !== 'observe' || !/^\d{1,32}$/.test(message.deadline_ns || '') ||
        typeof message.context?.stateRoot !== 'string' ||
        !require('./verification-invocation').validInvocation(message.invocation)) throw new Error('invalid observer admission');
    reporter = await require('./verification-progress').connect(message.channel, BigInt(message.deadline_ns));
    process.send({ type: 'observer_ready' });
    let observedOwnAttempt = null;
    const revoke = async type => {
      stopped = true;
      await reporter.flush({ type,
        invocation_nonce_sha256: message.invocation.nonce_sha256,
        invocation_scope_sha256: message.invocation.scope_sha256,
        at_ns: String(process.hrtime.bigint()) });
    };
    const poll = async () => {
      if (stopped) return;
      try {
        const status = require('./verification-control').readStatus(message.context);
        const attempt = status.attempt;
        if (attempt?.invocation?.nonce_sha256 === message.invocation.nonce_sha256 &&
            attempt.invocation.scope_sha256 === message.invocation.scope_sha256 &&
            (!observedOwnAttempt || observedOwnAttempt.attempt_id === attempt.attempt_id && observedOwnAttempt.generation === attempt.generation)) {
          observedOwnAttempt = { attempt_id: attempt.attempt_id, generation: attempt.generation };
          if (attempt.claimed && (attempt.cancel?.requested || attempt.recovery?.status === 'active')) {
            await revoke(attempt.cancel?.requested ? 'cancel_requested' : 'recovery_fence_observed');
            return;
          }
        }
      } catch (error) {
        // Tolerate only the first publisher's directory-to-record interval,
        // before any own record has been observed. Corruption still revokes.
        if (!observedOwnAttempt && error.code === 'verification_control_missing') {
          setTimeout(poll, 100);
          return;
        }
        try { await revoke('status_unconfirmed'); } catch {}
        return;
      }
      setTimeout(poll, 100);
    };
    poll();
  } catch {
    if (process.connected) process.send({ type: 'observer_failed' }, () => process.exit(1));
    else process.exit(1);
  }
});

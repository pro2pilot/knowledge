This is a source design for the next bounded component. It is not a build,
native run, production admission or a public route. Root selected trusted
Main/native creation with a distinct H identity. No host sysctl, account,
global capability or canonical release source has been changed.

Current source constraints

* Main startup is root0, fixed six capabilities, NNP1, groups0, dumpable0 and
  a fixed cooperative single-thread program. NNP1 cannot become NNP0 in its
  descendants. The old ordinary H and SUID preparer therefore remain separate;
  their NNP0 guards must stay unchanged.
* The native runtime front already supplies atomic CLONE_PIDFD births, private
  credentialed controls, min-only caller limits, actual wait/EOF and fixed
  per-slot custody. Its children have not supplied a protected ordinary H.
* Native UID history reserves burned authority/worker PAIRS. H must not borrow
  either UID or enter that ledger's ENTIRE inclusive [uid_first,uid_last]
  range. A dedicated host-principal UID/GID is administrative, never a request
  value. Both H IDs must differ from both authorized caller UID/GID as well.
* Same-UID ordinary V can control an ordinary H before its first self-check.
  A later dumpable0/inode/hash check cannot attest an untampered program.
  This stage removes that relation: Main owns H from its initial root0 birth,
  then drops all real/effective/saved IDs to the distinct protected H role.

Fixed private Main seam

The implementation is a program-private Main host front. Only the fixed Main
calls its start helper for an actually accepted slot. There is no Node/public
registration API and no caller-supplied executable, path, FD, UID, callback,
clock, owner or budget parameter to the creation helper. Main administrative
configuration and internally owned descriptors remain native resources, not
fields accepted from peer packets. Main's existing v1 runtime listener and
burned F/S/K history retain their current contracts.

The proposed new fixed host endpoint uses a bounded native control transport.
Main obtains V's actual PID/UID/GID from kernel peer credentials, holds a
pidfd with before/after brackets and requires V's actual user/time namespace
to match Main's captured original namespace. Ancillary rights from V are
rejected and closed; request bytes do not choose descriptors. A private
Main-created stream carries the FIRST bounded JSON frame and then the V
negative edge. If that stream's writer is transferred to native V transport,
it stays internal to that actual connection and never becomes a caller FD
factory. Kernel V death is independently terminal even with writer aliases.

The fixed64B header contains requested original S/W/C only. Main copies them
once and may only narrow effective W/C against existing administrative limits.
Requested and effective bounds have separate fields. A content-reading
preparer must publish limits and receive Main's ACK before graph I/O. Header
admission has its own existing finite pre-work bound, with no H/FS/K/issuer
authority. No user deadline is renewed after a stall or graph preparation.

Protected graph and actual Node execution

An isolated native root child prepares the fixed root-owned generation while
Main independently observes its pidfd, V and original limits. That child
never runs Node/project code. It captures the held Node executable, the
deterministic closed bundle and addon, validates protected directory/file
objects and hashes, creates fully sealed source/addon memfds, then sends only
the fixed private descriptor set to its genuine Main parent. Actual native
sender credentials, source, ownership, limits and complete descriptor custody
are mandatory. These are not serialized owner constructors. Main retains
the actual objects and reaps the preparer; unknown wait/EOF stays unconfirmed.

Main itself creates H with CLONE_PIDFD and a private release gate. The returned
H pidfd is stored before any fallible relocation or release; no later PID
lookup substitutes for the atomic birth. Main is H's biological parent and
owns H wait/EOF. This avoids transferring biological reap ownership or
inventing V ChildProcess events for a Main child. The fixed held Node object
is the one used by execveat(AT_EMPTY_PATH). The fixed builtin-only Node -e
bootstrap reads the sealed bundle through internal FD8; process.dlopen reads
the sealed addon through internal FD9. No pathname module/package fallback is
used by the closed loader. Module labels used for compatibility are DATA;
native source/birth checks do not trust those labels.

The current Node e520 retained ELF is dynamic: seven DT_NEEDED objects and
PT_INTERP /lib64/ld-linux-x86-64.so.2, with no RPATH/RUNPATH. A protected-system
interpreter/library policy and actual mapping-to-held-object checks remain a
required part of this mechanism. No static-Node, complete memory-CFI or
hard-I/O-latency theorem is inferred. New source/build/runtime qualification
cannot reuse old Node/helper/cold/component PASS as a blanket certificate.

Identity transition

Before release/exec, the actual H child remains protected root0 under Main.
It clears supplementary groups and keepcaps/ambient state, sets all R/E/S
UID/GID and fsuid/fsgid to the administrative H identity, clears E/P/I/ambient
caps and verifies NNP1. Main lacks CAP_SETPCAP: inherited bounding six is
reported honestly and must not cause a request for a new capability. The
child re-arms PDEATHSIG after all UID/GID changes and brackets it with Main
pidfd/getppid checks. An ordinary Node exec may reset dumpable; cross-UID
isolation is the foundation and postexec dumpable0 is an additional check.
No user namespace transition or V-owned namespace is allowed. Existing
key-process child_exec userns logic is not reused as an H owner.

The H principal must be reserved exclusively for the fixed trusted host role:
no project/worker/login/subordinate-UID process may run under it. It is outside
the entire F/S/K ledger, not a recycled reservation and not UID-CLOSED proof.
Any existing process outside genuine Main-owned H slots using that identity
is a refusal/recovery condition. A proc sample alone is not a guarantee about
future identity creation; administrator reservation and the closed fixed
program are explicit premises. The boxed fixture uses a dedicated unused
identity and creates no host account or UID policy.

Fixed child FD map (proposal, not a caller API)

0 FIRST JSON/negative stream; 1/2 H output/diagnostics; 3 closed; 4 private
Main/H credentialed control; 5 actual Main pidfd; 6 actual V pidfd; 7 sealed
original/effective context; 8 sealed bundle; 9 sealed addon; 10 held original
Main user namespace identity. All unlisted/project/listener/history/key FDs
are closed. Main's singleton alias must be retained until all inherited
listeners have closed, then retired. Node private FDs become CLOEXEC before
any possible descendant birth. No private output writer alias survives in a
non-owner. Namespace identity FD is observation only, with no namespace entry.

Compatibility and narrow verification

A NEW fixed Main-owned H entry requires the genuine native Main context,
strict H identity/NNP1 and original bounds. It does not relax the old H guard
and never calls the old SUID preparer. It reads only the bounded request DATA
and protected modules, then returns explicit runtime/FS/key unavailable before
createRoot, claims, project I/O, K/F/S work or signing. H cannot automatically
read V0700 projects or root0600 secrets. Native runtime/FS/key delegation is a
later separately typed step, not an ACL/chown/capability workaround.

The bounded boxed fixture should prove actual Main0 -> H distinct-ID birth,
same original userns, exact final credentials/caps/NNP, the held Node inode and
sealed bundle/addon identities, fixed source imports, V's inability to attach
as a cross-UID tracer, actual H pidfd wait+true EOF and unchanged requested/
effective limits. It should also refuse identity collisions, foreign/context
substitution and bad protected bytes without starting the body. The full
source/ordinary build packet, then exact compiled privileged Docker scope,
require separate review; no native invocation is authorized by this document.

Exactly two scenarios

D1: preexisting/cross-UID V tracer or a V-owned namespace/old UID impersonates
the creator. Require genuine native Main birth, original Main userns, private
kernel channels, exclusion of the whole ledger and caller IDs, exact protected
H identity before/after exec and no borrowed key-process userns/owner API.

D2: credential/cap/FD inheritance, held Node/bundle/DSO replacement, unread
FIRST payload or project-access incompatibility promotes bytes to permission
or renews a budget. Require strict drop, honest Bnd6, held-at-use sources,
phase-aware non-consuming negatives, original min-only bounds, actual wait/
EOF and deliberate unavailable-beforeRoot without delegation or key access.

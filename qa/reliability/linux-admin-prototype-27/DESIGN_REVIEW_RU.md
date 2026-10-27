# Explicit installed CLI design: два блокера и QA границы

План жизнеспособен как отдельный явно устанавливаемый admin deployment, а не
подмена helper в локальном runtime. Для интеграции обязательны две границы:

1. **Аргументы interpreter не являются profile boundary.** AppArmor видит Node
   executable, а не доверенность JS script. Один installed Node с authority `ix`
   не должен исполнять project.js/--eval/--require. Нужен fixed native dispatch и
   mandatory worker drop до любых произвольных argv, с label/caps/NNP readback;
   root-owned runtime/closure и actual systemRoot/process.execPath/HOST фиксированы.
   Static bootstrap обязателен либо нужен exact immutable ELF dependency mmap
   allowlist: очистка LD_PRELOAD/LD_AUDIT в динамическом main слишком поздняя.

2. **Immutable files не аутентифицируют IPC/процесс.** Anonymous inherited channel,
   typed one-shot operations, attempt/generation/parent binding и approved workspace
   IDs необходимы. Не принимать helper/role/systemRoot/proofRelay из произвольной
   env/payload. Same-UID parent/worker не должен ptrace/process_vm/proc-mem/fd
   заимствовать authority. Target тоже должен ограничивать readby/tracedby peers.

Для Git: текущий git-context вызывает spawnSync('git') с inherited PATH/config.
В admin deployment используйте фиксированный системный Git и обязательный
переход в worker до Git, включая его hooks/fsmonitor/helpers/pager descendants.
Ни Git, ни shell не получают authority `ix`; никаких fallback `pix/pux/ux`.
Whitelist environment очищает GIT_* overrides, loader и interpreter inputs,
HOME/XDG/system config policy задаются явно. Если metadata operation зависит от
произвольного repository helper, этот helper остаётся worker либо операция
отказывает; его не запускают в authority ради совместимости. Git output — inert
bounded data, не authority instructions. Выполнение Git также остаётся внутри
штатной native lifetime scope.

NNP требует отдельной точности: replacement профиля не равен permission-subset.
QA поэтому использует explicit **stack** fixed worker profile, не fallback.
Authority label сохраняется как ограничение, worker deny пересекается с ним.
Полный известный compound label фиксируется, authority-only никогда не принимается
как worker. Policy peers перечисляются точными labels/stacks; новые namespace
permissions не распространяются на generic interpreter/commands.

Фиксированный C primitive probe проверяет часть этих условий: static ELF,
LD_PRELOAD/LD_AUDIT sentinel, parent memory/FD denial, depth3 user/PID namespaces,
NNP/caps0, explicit worker stack, kernel denied userns/changeback и сохранение
worker stack через own-helper `ix`, locked securebits/dumpable parity и отдельный
pre-exec tracer контроль с inert static positive target. Только kernel exec
denial квалифицирует последнюю границу; successful exec с userspace guard refusal
остаётся FAIL/limitation. Он **не проверяет** production Node/Git/context
dispatch, full closure, API/finalization или recovery через outer proof relay.
Последнее может быть отдельным BLOCKED, а не поводом расширять ptrace peers.

Подготовлено только QA, автором не компилировалось/не исполнялось/не пушилось.
Root должен сначала проверить C/Python/template и отдельный GitHub workflow.

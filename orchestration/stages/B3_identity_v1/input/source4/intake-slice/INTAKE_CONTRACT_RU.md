# A2: private Main intake, ограниченная часть B1

## Назначение и строгая граница

`main-intake.inc` включается после неизменного `../main-h-birth-core.inc`
в тот же private native translation unit. Он содержит настоящий код Linux
socket/proc/namespace/pipe операций; тестовая модель заменяет эти операции
только в оснастке. Production callback, JSON constructor, передаваемый clock,
caller PID/FD/path, nonce-as-authority или экспортируемый API не добавлены.

Срез связывает один фактически принятый Main connection с kernel peer pidfd,
credential observations, удержанными proc/namespace и исходными requested /
min-only effective S/W/C. Он создаёт две собственные output pipe пары,
проверяет их независимые kernel identities и формирует private состояние
`MI_B1_READY`. Это **капсула фактов B1**, а не заполненный `mh_actual_offer`,
не разрешение родить H и не сообщение о готовности защищённого графа.

`mi_core_offer_original()` после повторной проверки действительного B1_READY
терминально отменяет попытку и возвращает `EOPNOTSUPP`. В новом срезе нет
присваивания `mh_actual_offer`, вызова `mh_spawn_original`, clone/fork/exec,
positive gate byte, Node/bundle или project/FS/K работы. Возвращаемое 1 у
`mi_receive_original()` означает завершение перечисленного intake наблюдения.
Оно не означает H identity, H readiness, release или какой-либо finality.

Изменения B2–B5 не выполнялись. В частности, старый core остаётся terminal-only,
его child-held остаётся root0; отдельный drop-helper не доказывает состоявшуюся
H identity transition. Bundle b932… остаётся inert DATA с несовместимым entry.

## Источник Main и воспроизводимый derivative

`derive_main.py` проверяет exact SHA/размер pinned Main и перечисленных
зависимостей, проверяет единственность каждого точного anchor и создаёт
**новый** `private-main-intake.c`. `DERIVATIVE_PINS.json` содержит все anchors,
их SHA и before/after. `--check` ничего не пишет и побайтово воспроизводит оба
созданных файла. `--write` отказывается перезаписывать существующие outputs.
Никакая версия Main не копируется поверх `BASE_MAIN`.

Derivative сохраняет исходную цепочку startup → административная config →
singleton → защищённый listener source. В новом месте вызова `mi_main_capture`
передаются только локальные `original` и поля `configuration.policy` этого
Main. Старые `kv_linux_runtime_front_open/poll/stop/close` заменены внутри
нового derivative одним bounded terminal intake attempt. Front duplicate
listener здесь не создаётся. Actual accepted descriptor создаётся самим
`mi_accept_original()` через `accept4` на захваченном Main listener.

В derivative удалены `--initialize` и оба initialization branch, включая
вызов `kv_linux_uid_initialize`; используется только уже существующий
singleton. BASE_MAIN при этом неизменен.

Файл намеренно не содержит executable `main`: символ переименован в
`static __attribute__((used)) mi_private_main_source_only`: symbol остаётся
внутренним, attribute удерживает его compiler body. Это source-only материал
для review, не
команда запуска. Он сохраняет native startup/listener administrative source,
который **нельзя исполнять** в рамках этапа. Full derivative translation unit
требует отсутствующих в supplied snapshot transitive headers, в частности
`verification-linux-service-session-front.h` и
`verification-linux-service-child-runtime.h`. Их объявления не заменяются
заглушками. Standalone intake native object и actual-include model имеют
отдельную замкнутую test closure и не квалифицируют весь Main build.

## Обязательные Main-origin premises

1. Это именно фиксированный trusted native Main из проверенного installed
   source, а не библиотека для произвольного процесса с похожим UID. Process
   до startup не имел потоков; в дальнейшем нет потоков, async FD mutators,
   signal-handler descriptor operations, dlopen/project callbacks или
   произвольной записи в private state. One-time proc scan не доказывает
   историю отсутствия потоков.
2. Main profile проверяет неизменный actual core helper: root0 R/E/S/fs IDs,
   groups0, NNP1, exact six E/P/Bnd, I/A0, keepcaps0/dumpable0 и SIGCHLD.
   Intake не меняет capabilities, identities, namespaces или host policy.
3. Main владеет единственным listener; его старый front не открыт и нет
   неучтённого listener alias. Listener borrowed by intake, а закрывает его
   fixed Main после terminal retirement всех intake descriptors. Конкретный
   `(dev,ino)` проверяется вновь непосредственно перед accept.
4. Trusted `/proc` является настоящим procfs с корректной PID view, без
   privileged mount replacement/namespace manipulation. Source проверяет
   `PROC_SUPER_MAGIC`, типы namespace FDs и равенство namespace `/proc/1/ns/pid`
   исходному namespace текущего Main. Одного `/proc/self`, совпавшего числа
   PID или fstatfs было бы недостаточно. Main current user/time/pid namespace
   сравнивается с original capture повторно.
5. Authorized V не имеет privilege для подделки SCM credentials или доступа
   к private Main памяти/FD table. Admission требует всех R/E/S/fs UID/GID,
   равных authorized ID, и нулевых I/P/E/ambient capabilities. Это фактические
   observations, не lifetime proof; отсутствие последующего capability gain
   (включая credential-spoofing privileges и CAP_SYS_PTRACE) остаётся
   административным lifetime premise. V NNP1 не добавляется как новая policy;
   старые NNP0/SUID guards не изменяются.
6. Native owner не отдаёт pipe/read/socket OFDs наружу, не меняет их flags
   через alias и не рождает child в A2. Подмена private памяти либо FD table
   trusted Main привилегированным сторонним кодом не покрывается этим срезом.

Эти premises нельзя восстановить из JSON `ready`, nonce, совпадения UID,
подписанного названия роли или kernel credentials создателя socketpair.
Фактический biological parent будущего H устанавливается Main-owned atomic
birth в отдельном core; socket peer credentials этот факт не доказывают.

## State / ownership

Все state, handles и helper functions `static`; поддерживается одна попытка
на процесс. После cancel/finish повторный capture невозможен. Diagnostic raw
receipt не используется как источник новых ресурсов или authorization.

| State | Приобретённые ресурсы / допустимый следующий шаг |
|---|---|
| `MI_COLD` | Ресурсов нет; capture либо terminal cancel |
| `MI_MAIN_CAPTURED` | Borrowed actual listener; owned proc root, Main procdir и original user/time/pid namespace handles; accept под неизменным admission deadline |
| `MI_ACCEPTED` | Actual `accept4` result немедленно сохранён до первой fallible операции; дальнейший отказ закрывает его и остальную owned custody |
| `MI_PEER_HELD` | Kernel SO_PEERPIDFD, единожды удержанный peer procdir, original peer namespaces; ожидается один header |
| `MI_HEADER_BOUND` | Requested S/W/C и narrowed W/C захвачены; pipe acquisition может частично отказать |
| `MI_B1_READY` | Две fresh независимые pipe пары; только terminal cancellation / explicit full-offer refusal |
| `MI_TERMINAL` | Все owned numbers инвалидируются перед однократным close; raw ошибки сохранены; нет нового accept/receive/publication |
| `MI_FINISHED` | Завершена source disposal попытка без close faults; никакой H/reap/UID-closure claim |

Borrowed listener не закрывается intake. Остальные 15 ролей принадлежат
intake до terminal disposal, включая connection, pidfd, proc/ns handles и
четыре pipe ends. После `pipe2` оба результата заносятся в custody до
relocation. `F_DUPFD_CLOEXEC` нужен только для high FD >=32; созданный новый
номер сохраняется до close старого. Temporary aliases закрываются до любого
B1_READY. Close не повторяется после EINTR/ошибки по потенциально reused FD.
Ошибка close остаётся `close_fault`; инвалидированный номер не выдаётся за
доказанный успешный kernel close. Receipt хранит первые 512 raw close records,
общий saturating `close_total`, отдельный counter SCM closes и
`receipt_overflow`. Переполнение истории не выдаётся за kernel close failure;
при нём фиксируется ограниченность receipt. Полный model trace сохраняет
каждую wrapper operation независимо от этого bounded source history.

Unexpected SCM descriptors приобретаются отдельным kernel receive и
закрываются как такие receive-owned descriptors. Одинаковый числовой FD в
повторном malformed record закрывается не более одного раза. Совпадение
числа с уже удерживаемым Main FD невозможно для нормального kernel install;
модель проверяет refusal без закрытия чужой authority по такому числу.

## Peer / proc / namespace binding

Connection должен быть CLOEXEC/nonblocking AF_UNIX SOCK_SEQPACKET,
не-listener и с SO_PASSCRED=1. Флаг заранее выставлен pinned listener source;
intake не принимает arbitrary socket FD в request. Kernel SO_PEERCRED
считывается до и после SO_PEERPIDFD. PID должен быть положительным, отличным
от Main PID; UID/GID должны совпадать с actual administrative policy.

`SO_PEERPIDFD` возвращает отдельный retained handle. Source **никогда не
вызывает pidfd_open(peer_pid)**, не строит authority из peer PID текста и не
заменяет peer handle после смерти. Unsupported/error option означает refusal.
Poll на pidfd проверяется как exact non-ready/non-error observation, с
проверками исходного deadline до и после него.

Для held proc необходима **единственная первоначальная metadata capture**
`openat(held_proc_root, kernel_credential_pid, ...)`, окружённая liveness
checks того же SO_PEERPIDFD. Это не повторное открытие peer authority по PID.
После capture нет нового числового proc lookup: все status/ns открытия идут
от held peer procdir. После failure новый numeric lookup также невозможен,
поскольку попытка terminal. Held procdir не предотвращает PID reuse; его
операции не должны ретаргетироваться на новый процесс с тем же числом PID.
Это kernel-semantic premise, моделируемая отдельно, не физически доказанная
здесь гарантия.

`/proc/.../status` читается одним bounded-size read, с отказом при заполнении
буфера, неполном/дублированном required field и ошибке. Проверяются Pid/Tgid,
один NSpid, все четыре Uid/Gid и CapInh/CapPrm/CapEff/CapAmb==0. Значение
SO_PEERCRED само по себе не обнаруживает последующий credential drift.
Текущие held-proc observations и per-message SCM_CREDENTIALS должны
согласоваться с original connection credentials.

Peer user/time/**pid** namespace должны совпасть с original Main namespace
objects по `(st_dev,st_ino)` и `NS_GET_NSTYPE`. Требование same pid namespace
здесь является дополнительным ограничением приёма, чтобы источник proc PID
был недвусмысленным. Оно не расширяет права caller. Namespace handles
используются только для наблюдения; setns/unshare отсутствуют.

Повторные checks окружают receive и pipe preparation. Non-consuming socket
poll проверяет HUP/RDHUP/ERR/NVAL независимо от живости peer process. До
header POLLIN допускает ожидаемые DATA; после принятого header любой новый
POLLIN является terminal extra packet/EOF и не потребляется. Поэтому valid
queued header с уже наблюдаемым close/half-close не превращается в live
transport claim. Будущая смерть/EOF после последнего наблюдения всё равно
не исключена. Checks не являются
атомарным snapshot всего процесса и не доказывают будущую неизменность V;
строгие lifetime premises сохраняются. Смерть V либо новый процесс с тем же
PID не позволяет заново открыть или выпустить существующий slot.

## Header, ancillary и время

Новый private 64-byte DATA header не является прежним public runtime wire.
Его bytes 0–7: `4b 56 4d 48 41 32 00 00`; bytes8–15 — little-endian
version1 и length64. Bytes16–23:
requested S; 24–31: requested W; 32–39: requested C, все LE uint64; bytes40–63
нулевые. В нём нет PID, FD, UID, path, callback, graph readiness или nonce.
JSON не разбирается.

`recvmsg(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)` читает ровно один packet. Требуются
точная длина64, ровно один kernel SCM_CREDENTIALS exact size, совпадающий с
original connection creds, и отсутствие прочих ancillary. MSG_TRUNC,
MSG_CTRUNC, duplicate creds, неизвестные records и SCM_RIGHTS/SCM_PIDFD
отвергаются. **До любого возврата по payload/EOF/creds/deadline** parser
проходит все структурно видимые cmsgs и закрывает каждый полный полученный
SCM_RIGHTS/SCM_PIDFD integer, включая видимую часть усечённого FD record.
Он не прекращает sweep из-за первого запрещённого, но корректно framed cmsg.

Framing cmsgs создаёт ядро; sender не выбирает сырой cmsghdr layout в
receiver buffer. При невозможном повреждённом length, из которого нельзя
вычислить следующий record, parser закрывает известные видимые полные FD
этого record и отказывает. Это не произвольный memory-corruption recovery.
FDs, не установленные ядром из-за truncation, не принадлежат receiver; source
не выдумывает их номера. Duplicate-number close защита не означает, что
нормальный kernel install возвращает одинаковые FD numbers.

Admission end устанавливается один раз от actual Main capture clock плюс
существующее administrative setup_ns. Accept/receive EAGAIN не обновляют его.
S/W/C копируются один раз: `0 < S < W < C <= INT64_MAX`, S не позже recorded
accept time, текущее время не раньше S. Header должен завершить binding до
**исходного admission end**; переход state не может сбросить истёкший setup.
Effective W = min(requested W, S+administrative work_ns). Effective C =
min(requested C, effective W+administrative cleanup_ns). Overflow, отсутствие
work interval и W>=C отвергаются. Original requested values не переписываются.

С этого момента work checks используют narrowed W. clock failure, zero,
backwards movement, overflow, stop и observed deadline terminal. Guard
перепроверяет stop после clock call; stop во время delayed clock не даёт
B1_READY. Вполне закончить already-started syscall после deadline возможно;
новые действия не разрешаются observed late completion, и cleanup closes
остаются допустимы. Это **не физическая deadline interruptibility**, не
hard scheduler/procfs/socket/poll/close latency proof.

## Output pipe objects и O_NONBLOCK

Output создаются только двумя отдельными `pipe2(O_CLOEXEC|O_NONBLOCK)`.
Проверяется каждое read/write направление, FIFO type, соответствие kernel
object внутри пары и **неравенство `(dev,ino)` между stdout и stderr**.
Разные номера FD сами по себе не являются достаточным условием.

O_NONBLOCK принадлежит open file description. Его readback не доказывает,
что другой alias не изменит флаг позднее. Здесь lifetime invariant вытекает
из fixed source: fresh local creation, закрытие temporary dup aliases,
отсутствие передачи FD, F_SETFL, fork/clone, иных потоков и внешнего owner.
Эта source custody должна сохраниться будущим bridge; она не выводится из
одного fstat или fcntl. При нарушении exclusive alias premise библиотечный
check не превращает потенциально блокирующий read в физически interruptible.

Неизменный старый core не проверяет cross-pipe identity inequality и не
доказывает отсутствие OFD aliases. A2 не переписывает его и не объявляет
старые физические выводы сильнее. В A2 все pipe ends остаются local и
закрываются без рождения H. Future core handoff обязан сохранить distinct
objects и разрешённое распределение ownership; это ещё не выполнено.

## Что остаётся BLOCKED

- **B1/full core publication interface:** captured accepted connection и
  observation capsule есть в source; полноценного slot constructor нет.
  Переход от этих facts к `mh_actual_offer` требует согласованного Main-native
  producer bridge, который владеет остальными typed resources и переносит
  ownership без caller-supplied numbers.
- **B2:** административная доставка и reservation отдельного HUID/HGID;
  нынешний H policy/config ABI не меняется.
- **B3:** genuine protected graph/preparer/held image/bundle/addon/context,
  interpreter/DSO/mapping policy; они не заменяются memfd seals или bool.
- **B4:** новый NNP1 entry/addon и postexec FD retirement. Старый bundle/NNP0
  SUID путь не приспосабливается к новому Main.
- **B5:** полный Main H/recovery loop, retirement aliases и retained custody
  после C. Одноразовый terminal intake driver этим интерфейсом не является.
- **Build input:** для полного derivative translation unit отсутствуют
  pinned transitive C headers. Восстановление полного exact dependency closure
  является отдельным шагом; fake declarations/stubs запрещены.

Следующий безопасный шаг: прочитать exact-source review и raw results,
воспроизвести `derive_main.py --check` и ordinary actual-include model на
свежей применённой базе. Затем исходный инженер должен отдельно согласовать
полный dependency closure и B1-to-core ownership bridge вместе с остающимися
B2–B5. В этом этапе такой bridge не включается по флагу `ready`.

## Источники семантики и evidence

- Linux `unix(7)`: https://man7.org/linux/man-pages/man7/unix.7.html — различие
  connection credentials и per-message credentials, ancillary rights.
- Linux procfs documentation:
  https://www.kernel.org/doc/html/latest/filesystems/proc.html — held proc
  descriptor не блокирует reuse числа PID и не ретаргетируется на новую task.
- Linux `fcntl(2)`: https://man7.org/linux/man-pages/man2/fcntl.2.html — file
  status flags и open file descriptions.
- Linux `pid_namespaces(7)`:
  https://man7.org/linux/man-pages/man7/pid_namespaces.7.html — procfs PID view.

Exact-source review предшествует любой компиляции/модели. Содержимое test
model/runner, symbol guard, compiler actions и каждый raw stdout/stderr/rc
должны быть проверены по final pins. Неудачные попытки остаются evidence.
Native Main/H, bundle, namespace/credential transitions и actual H pipe/
wait/exec qualification здесь NOT_RUN; ordinary socket fixtures, если
предпосылки доступны, проверяют только свой заявленный transport scope.

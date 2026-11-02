# Этап A: закрытая часть private Main/H birth core

## Объём и статус

Этот документ описывает новый source-срез `main-h-birth-core.inc`. Он не
заменяет неизменный `MAIN_CREATOR_CONTRACT.md`, не вводит продуктовый endpoint
и не объявляет готовыми issuer, Linux service, H runtime или release gate.

Реализована ограниченная последовательность **потребление одной native offer →
atomic birth с удержанием pidfd → удерживаемый native child → необратимая
отмена → отдельные наблюдения biological reap и двух output EOF → освобождение
подтверждённой custody**. Её применимость условна: настоящий producer private
slot, указанные ниже факты происхождения и интеграция в Main отсутствуют.

**Разрешение исполнения и exec остаются BLOCKED.** В новом срезе нет записи
положительного gate token, `execveat`, старого `MH_BOOT` или вызова Node. Release
для действительной pending offer или owned custody получает `EOPNOTSUPP` и
отменяет попытку; при её отсутствии возвращается ошибка состояния/владельца.
Это отказ операции,
а не фиктивный успешный bootstrap. Полный bootstrap имеет статус PARTIAL.

`MH_CHILD_HELD` — результат удержания atomic birth со стороны родителя. Он
не означает, что ребёнок уже дошёл до конкретной инструкции gate, что он
жив в будущем или что исполнение разрешено. Child не посылает ACK о готовности.
Даже если он ещё не запланирован, у него нет достижимого пути к release/exec.
Фактический запуск privileged/native Main/H в этом этапе **NOT_RUN**.

## Почему нельзя завершить release в этих входах

Ниже перечислены точные интерфейсные блокеры. Их нельзя заменить полем
`graph_ready`, caller-supplied FD, цифровым PID или совпадением DATA hash.

1. **B1 — настоящий private Main producer.** В pin-нутом Main/runtime front
   нет подключения этого include и producer для `mh_actual_offer`. Нужны
   genuine accepted V, kernel `SO_PEERPIDFD`, actual peer credentials,
   удерживаемый procdir, исходные Main user/time namespace и original S/W/C;
   чужие SCM_RIGHTS должны отвергаться и закрываться своим intake. Проверка
   `poll` внутри core устанавливает только отсутствие наблюдаемого события
   смерти, а не происхождение V pidfd. Numeric peer/child `pidfd_open` fallback
   не реализован и не допускается.
2. **B2 — административная H identity.** Код исключает HUID и HGID из всего
   включительного ledger range и обоих authorized caller ID; он не создаёт
   административную резервацию. Pin-нутый configuration ABI не предоставляет
   утверждённого H principal. Эксклюзивность H identity на всё время жизни,
   отсутствие login/project/worker/subuid пользователей этой identity и
   отсутствие у V `CAP_SYS_PTRACE` в target Main userns остаются внешними
   предпосылками. V NNP1 не был согласован в старом контракте и здесь не добавлен.
3. **B3 — held protected loader/runtime graph.** Нужен native preparer с
   genuine sender/parent custody, original bounds/ACK до content I/O,
   защищённой directory/file identity, immutable sealed bytes и выбранными
   именно при употреблении объектами. Текущие `F_GET_SEALS`/`fstat` — только
   проверки формы held DATA. Они не подтверждают trusted origin, содержимое
   или полный граф. Dynamic Node interpreter, семь DT_NEEDED и фактические
   mappings/held objects остаются отдельной нерешённой границей.
4. **B4 — новый NNP1 entry/addon.** Bundle с SHA
   `b9322ffe458c30bf46ac649f86f3db0dc864592d122648e5db16754dd30a9aab`
   остаётся неизменным inert DATA с прежним несовместимым entry. Нет нового
   native Main-origin addon и H entry, который проверял бы финальные H IDs,
   NNP1/Bnd6, original namespace и genuine inherited roles, закрывал private
   inheritance до рождения потомков и возвращал unavailable до createRoot,
   project I/O, claim, FS/K/runtime delegation. Старые NNP0/SUID guards не менялись.
5. **B5 — настоящий descriptor inventory и event loop.** Native producer
   должен владеть единственным наследуемым listener (`slot.listener`),
   singleton и исчерпывающим списком aliases. Slot хранит именно actual sole
   listener, а не выбранный из запроса FD. Пара output pipes не имеет writer
   aliases вне Main и его actual child. Pin-нутый front имеет свой private
   listener; интерфейс подключения к нему здесь не добавлен. Также нужен
   Main event loop для вызовов stop/progress/finish и отдельного удержания
   unconfirmed custody после C. Это не выводится из данных slot и не
   реализуется изменением чужого Main исходника в этом этапе.

Отдельный HUID не предоставляет доступ к V0700 project или root0600 secrets.
Никаких ACL, chown, новых capabilities, namespace delegation, host accounts,
SUID обходов или privileged Root Node для совместимости не добавлено.

## Частный API и состояния

Все перечисленные сущности `static` и принадлежат одному fixed native Main
translation unit. Нет exported API, packet decoder, JS owner constructor,
callback/clock injection или setter для чужого процесса. В этом срезе
поддерживается одна удерживаемая попытка; многослотовая интеграция не заявлена.

| Операция | Результат и ограничение |
|---|---|
| `mh_spawn_original()` | Забирает точную `mh_actual_offer`; сжигает попытку до fallible preflight. `MH_CHILD_HELD` означает только retained birth. Любая ошибка необратима для этой offer. |
| `mh_cancel_original()` | Sticky cancellation, закрытие своего gate writer и ограниченный signal по своему atomic pidfd. Вызов до spawn также потребляет и сжигает offer без действий с supplied FD. |
| `mh_release_original()` | При наличии pending offer/owned custody — отказ `EOPNOTSUPP` после terminal cancel; иначе ошибка состояния/владельца. Ни одного gate byte, release/exec flags остаются нулевыми. |
| `mh_stop_original()` | Только signal-safe latch. Следующий ordinary шаг запрещает новую работу и начинает/продолжает отмену. |
| `mh_progress_original()` | Ограниченный шаг: максимум один `waitid(WNOHANG)` и один nonblocking read каждого output; время перепроверяется между стадиями. Нет блокирующего cleanup-loop. |
| `mh_finish_original()` | `EBUSY`, пока birth/custody неизвестны либо отсутствует actual reap или один из двух actual EOF. Завершённая очистка освобождает только собственные handles. |
| `mh_child_drop_checked(...)` | Отдельный source/model helper полной credential transition; в held-child пути не вызывается. Сам по себе не является release или разрешением exec. |

Срез не доверяет `slot.h_pidfd`, `slot.h_pid`, `slot.gate_*` как authority:
это только диагностические зеркала. Для signal/wait/close используется
отдельный private `mh_owned`, заполняемый из результата actual clone.
Повторная offer при ещё удерживаемой custody получает `EBUSY` и не затирает
старый handle. Уже потреблённая offer не может повторно создать ребёнка.

Нет общей теоремы против произвольного повреждения памяти доверенного Main
или закрытия/переиспользования его native owner FD чужим privileged кодом.
Exclusive descriptor custody, отсутствие прошлых/текущих потоков и
кооперативный fixed Main — явные предпосылки. Runtime `one_thread` scan
в include не реализован; один такой scan сам по себе не доказал бы историю.

## Actual Main, H identity, namespace и credentials

Source preflight читает реальные R/E/S UID/GID, fsuid/fsgid, supplementary
groups, E/P/I capabilities, bounding mask, ambient capabilities, NNP,
keepcaps, dumpable и SIGCHLD disposition. Требуются root0, groups0, ровно
CHOWN/KILL/SETGID/SETUID/SYS_PTRACE/SETFCAP в E/P/Bnd, I/A0, NNP1,
keepcaps0, dumpable0, default SIGCHLD без SA_NOCLDWAIT.

HUID и HGID должны быть ненулевыми, отличными от `(uid_t)-1`/`(gid_t)-1`,
от каждого из authorized UID/GID и от **всего** включительного ledger range.
HUID может равняться HGID. Sentinel -1 отдельно отвергнут: у setres* он
означает «не менять», а не пригодную отдельную identity.

Core самостоятельно захватывает **свой** Main pidfd через
`pidfd_open(getpid(), 0)` до clone и удерживает его для ребёнка. Это lookup
текущего исполняющегося Main, который не может быть подменён повторным
использованием собственного PID во время вызова. Ни peer PID, ни возвращённый
child PID не передаются в `pidfd_open`. Для H применяется только atomic
`CLONE_PIDFD|SIGCHLD` с x86_64 ABI `clone(flags,NULL,&bornfd,NULL,0)`;
fork/numeric-PID fallback отсутствует. Неподдерживаемый syscall — отказ.

Held/current user namespace проверяются по `st_dev/st_ino` и
`NS_GET_NSTYPE==CLONE_NEWUSER`. Это consistency check относительно native
capture в slot; происхождение original namespace и V time namespace
отнесены к B1. `setns`/`unshare`/`CLONE_NEWUSER` не вызываются.

`mh_child_drop_checked` перед любыми credential changes проверяет original W,
stop, Main profile, actual getppid, Main/V pidfd и original namespace. Затем
ставит PDEATHSIG, повторяет parent checks и сбрасывает keepcaps, ambient,
все supplementary groups, R/E/S GID, R/E/S UID, E/P/I и ambient capabilities.
Проверяются все полученные R/E/S/fs IDs, groups0, caps0, keepcaps0, NNP1 и
честно унаследованный Bnd6. CAP_SETPCAP не запрашивается. Core limit становится
нулевым, dumpable — 0. После последнего credential change PDEATHSIG=SIGKILL
ставится снова, с getppid/held Main pidfd brackets и повторным namespace/В/W
контролем. Смерть Main в окне, когда credentials очистили PDEATHSIG, не даёт
успешного результата helper. До release этот helper не вызывается: actual
held child в данной source-модели остаётся fixed root0 и заканчивается.

Проверка drop в ordinary model не является фактическим изменением UID/GID,
проверкой cross-UID ptrace или runtime proof. Обычный будущий Node exec может
изменить dumpable; separate identity и genuine trusted origin не заменяются
одним dumpable check.

## Descriptor custody и child gate

Перед acquisition проверяются высокие (`>=32`), distinct, CLOEXEC inputs.
Reader/writer каждой output пары должны иметь согласованный FIFO inode и
направление, а reader — O_NONBLOCK. Это не доказывает отсутствие aliases:
оно требуется от fixed native producer.

| Ресурс | Кто владеет и когда закрывается |
|---|---|
| Входные listener, singleton, V pidfd, userns, input/control, context/bundle/addon/image | Заимствованы у Main. Parent core их не закрывает. Child имеет отдельную FD table и закрывает свои copies/aliases. |
| Main self pidfd | Создаётся самим core, сразу заносится в custody, поднимается в высокий FD. Parent закрывает свою копию после clone; child сохраняет FD5. |
| Gate read/write | Оба результата pipe2 сразу заносятся в custody. Partial acquisition/relocation закрывает только фактически принадлежащие core handles. Parent после clone закрывает read; child закрывает write. |
| H pidfd | Результат atomic clone сохраняется до первого fcntl/close/poll/clock. Не пересоздаётся по PID. Retain до подтверждённого cleanup либо остаётся pending. |
| Output writer/readers | Только после actual birth передаются parent core. Parent закрывает свои writers; readers удерживает до отдельных read==0 и cleanup. На preflight/clone failure эти входы остаются у producer. |
| Временные `/proc/self/ns/user` descriptors | Только internally opened; закрываются один раз, parent raw close events сохраняются. |

**Первой child FD операцией является close actual sole inherited listener.**
Это происходит до fallible PDEATHSIG/parent checks, чтобы ранний `_exit` не
зависел от порядка kernel fdtable cleanup относительно singleton. Затем
закрывается противоположный gate end, ставится PDEATHSIG и проверяется Main.
Singleton дублируется в FD15 и остаётся до закрытия всех unlisted/high FDs.
После этого FD15 закрывается. Другие listener aliases исключаются B5.

Зафиксирована карта: 0 FIRST DATA/negative input, 1/2 output, 4 private
control, 5 actual Main pidfd, 6 V pidfd, 7 sealed context DATA, 8 sealed bundle
DATA, 9 sealed addon DATA, 10 held userns, 12 transient gate, 20 held image
DATA. FD3 и unlisted FDs закрыты; FD12/20 имеют CLOEXEC. Срез не читает FIRST,
не трактует queued FIRST как смерть, не предоставляет raw project/history/
key descriptors и не использует bundle/addon/image как разрешение.

Gate делает **один** poll с конечным timeout, не превышающим оставшийся W
(округление вниз); нет бесконечного EINTR retry. EOF, любой байт, HUP/ERR,
Main/V death, timeout и interrupt заканчивают child. Положительного gate
сообщения в протоколе этого среза нет. После W gate bytes не читаются.
Child snapshot не видит поздних изменений `slot.failed` в parent, поскольку
нет CLONE_VM. Отмена передаётся через закрытие gate writer и actual pidfd
SIGKILL; local-copy flags не выдаются за межпроцессное уведомление.

В будущем FD8/9 должны пережить именно Node exec, а native bootstrap должен
закрыть/поставить CLOEXEC всем private roles до любого descendant birth.
**Эта postexec стадия не реализована.** В текущем срезе нет exec/descendant
birth; FD20 сохранён как DATA с CLOEXEC, но не исполняется.

## Время, сигналы и raw cleanup receipt

Сохраняются original requested S/W/C и min-only effective W/C; все bounds
должны быть ненулевыми/упорядоченными и представимыми в signed 64-bit ns.
Work current читает clock после V liveness; непосредственно перед clone
есть свежая проверка после profile/namespace. Постпроверка после clone
не превращает поздний birth в release: только cancellation.

Signal может стать pending между последней pre-clone проверкой и syscall.
В single-thread fixed Main это не разрешает никакого body: возможный atomic
birth остаётся gated и отменяется после наблюдения stop/death/deadline.
Абсолютное утверждение «никогда не возникнет child после физической доставки
асинхронного сигнала» здесь не заявлено.

Clock error, zero, overflow или движение назад устанавливают sticky
`timing_unknown`. Наблюдение C устанавливает sticky `deadline_expired`.
После этих фактов новые wait/drain attempts и signal retries не начинаются,
даже если следующий model clock снова меньше C. Между work/cancel и wait,
между wait и каждым output read время проверяется повторно. Неизвестная
custody сохраняется; нет новой cleanup deadline и нет timeout==success.

Первый обязательный terminal SIGKILL и закрытие gate допустимы даже при
обнаружении уже истёкшего C. Это прекращение работы, а не поздний work/exec.
Повторные EINTR/EAGAIN signal attempts разрешены только до C, максимум восемь.
Все восемь возможных результатов сохраняются с fd, rc, errno и clock bracket.
ESRCH не означает reap. Сигнал посылается только по actual saved birth pidfd;
числовой PID применяется в receipt лишь как сопоставляемое наблюдение.

`waitid(P_PIDFD, ..., WEXITED|WNOHANG)` должен дать SIGCHLD, тот же child PID,
UID0 для **этого held-root-only пути** и CLD_EXITED/KILLED/DUMPED. ECHILD,
чужой PID/UID/code/signo и неизвестный result не становятся reaped. UID0
здесь нельзя молча заменить HUID без нового review режима drop/release.

Raw receipt различает вызов signal, actual reap, stdout read==0, stderr
read==0, первое полное cleanup observation и своевременность этого observation.
Read>0, POLLHUP, ESRCH, successful kill или один EOF не заменяют остальные
факты. Source receipt хранит latest wait/read raw result+errno, их счётчики,
последний siginfo, полную ограниченную signal history и parent owned close
history. Это **не полный бесконечный журнал всех EAGAIN**; для воспроизводимых
ordinary tests полный порядок wrapper events сохраняется в raw test output.

Первая полная observation замораживается: повторные progress/cancel/release
не меняют её timestamp, не демотируют состояние и не запускают новые wait,
read или signal. Если последний read начался до C, но вернулся после C,
факты read0/reap записываются, а timely_cleanup остаётся false. Уже
подтверждённые facts можно освободить через finish; это не поздний успех
работы. Если необходимых фактов нет, finish возвращает EBUSY и сохраняет
handles. Внешняя recovery после C отдельно не реализована.

`timely_cleanup` относится к wait+EOF observation, не к успешности каждого
последующего close. Close error имеет собственный sticky `close_fault`; finish
возвращает EIO. Перед close owned number убирается из custody, и Linux close
не повторяется после EINTR, чтобы не закрыть переиспользованный номер.
Смена поля на -1 не выдаётся за успешный kernel close.

## Проверка и предел доказательств

Обязательная последовательность этого этапа: контракт/review → source review →
ordinary compile-only native object → actual-include C model с заменёнными
syscall/libc operations → raw review. Модель проверяет именно функции include,
а не отдельную переписанную state machine. Build subject не запускается;
модель не содержит незаменённых process/FD/credential/time вызовов, что
проверяется undefined-symbol gate.

Source, compiler и ordinary model evidence не доказывают фактическую работу
Linux clone/pidfd/PDEATHSIG, privilege drop, proc metadata, listener teardown,
Node/dlopen/DSO graph, hostile ptrace, physical process death или hard I/O
latency. Эти runtime проверки NOT_RUN. Protected graph, FS/runtime/key
delegation, public selector и продуктовые библиотеки не изменялись.

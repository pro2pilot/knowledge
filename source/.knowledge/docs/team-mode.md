# Team mode — 3.4.4 RC5

Ветка: Knowledge 3.4.4 RC5, аудит
`independent-audit.20261027.reliability.4`. Точные source/package pins для
собранного кандидата фиксируются после новой сборки и qualification; прежние
675-file baseline hashes не идентифицируют текущий кандидат. Исходная проектная
спецификация 3.2.4 сохранена в архиве входных материалов.

## Текущие reliability-границы

- Darwin native verification существует как production isolated-copy pipeline,
  но выключен по умолчанию даже при готовом broker. Явный opt-in требует
  `native_execution.darwin.enabled=true`, `mode="isolated_copy"`, broker paths
  и copy limits. Broker service и reserved private UID готовятся отдельно
  администратором. Writable Flow/Team — другая capability: для неё нужен отдельно
  provisioned workspace и соответствующая административная конфигурация;
  isolated-copy verification не предоставляет запись в исходный проект.
- Public lock-owner publication использует staged atomic path: private, never-reused
  directory сначала получает owner metadata (и execution-scope descriptor, если
  он есть), данные fsync-ятся и перечитываются, затем подготовленный каталог
  публикуется атомарным native no-replace primitive. До публикации public lock
  отсутствует; crash в стадии подготовки не оставляет ownerless public mutex.
  Реализация есть в `tools/lib/contained-lock-manager.js`; это не заменяет
  platform-specific physical qualification.
- Targeted Team run прошёл 7 physical cases и все 8 shipping steps. Doctor
  сообщил 86/100 `usable_with_warnings` с двумя подлинными medium warnings:
  `suspect_module` и `low_confidence_module`; это не повышает доверие к модулям.
  Hosted result ограничен этой выборкой и не квалифицирует stock macOS/SIP.
- Свежий targeted current-source physical run на Windows x64 / Node 22.17.1
  прошёл 61 selected TAP cases и 20 runtime-safety checks. Reducer correction
  переинтерпретировал сохранённый TAP и не повторял физические тесты. Это не
  ARM64 qualification и не full release gate.
- Для restricted Linux hosts принято направление отдельного system broker с
  isolated copy, но production implementation и qualification ещё отсутствуют.
  Hosted Ubuntu 24.04 ARM64 отказал в nested PID namespace с `EPERM`; host policy
  не меняли.
- Причина исторического второго ownerless lock остаётся **UNKNOWN**.

Все результаты относятся к точному source snapshot. Итоговый установленный ZIP
ещё ожидает полной runtime qualification.

## Область действия

Team mode включается явно. Каждый агент работает в выбранном repository/worktree,
с собственным workspace ID и agent ID. Реестр и координационные блокировки лежат
в общем team root. Curated knowledge остаётся частью выбранного checkout;
генерируемое состояние может находиться в отдельном workspace state.

| Корень | Назначение |
|---|---|
| `systemRoot` | Код инструментов, шаблоны, интеграции и документация |
| `targetRoot` | Выбранный repository/worktree |
| `projectKnowledgeRoot` | Curated knowledge выбранного checkout |
| `stateRoot` | Генерируемое состояние и журналы выбранного workspace |
| `teamRoot` | Общий реестр, события и координация Team |

В обычном repo mode регистрация workspace и team root не требуются. Team mode
не заменяет Git и не делает одновременные изменения в одном dirty working tree
безопасными. Практический рабочий порядок — отдельная branch/worktree на задачу.

Новые владельцы используют `knowledge-lock-owner.v2`. Каталоги остаются в
`locks/v1`: смена пути создала бы две независимые блокировки для старого и нового
writer. `hostname` сохраняется для диагностики и не определяет область PID.
На Linux owner содержит kernel boot ID, identity PID namespace, точные start
ticks и подтверждённые координаты PID в собственном namespace и в procfs view.
Сравнение выполняется до и после process probe. Owner неизвестной области
сохраняется, независимо от возраста.

Это не распределённая lease/fencing система. При разных hosts/boots, недоступной
native identity или неподтверждённой области автоматическое восстановление
блокировки запрещено. Обычный acquire после штатного release владельца остаётся
доступен. На Windows/macOS provider точной области для общего lock manager ещё
не квалифицирован: новый owner записывается с `native_identity: null`, а
автоматический stale reclaim после аварии остаётся ограничением доступности.
Это отдельный вопрос от native Job/broker cleanup. Наличие production macOS
verification broker не квалифицирует общий lock manager recovery provider на
Windows или macOS.

## Регистрация и запуск

Следующие команды показывают набор аргументов. Замените пути и идентификаторы
на выбранные значения; используйте одну и ту же комбинацию во всём workflow.

```bash
node .knowledge/tools/team-init.js --team-root /path/to/team --target-root /path/to/repo --json
node .knowledge/tools/workspace-register.js --team-root /path/to/team --workspace-id ws-a --agent-id agent-a --target-root /path/to/repo --json
node .knowledge/tools/flow.js doctor --team-root /path/to/team --workspace-id ws-a --agent-id agent-a --target-root /path/to/repo --exclusive --json
node .knowledge/tools/team-status.js --team-root /path/to/team --workspace-id ws-a --agent-id agent-a --target-root /path/to/repo --json
```

Для нестандартного состояния добавьте `--state-root /path/to/team/custom/ws-a`.
Выбранный каталог должен быть **строгим физическим потомком** `teamRoot`: сам
team root и путь вне него недопустимы. Существующие родители, каталог состояния
и `maintenance/flow-logs` должны пройти проверку физической границы. Flow делает
эту проверку до начала шагов. Безопасный отсутствующий вложенный каталог допустим.
В start record сохраняется именно выбранный state root, а не автоматически
подставленный канонический путь.

При работе с отдельным местом установки укажите также `--system-root` и
`--project-knowledge-root`. Не определяйте выбранный репозиторий только по текущему
каталогу shell; проверяйте корни и IDs в JSON-результате команды.

## Что означает завершение попытки

Каждый новый запуск получает отдельный `run_id` и неизменяемую start record TFR v2.
В ней закреплены repository, workspace, agent, flow, выбранный state root,
target/project roots и, при наличии, связь с предыдущей неуспешной попыткой.
Завершение создаётся после освобождения flow lock.

Авторитетным источником является reader finalization records. Событие `flow_end`
и сырое поле `workspace.last_status` могут предшествовать освобождению блокировки;
сами по себе они не подтверждают успешное завершение всего запуска.

| Наблюдение текущей попытки | Как читать результат |
|---|---|
| Валидная v2 start/final и соответствующий flow log | Завершённая попытка; `binding_version: run_bound_v2` |
| Валидная завершённая v1 запись | Историческое завершение; `binding_version: legacy_v1` |
| Start существует, final отсутствует | Попытка незавершена; прежний успех не наследуется |
| Final физически есть, но он null, повреждён или не соответствует start/log | Недостоверное завершение; invalid/unknown |
| Ошибка release либо finalization после выполненных шагов | Ошибка завершения; выполненные шаги сохраняются в диагностике |
| Запись выполнена, но readback завершился ошибкой | `write_completed_readback_failed`; сначала сверить сохранённую запись |

Для v2 reader сверяет run/context, статус и счётчики фактического flow log,
его местонахождение и физическую привязку. Изменение возвращённого caller-объекта
start не меняет сохранённую authority. Нельзя подставить чужой flow log только
потому, что он существует и имеет корректный JSON.

Team Status, Team PR Summary и Inspector показывают результат именно текущей
попытки. В Inspector доступны attempt ID, binding version и выбранный state root.
Для custom state это также позволяет проверить, что панель показывает нужное
состояние, а не старый отчёт из канонического каталога.

## Повтор и совместимость v1

Повтор не выполняется автоматически. После валидно завершённой неуспешной
попытки того же flow явный `--retry-of=<run-id>` создаёт новую попытку с новым ID.
Старая запись остаётся неизменной. Если исходная попытка неоднозначна,
незавершена либо её запись повреждена, сначала требуется разбор фактических
событий, блокировки и журнала; этот флаг не превращает unknown в разрешённый retry.

Завершённые корректные v1 записи остаются читаемыми. Незавершённую v1 попытку
нельзя просто дописать v2 final. Не удаляйте её и не меняйте вручную поля версии
для обхода сверки. Новый запуск и миграционное решение должны сохранять историю.

Если основной шаг уже ошибся, его code остаётся primary. Ошибки release,
публикации события и финальной записи сохраняются отдельно. Ошибка чтения после
записи требует сверки persisted record, а не немедленного повторного запуска.

## Doctor и ownerless locks

Doctor проверяет lock layout выбранных state/project roots и показывает
операционную блокировку отдельно от содержательной готовности. Team status
отдельно проверяет существующий registry lock. Это наблюдение на момент чтения;
оно не обещает успех следующего acquire и не охватывает все корни одним вызовом.

Отсутствие owner metadata не даёт права удалить lock. Неопределённый владелец,
подмена физического каталога, изменившиеся owner bytes и несогласованная layout
должны оставлять проверяемую диагностику. Cleanup может освобождать только то,
чью физическую идентичность и владение подтверждает текущая операция.

Валидный lock с неизвестной областью владельца сохраняется независимо от возраста.
Прежний remote threshold 24 часа не является lease и не разрешает reclaim.
Без подтверждённой области нельзя отличить умершего удалённого владельца от
медленного процесса, спящей машины или сетевого разделения. Contender ждёт в
пределах обычного lock timeout и получает `lock_timeout`, не изменяя owner bytes.
Диагностика сохраняет `owner_disposition` и, когда нужна native проверка,
`recovery_required`. Универсального безопасного force unlock здесь нет.

При захвате физически безопасного каталога без owner metadata contender ждёт
в пределах исходного бюджета acquire. Двухсекундный диагностический порог больше
не обрывает ожидание медленного writer. При исчерпании бюджета возвращается
`lock_timeout` с `owner_initialization_unconfirmed` и `owner_metadata_evidence`;
каталог не удаляется. Read-only Doctor по-прежнему показывает старый ownerless
каталог как проблему. Успешное stale recovery тоже не начинает бюджет заново:
после его истечения новый owner не публикуется.

Бюджеты acquisition и повторного release при Windows sharing violation
измеряются монотонными часами. Перевод системных часов не продлевает и не
сокращает эти бюджеты. Wall timestamps владельца и возраст stale metadata
сохраняют прежний смысл; перевод часов назад может отложить stale eligibility
и привести к консервативному отказу recovery. Зависший kernel или синхронный
filesystem I/O не получает от этого обещания жёсткого времени возврата.

Автоматический reclaim нового Linux owner требует `ESRCH` в доказанно правильной
координате: собственный PID при совпадении owner PID namespace либо записанный
proc PID у наблюдателя с одним native `NSpid` в том же procfs view. Обе ветки
требуют одинаковый подтверждённый physical procfs object. Provider
`linux_procfs_held_v1` удерживает private descriptor этого объекта на всё время
жизни writer; это сохраняет его incarnation, даже когда отдельный lock уже
освобождён. Nested authority с ограниченными capabilities не обязан читать
чужие namespace objects и не получает дополнительных прав.

Boot/scope и фактическая visibility procfs должны оставаться неизменными до и
после probe. Hidden/ambiguous mount, недоступные metadata и смена `/proc` дают
unknown. Если в подтверждённой proc coordinate есть процесс, `ESRCH` считается
противоречивым и не разрешает eviction: syscall filter может вернуть этот errno
без проверки PID. Возраст, owner bytes и physical identity каталога проверяются
отдельно. Production stale threshold остаётся 120 секунд, обычное ожидание
acquire — 30 секунд.

Восстановленная owner generation перемещается в один детерминированный непустой
каталог `locks/v1/.stale/`. Он сохраняется как барьер для запоздавшего contender:
повторный rename той же generation не может переместить нового живого владельца.
Такую историю нельзя очищать по возрасту, считать временными файлами или удалять
для force unlock. Обычный acquire/release не создаёт эту историю; сохраняется
одна запись на восстановленную generation. Повторное появление уже восстановленной
generation и повреждённый history target дают отказ без изменения public owner.
Удаление истории потребует отдельного протокола с доказанным завершением всех
старых writers; сейчас автоматического GC нет.

Occupied или повторно использованный PID остаётся занятым. `EPERM` сохраняет
occupied семантику; прочие ошибки дают unknown. Ни `/proc` ENOENT, ни несовпадение
start ticks, ни один hostname не разрешают удалить lock. Provider использует
фиксированные kernel paths; сканирование всех процессов и caller-supplied
identity не используются. Если procfs/nsfs или native witness недоступны,
automatic reclaim остаётся недоступным.

Оставшийся после crash mutex с другим boot ID или несопоставимой procfs scope
сохраняется как unknown. Автоматическое восстановление после настоящего reboot
ОС, переноса stateRoot на другой host или смены native scope ещё не
квалифицировано и может остаться заблокированным. Чистый shutdown без оставшихся
claims этим ограничением не блокируется. Совпадение hostname и большой возраст
не заменяют отдельный протокол миграции и доказанное завершение старых writers.

Writer не должен закрывать private anchor или выполнять exec-in-place после
acquire: перенос владения через exec/CLOEXEC требует отдельного протокола и
здесь не поддержан. Обычный spawn дочерней команды не закрывает descriptor
родителя. Kernel identities рассчитаны на кооперативных writers одного host;
они не заменяют distributed fencing на shared storage и не квалифицируют
одновременное восстановление нескольких машин из одного running VM snapshot.

Legacy `.lock` и owner v1 остаются читаемыми, но не получают выдуманную область
процессов. Новый код не удаляет их по PID/возрасту и не переписывает их в v2.
Перед обновлением следует завершить writers старой версии и дать им штатно
освободить блокировки. Старый reader не понимает v2 owner; смешанное выполнение
старых и новых writers не является поддерживаемым rolling upgrade. Оставшийся
после аварии legacy owner требует разбора сохранённых событий и фактического
владения. Doctor и Team status наблюдают состояние; высокий content score не
разрешает diagnostic reader освобождать native claim.

Текущая реализация устраняет окно публикации owner metadata для нового lock:
owner подготавливается и проверяется в отдельном private каталоге до атомарной
публикации public lock. Crash до rename/native no-replace оставляет только
private stage, а не public ownerless mutex. Recovery старых ownerless locks
остаётся консервативным: неизвестный владелец не становится свободным, и старые
каталоги автоматически не удаляются.

Причина исторической второй блокировки без исходного process/event trace
остаётся неизвестной. Новые физические тесты показывают поведение этой версии
при заданном сценарии; они не устанавливают создателя старого lock.

## Что ещё требует отдельного запуска

Переносимые проверки Team registry, finalization, выбранных корней, CLI и Inspector
выполнены на Linux в собственных тестовых репозиториях. Fault injection явно
отмечен в аудите. Он не заменяет реальный Windows filesystem/process lifecycle.
Native verification на Linux сейчас зависит от доступности PID namespace, pidfd
и подготовленного закреплённого helper. Принятый вариант отдельного system
broker и isolated copy ещё не реализован и не квалифицирован. При отсутствии
prerequisites возвращается
`verification_containment_unavailable` до claim и запуска verification worker.
Darwin isolated-copy production path запускается только при явном request opt-in;
`--qualification-mode` и временные-root QA fixtures остаются diagnostic-only и
не разрешают normal production admission. Writable Flow/Team требуют отдельной
административной подготовки и qualification. Свежий targeted physical Windows
x64 / Node 22.17.1 run прошёл 61 TAP cases и 20 runtime-safety checks. Team
evidence показывает 7/7 physical cases, 8/8 shipping steps и Doctor 86/100 с
двумя medium warnings. Свежая ARM64 и конечная installed-ZIP qualification
открыты. Scoped
результаты и исторический CI не заменяют qualification новых artifact bytes.

[Исторический аудит механизмов](audit-3.4.4-rc5-mechanisms.md) сохраняет результаты
своей прежней ревизии. [Текущий execution contract](verification-execution-contract.md)
описывает действующие границы. Числа нового прогона, raw-команды, critic scenarios
и SHA находятся в handoff этой ревизии. Live external providers и full release
gate проверяются отдельно.

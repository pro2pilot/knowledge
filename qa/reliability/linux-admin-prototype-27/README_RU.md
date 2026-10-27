# QA-only: проверка AppArmor admin-mode primitives

**Не реализует production runtime. Не запускалось автором. Не пушить/запускать без root-review workflow.**

Содержит фиксированный C probe и inert static tracer-control: ни один argv не задаёт исполняемый
файл, script, профиль или произвольную команду. Ровно один временный root-owned
STATIC ELF binary устанавливается под уникальным `/opt/knowledge-qa27-<uuid>/`; generic
Node/Python/standard helper не профилируются. Профили authority/worker уникальны
для прогона. Системные sysctl, существующие profiles, SUID/filecaps не меняются.

`run_probe.py` должен выполняться непривилегированным dedicated QA UID/GID1001,
с observed profile `unconfined` и доступным `sudo -n` для отдельных install,
apparmor_parser и удаления **только своих** fixed files. Не запускать весь
контроллер под sudo. Требуется Linux с pidfd, AppArmor enforcing/userns restriction1,
ABI4 policy, C compiler, Python с pidfd API. Root-owned `/opt` не должен быть
symlink или writable другими. Выходной каталог — новый descendant этой QA папки.

После проверки исходников и workflow root может вызвать (пример, не исполнен):

```text
python3 qa/reliability/linux-admin-prototype-27/run_probe.py --out qa/reliability/linux-admin-prototype-27/runs/<unique-name>
```

Из cwd worktree `r27-critic`; никаких production installation commands этот probe
не создаёт. Сначала обычным user компилируется fixed C с compile-time profile/path,
затем root install защищает binary/profile и загружает только этот policy.
Перед install ELF program headers проверяются: PT_INTERP и PT_DYNAMIC отсутствуют.
Authority profile не разрешает blanket mmap `/lib/**` или пользовательских библиотек.
Нужен доступный static libc toolchain; если его нет, probe отказывает, не переходит
молча на динамический privileged bootstrap.

Проверки:

- User-owned .so constructor пишет fixed marker и вызывает `_exit(93)`. Для
  LD_PRELOAD и LD_AUDIT positive control на `/usr/bin/true` обязан подтвердить
  работоспособность sentinel; installed static C с теми же loader inputs должен
  дойти до фиксированного authority-label check с exit0 без marker. Exit sentinel
  ловит инъекцию даже если AppArmor запретит constructor запись marker. User .so
  не становится частью trusted closure и никогда не устанавливается root.
- Same-UID unconfined parent пытается ptrace attach, process_vm read/write, proc-mem
  read/write и открыть фактический private fd authority. Только owned paused C
  target и известный fixed marker; изменение памяти при неожиданно разрешённом
  write записывает то же значение, не исполняет инъекцию. Нужны EPERM/EACCES.
- Отдельный inherited-tracer контроль: собственный child вызывает TRACEME и
  останавливается до exec. Inert static positive target должен успешно выполнить
  exec под tracer (TRACEEXEC event) и завершиться exit0. Fixed authority target
  должен получить EPERM/EACCES от exec ядра без TRACEEXEC. Успешный exec с ранним
  userspace tracer refusal фиксируется отдельно и даёт FAIL границы: активный
  tracer мог переписать guard до первой инструкции. Тест не изменяет инструкции,
  регистры или память. EXITKILL и точный child pidfd ограничивают очистку; timeout
  5s плюс cleanup2s на target. Неподтверждённый cleanup запрещает unload профиля.
- Authority (UID/GID1001, host capabilities0) ставит NNP и создаёт три настоящих
  уровня user/PID namespaces. На каждом worker caller drops only its own newly
  namespaced capabilities to0 после locked NOROOT/NO_SETUID_FIXUP; проверяет
  profile/real-effective-saved UID/GID/NNP/securebits/dumpable1/zero capabilities.
  AppArmor `setpcap` разрешён только authority для namespaced securebits setup,
  не выдаёт host capability; worker `audit deny capability` остаётся.
- Leaf делает явный необратимый **stack** worker component после NNP перед fixed
  adversarial simulation. Это не replacement/fallback: authority restrictions
  сохраняются, а worker deny пересекаются с ними. Новый userns и change back запрещены ядром. Исполнение
  того же fixed helper с `ix` должно сохранять worker label для `--identity`;
  повтор `--suite` от worker должен отказать до создания namespaces.
  Проверяется и записывается exact compound label с двумя известными components;
  authority-only и неизвестный дополнительный component не принимаются. Peer
  rules перечисляют только exact own labels/stacks; нет wildcard/unconfined ptrace.
- Каждый владелец завершает точный namespace init через захваченный pidfd и
  waitpid. Закрытие внешнего init покрывает его descendants. Три closure events,
  три depth events, worker negatives и parent denials обязательны для scoped PASS.

Root process имеет C alarm25s, supervisor40s; timeout — FAIL, не PASS. Если native
closure не доказан, контроллер **не удаляет профили/installation**, фиксирует
cleanup_unconfirmed и точное own path для административного разбора. Это намеренный
fail closed: exit/PID absence не заменяют proof. При штатном подтверждённом drain
удаляются свои profile и два fixed files; recursive delete/glob не используются.
Ошибки setup/partial profile add также проверяются на остаток exact own labels.

`stdout.private.log` содержит private pid/address/fd тестового marker; не загружать
его публично автоматически. `summary.json` проецирует результаты без адреса и
raw PID. Оба лога private0600, output directory0700. Собственный profile name и
уникальный `/opt` path не являются пользовательскими проектными данными.

Ограничения: не проверяет Node/Git entry dispatch, production authority closure,
контексты workspace, KVE/ACK, full runtime, bounding-set contract или
production install/update/recovery. Не решает возможный cross-label observer
fallback; он требует отдельной проверки с outer proof relay. Успешный scoped
primitive result — основание для следующей design-review, не Linux support PASS.

Обоснование explicit stack: kernel AppArmor `aa_change_profile` отдельно проверяет
NNP для replacement, тогда как stacking является добавлением ограничений.
[Kernel6.17 domain.c](https://raw.githubusercontent.com/torvalds/linux/v6.17/security/apparmor/domain.c),
[libapparmor aa_stack_profile](https://gitlab.com/apparmor/apparmor/-/blob/master/libraries/libapparmor/src/kernel.c),
[AppArmor stacking policy](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmorStacking).

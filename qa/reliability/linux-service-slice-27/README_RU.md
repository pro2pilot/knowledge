# Linux service: закрытый этап интеграции

Рабочий каталог следующего физического QA после `linux-admin-service-27`.
Это не установленный backend, не release candidate и не доказательство KVE/ACK.
Production dispatch остаётся выключенным.

Цель этапа: обычный caller передаёт bytes проекта; отдельный фиксированный
Node importer под A UID проверяет их и создаёт копию. Native init дожидается
выхода importer, делает источник доступным только для чтения, затем запускает
фиксированную authority и реальный Node test под отдельным W UID. Для записи
есть отдельный scratch. Полезная работа и cleanup находятся под независимым
keeper. Root не читает исходный проект и не исполняет его код.

Изменяемый проект, nested Flow, KVE/KVR, импорт результата в исходный проект,
production installation/update/recovery и релизная приёмка этим этапом не
закрываются. Пока физический результат не сохранён и не проверен, статус —
IMPLEMENTATION IN PROGRESS, а не PASS.

## Фиксированные аварийные режимы

`controller.py prepare --fault` принимает пять закрытых профилей: `none`,
`import-receipt-held`, `result-held`, `keeper-during-drain`, `broker-during-drain`.
Последние два сначала выполняют настоящий importer и Node test. Namespace init
удерживает результат на приватной pipe; первоначальный work deadline остаётся
30 секунд. Keeper A отправляет настоящий `SIGKILL` через удерживаемый pidfd init
и останавливается на барьере **до wait/reap и подтверждения cleanup**.

В этих двух профилях отдельный фиксированный native-наблюдатель C удерживает
собственные pidfd B, A и init. Он получает совпадающие сообщения о начале drain
от A и B, сверяет kernel `SCM_CREDENTIALS`, pidfd identities, первоначальный
cleanup deadline и живые A/B. Только после этого C посылает `SIGKILL` через
удерживаемый pidfd выбранного holder. При смерти A cleanup завершает B через
subreaper и ранее полученный init pidfd. При смерти B оставшийся A продолжает
свой первоначальный drain. C самостоятельно проверяет конец output pipe,
статусы завершения holders и пустую work cgroup; результат принимается только
при подтверждённом reap init оставшимся holder в исходном бюджете 10 секунд.
Аварийная уборка самим C всегда отвергает эксперимент.

Граница проверяется после реальной отправки stop и до reap, поэтому init уже
может завершиться к моменту смерти holder. Поле `drain_init_exit_before_fault`
сохраняет это наблюдение. Режимы не изображают зависание диска, kernel D-state
или гарантированно живой после SIGKILL init. Они подтверждают продолжение
незавершённой stop/reap-транзакции вторым holder. Статус полезной работы остаётся
`FAIL`, success ACK запрещён; `ACCEPTED_FAULT_QA` обозначает только успешный
аварийный эксперимент компонента.

`qa/reliability/audit5/run_faults.py --out DIR` запускает все пять профилей и
отдельную post-exit acceptance. Для ограниченного повторного запуска новых
сценариев доступны `--modes keeper-during-drain broker-during-drain`.
Каждый raw proof, prepare receipt и отдельный acceptance сохраняются; исходники
QA привязаны SHA-256, результаты прежних запусков не перезаписываются.

WINDOWS: ПАРНЫЙ ПРОГОН СВЯЗИ NODE PARENT JOB

Цель: проверить одну product-правку после двух одинаковых native отказов
original CLI SIGKILL на Windows x64/ARM64 в runtime05. Диагностические
before/after используют ровно одинаковые 32 named cases и native C bytes.
Между ними изменён только tools/lib/command-windows-runtime.js:
фиксированные primary/secondary holders запускаются с detached:true.
609 других файлов, их executable modes и все assertions идентичны.

ПРИЧИНА ПО ИСХОДНИКАМ
Node v22.17.1 deps/uv/src/win/process.c, SHA256
39516fc8c2316ec53b853a67301958796372676fb1b27d4ec76ec51217ae6f26:
libuv создаёт собственный non-inheritable Job с KILL_ON_JOB_CLOSE и
добавляет в него каждого недетаченного непосредственного ребёнка.
Поэтому secondary, находящийся вне нашего A Job, всё ещё погибает при
смерти исходного Node M. Это объяснение подтверждено source review,
а новая физическая проверка after ещё обязательна.

Изменение не использует unref, не меняет guard/payload spawn и не
отключает native parent/process-handle/pipe watchdogs. Процесс и IPC
остаются учтёнными до фактического завершения. В точном libuv коде
detached не включает CREATE_BREAKAWAY_FROM_JOB: произвольные внешние
Jobs не обходятся. До native arm остаётся отдельная граница зависшего
pre-init I/O при смерти M; до bound/permit Project/Team работа не
допускается. Этот парный прогон не объявляет такую границу закрытой.

ТОЧНЫЙ ВХОД БЕЗ ПОВТОРНОЙ ПЕРЕДАЧИ БОЛЬШОГО BINARY BLOB
derive_inputs.py читает уже опубликованный runtime05 архив:
qa/reliability/runtime-qa/SOURCE.zip
SHA256 9f23726b5c23ad71419099ba743c5f1c52637748267851651a6b9027a1bfef46.
Проверяются весь ZIP inventory, CRC, hashes каждого member и modes.
Пять объявленных source-only overlays создают прежний frozen diagnostic
cohort. After добавляет только reviewed runtime-file overlay.
Каждый итоговый ZIP проверяется против полного manifest и SHA256.
Использован ZIP_STORED, чтобы одинаковые bytes не зависели от zlib runner.

Before: 610 files, 6,723,578 bytes, SHA256
d6bd84a91ac6df909b67776edb755f3d11bc19db1f33596185de9ad45c2daa41.
After: 610 files, 6,723,827 bytes, SHA256
e26d33824e988bdd1c21e2e086de20ba21dcc5d42b4784fd816baf1d492ac894.

CI И ОЦЕНКА РЕЗУЛЬТАТОВ
Четыре независимых jobs: before/after × Windows x64/ARM64, Node22.17.1.
fail-fast:false; continue-on-error отсутствует. Baseline FAIL остаётся
реальным FAIL в raw evidence и GitHub job status. Общий красный статус
этого парного исследования нельзя путать с результатом after cohort.
Для after необходим полный точный32 inventory:29 PASS и3 заранее
названных Linux-only SKIP; дополнительные/пропущенные cases либо SKIP
отклоняются текущим native_qa.py. Ни input derivation PASS, ни compile
не считаются подтверждением Windows lifecycle.

Изменение затрагивает только отдельный QA path/workflow в изолированной
ветке. Main, tags, релиз и host security policy не меняются.
Публично загружаются bounded native QA evidence и DERIVATION.json.
Исходники, toolchains, private receipt stores и temp fixtures не
загружаются. При неопределённом завершении фикстуры сохраняются runner.

ПУБЛИКАЦИЯ
PUBLISH_INVENTORY.json и TREE_TEXT.json перечисляют точные text assets.
Каталоги local-verified и preparation-attempt1-unsorted — локальные
доказательства подготовки, их НЕ нужно включать в Git tree.
Первый generator attempt имел неверный порядок строк manifest;
неизменённый validator отклонил его до создания derivative archive.
Ошибка и исходные manifests сохранены, native tests тогда не запускались.

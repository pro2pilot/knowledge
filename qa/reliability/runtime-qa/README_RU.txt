НАТИВНАЯ ПРИЁМКА COMMON LOCKS — ЛОКАЛЬНЫЕ CI ASSETS

Эти файлы сами ничего не публикуют. Root переносит конкретный проверяемый
набор в отдельную разрешённую ветку. Main, tags и релиз не изменяются.

1. Заморозить полное дерево текущих исходников в НОВЫЙ выходной каталог:

python reliability/ci-assets/prepare_native_qa.py --source reliability/source/.knowledge --out reliability/ci-assets/frozen-NEW-ID

Подготовка включает исходники, документацию, source-only tests и точную
историческую fixture v2. Все исключения перечислены в SOURCE_MANIFEST.json:
готовые native outputs, .build-*, кэши и top-level runtime state. ZIP имеет
детерминированный порядок, время и режимы файлов. После записи проверяются
CRC, состав, SHA каждого файла и повторный состав исходников, включая
новые/удалённые пути и исполняемый бит. FAIL_SOURCE_CHANGED не публиковать.

2. В удалённый qa/reliability/runtime-qa/ перенести четыре файла:

  native_qa.py
  EXPECTED_CASES.json
  SOURCE.zip                (из новой успешной заморозки)
  SOURCE_MANIFEST.json      (из той же заморозки)

Workflow rc5-reliability-native-runtime.yml положить в .github/workflows/.
Ветка в workflow: codex/rc5-reliability-20261025; permissions contents:read.
Шесть actual-host jobs: Linux, Windows и macOS, x64 и ARM64. Root отдельно
управляет размещением, запуском и чтением фактических результатов jobs.

3. Каждый job проверяет ZIP и извлекает отдельную .knowledge, собирает
N-API 8 из её точного C source, проверяет loader/source/binary binding.
Linux дополнительно собирает точный native helper для реального scope test.
Затем запускаются выбранные common-lock suites и публичный transition test.
Проверки не устанавливают зависимости в пользовательский проект и не
запускают продуктовый updater. Внешние загрузки — только проверяемые по
официальному SHASUMS256.txt архивы/headers/node.lib с nodejs.org.

Дополнительно запускается настоящий Node 18.20.8 с тем же addon: публикация,
аварии, конкуренция, inode binding, loader pins и compatibility. Для win-arm64
официального Node 18.20.8 binary нет: ветка явно NOT_RUN_PLATFORM_NOT_DISTRIBUTED,
что не является успешной проверкой Node18. Node22 ARM64 проверяется отдельно.

EXPECTED_CASES.json требует присутствия каждого из 106 исходных main cases
и 39 ABI cases. Допустимые SKIP перечислены по точным именам и платформам.
Все они остаются видимыми и не засчитываются как выполненная нативная
проверка. Отсутствующий required case, неожиданный SKIP, all-SKIP, TODO,
неполный TAP, таймаут или обрезанный журнал делают результат FAIL.

Ожидаемые количества для текущих тестов (это ожидания, НЕ результаты ОС):
  Linux main: 106 PASS, 0 SKIP; ABI: 39 PASS, 0 SKIP.
  macOS main: 85 PASS, 21 Linux-specific SKIP; ABI: 39 PASS, 0 SKIP.
  Windows main: 79 PASS, 27 POSIX/Linux-specific SKIP;
  Windows x64 ABI: 37 PASS, 2 POSIX-mode/ACL-fixture SKIP.
Каждый новый/изменённый тест требует пересмотра политики ожидаемых cases.

4. Публикуется только native-runtime-qa/public/: ограниченные raw stdout/
stderr, команды, exit statuses, таймауты/неподтверждённая очистка, полные
контрольные суммы, policy cases, source manifest и собранные binaries с
их manifests. toolchains, headers, извлечённый source, .build intermediates,
fixture state и caches не входят в artifact. Лимит журнала 8 MiB на поток;
превышение не скрывается и не превращается в PASS.

Windows timeout убивает только точно удерживаемый Popen HANDLE; без
независимого доказательства дерева cleanup остаётся unconfirmed, job FAIL.
Это поведение оснастки, а не положительная приёмка production cancellation.

Проверенная локальная исходная версия контроллера:
reliability/evidence/locks/native-qa-local-attempt1/public/RESULT.json
  фактический Linux x64 Node24.22.1: 106/106, public22/22;
  фактический скачанный Node18.20.8: 39/39; входные исходники не изменились.
Независимый критик затем выявил две ошибки evidence guards (all-SKIP и
неучтённый новый файл/исполняемый бит). Они воспроизведены и исправлены:
reliability/evidence/locks/ci-evidence-guards-before-after/RESULT.json
  четыре реальных filesystem scheduling cases (before/after),
  шесть явно синтетических TAP-policy cases; Windows ими не квалифицируется.
Точные прежние scripts сохранены и SHA сверены с историческими receipts:
reliability/evidence/locks/ci-assets-before-review/PROVENANCE.json

Повтор guard regression:
python reliability/ci-assets/verify_ci_evidence_guards.py --before reliability/evidence/locks/ci-assets-before-review --after reliability/ci-assets --out reliability/evidence/locks/ci-evidence-guards-NEW-ID

Повтор полноценного локального QA (выходной каталог должен отсутствовать):
python reliability/ci-assets/native_qa.py --archive PATH/SOURCE.zip --manifest PATH/SOURCE_MANIFEST.json --out PATH/NEW-QA-OUTPUT --node ABSOLUTE-NODE

Common-lock QA не заменяет production Darwin broker physics, Windows
command-scope custody acceptance, установку/обновление точного candidate ZIP
или полный release gate. Эти scopes ведутся отдельными проверками.

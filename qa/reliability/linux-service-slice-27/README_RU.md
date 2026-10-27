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

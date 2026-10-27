# Linux service boundary: адресная проверка, не production backend

Выбранный пользователем контракт: отдельный системный native broker, разные
служебные UID для authority и команд, изолированная рабочая копия. Root исполняет
только фиксированные native операции; Node и проектные команды не получают root.

Этот первый вертикальный срез проверяет границу ядра на restricted Ubuntu ARM64.
Он не запускает Node, не импортирует пользовательский проект и не выдаёт KVE/ACK.
Никакой результат этого контроллера не квалифицирует production backend.

Нужны systemd system service и cgroup v2. Broker запускается systemd, получает
только фиксированные команды по SOCK_SEQPACKET и проверяет SCM_CREDENTIALS каждого
сообщения. Поддержки SCM_RIGHTS/import FD нет. UID сжигается в root-owned журнале
до рождения процессов; повторное использование в этом срезе запрещено.

Независимый native keeper владеет точным pidfd namespace init, следит за сроком
работы и смертью broker. PDEATHSIG init служит дополнительной остановкой при
смерти keeper. Завершение подтверждается отдельно: exact child wait/pidfd,
закрытие output и cgroup.events populated=0. Systemd cleanup остаётся внешней
страховкой и не превращает незавершённую операцию в PASS.

Глобальные AppArmor/sysctl не меняются. Установка и очистка ограничены новым
уникальным каталогом и новым уникальным service unit контроллера.

Статус: реализация и физическая проверка в работе. Runtime, рабочая копия,
production recovery и release gate этим документом не подтверждаются.

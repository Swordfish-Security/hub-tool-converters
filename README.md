# hub-tool-converters

Набор конвертеров/парсеров отчетов о сканировании из формата сканера в формат AppSec.HUB

## Содержимое репозитория

1. [Модель отчета AppSec.Hub](hub/models/hub.py)
2. [Парсеры форматов инструментов](converters/parsers)
3. [Конфиг файлы](config)
4. [Тесты](tests)

## Документация

1. [Общая документация по импорту отчетов](https://docs.appsec-hub.ru/2024.1/ug/security%20issues/?h=импор#_3)
2. [Схема отчета AppSec.HUB](https://docs.appsec-hub.ru/2024.1/gi/appendix%202/)
3. [Пример отчета в формате AppSec.HUB](https://docs.appsec-hub.ru/2024.1/gi/appendix%202/#_1)

### Параметры запуска

| Параметр          | Описание                                                                                                                               | Обязательный                                          |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| -t; --type        | Тип источника (--help для просмотра всех типов)                                                                                        | Да                                                    |
| -s; --scanner     | Тип сканера (если задан формат, то сканер может быть любым, иначе совпадать с одним из допустимых форматов)                            | Да                                                    |
| -f; --filename    | Путь до отчета сканера                                                                                                                 | Да                                                    |
| -o; --output      | Путь где будет создан отчет в формате AppSec.HUB                                                                                       | Да                                                    |
| -n; --name        | Название репозитория в AppSec.Hub/артефакта/инстанса                                                                                   | Да                                                    |
| -u; --url         | Урл репозитория/артефакта/инстанса                                                                                                     | Да                                                    |
| --format          | Формат входного файла (bandit, burp, checkov, gitleaks, gosec, horusec, mobsf, sarif, semgrep, solidpoint, spotbugs, trufflehog, svace, cyclonedx) | Нет, по умолчанию взято значение из аргумента scanner |
| -b; --branch      | Ветка в репозитории, по которой запускалось сканирование                                                                               | Нет, по умолчанию master                              |
| -c; --commit      | Коммит в репозитории, по которому запускалось сканирование                                                                             | Нет                                                   |
| -bt; --build-tool | Сборщик (--help для просмотра всех сборщиков)                                                                                          | Нет, по умолчанию maven                               |
| --stage           | Стадия экземпляра (ST - System Test, UAT - User Acceptance Test, IAT - Integration Acceptance Test, STG - Stage, PROD - Production)    | Нет                                                   |
| --report-version  | Версия формата отчёта AppSec.HUB (1.0.1, 1.0.2 или 1.0.3, см. раздел «Версии схемы отчёта»)                                           | Нет, по умолчанию 1.0.1                               |

### Список поддерживаемых форматов

bandit, burp, checkov, gitleaks, gosec, horusec, mobsf, sarif, semgrep, solidpoint, spotbugs, trufflehog, cyclonedx, kaspersky-cs, svace(только .csv, в формате .sarif запускать через sarif)

Для kaspersky-cs поддерживаются оба вида JSON-отчёта Kaspersky Container Security:
- отчёт сканирования с блоками `Results[]` (выгрузка через API/CLI);
- «Images Detailed Report» из веб-интерфейса KCS 2.x (`images[].vulnerabilities[]`).

### Версии схемы отчёта

| Версия | Что добавлено | Минимальная версия AppSec.Hub |
|--------|---------------|-------------------------------|
| 1.0.1  | Базовая схема | — |
| 1.0.2  | Структурированные `httpRequest` / `httpResponse` у DAST-находок | — |
| 1.0.3  | Необязательные поля `hasExploit` (правило `sca_s`) и `relation` (находки `sca_s` и `sca_c`) | 2026.4.2 |

Отчёт версии 1.0.3 со значениями этих полей загружается только в AppSec.Hub, который их знает: более ранние версии не принимают отчёт с неизвестными полями целиком. Поля необязательны: если значение не известно, поле не пишется, и отчёт остаётся совместимым с отчётами предыдущих версий.

Поля версии 1.0.3 используются в фильтрах списка уязвимостей AppSec.Hub «by exploit» и «by relation» — так же, как значения, полученные из интеграции с CodeScoring.

| Поле | Где | Значения | Смысл |
|------|-----|----------|-------|
| `hasExploit` | `rules[]` с `"type": "sca_s"` | `true` / `false` | Для уязвимости известен публичный эксплойт. `false` пишется явно, когда инструмент сообщает, что эксплойта нет |
| `relation` | `findings[]` с `"type": "sca_s"` или `"sca_c"` | `direct` / `indirect` (`transitive` — синоним `indirect`) | Уязвимый компонент — прямая или транзитивная зависимость |

Пример фрагмента отчёта:
```json
{
  "rules": [
    {"type": "sca_s", "id": "CVE-2024-0001", "name": "CVE-2024-0001", "severity": "High", "cveId": "CVE-2024-0001", "hasExploit": true}
  ],
  "findings": [
    {"type": "sca_s", "id": "finding-1", "ruleId": "CVE-2024-0001", "locationId": "libfoo@1.0", "relation": "direct"}
  ]
}
```

## Пример запуска

1. Создание виртуального окружения и его активация
```bash
python -m venv venv && source venv/bin/activate
```

2. Установка зависимостей
```bash
pip install -r requirements.txt
```

3. Запуск конвертера
```bash
python main.py -s trufflehog -t CODEBASE -f tests/codebase/trufflehog/v3_github.json -o trufflehog_hub.json -n hub-tool-converters -u https://github.com/Swordfish-Security/hub-tool-converters.git
```

4. Запуск конвертера для сканера с форматом
```bash
python main.py -s pvs-studio -t CODEBASE --format sarif -f pvs-studio.sarif -o pvs-studio_hub.json -n hub-tool-converters -u https://github.com/Swordfish-Security/hub-tool-converters.git
```
или
```bash
python main.py -s svace -t CODEBASE --format sarif -f tests/codebase/svace/svace.sarif -o svace_hub.json -n hub-tool-converters -u https://github.com/Swordfish-Security/hub-tool-converters.git
```

```bash
python main.py -s kaspersky-cs -t ARTIFACT -f input-file.json -o output-file.json -n artifact_name -u https://artifact-url.rpm
```

С признаком эксплойта (схема 1.0.3):
```bash
python main.py -s kaspersky-cs -t ARTIFACT -f input-file.json -o output-file.json -n artifact_name -u https://artifact-url.rpm --report-version 1.0.3
```

5. Запуск конвертера для SolidPoint DAST
```bash
python main.py -s solidpoint -t INSTANCE -f solidpoint_report.json -o solidpoint_hub.json -n my-app -u https://my-app.example.com --stage ST
```

## Запуск тестов

1. Создание виртуального окружения и его активация
```bash
python -m venv venv && source venv/bin/activate
```

2. Установка зависимостей
```bash
pip install -r requirements.txt
```

3. Запуск тестов
```bash
python -m pytest -s
```

## Вносите свой вклад

Вы можете помочь нашему сообществу внеся вклад. Им могут быть:

1. Скрипты для конвертации отчетов о сканировании для различных инструментов в AppSec.HUB
2. Улучшение документации и примеры к ней

Для этого:

1. Сделайте форк этого репозитория;
2. Внесите в нём необходимые изменения;
3. Откройте Pull Request.

### Чеклист для добавления новых скриптов

- [ ] Создать файлы скрипта с кодом в уже существующей директории или создать новую (при необходимости)
- [ ] Обновить или создать README.md в директории. Необходимо указать всю важную информацию:
    - Назначение кода
    - Необходимые библиотеки
    - Способ установки и настройки

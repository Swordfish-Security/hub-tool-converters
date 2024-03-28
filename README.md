# hub-tool-converters

Набор конвертеров/парсеров отчетов о сканировании из формата сканера в формат AppSec.HUB

## Содержимое репозитория

1. [Конвертер формата gitleaks](gitleaks/src/gitleaks_converter.py) на Python

## Документация

1. [Общая документация по импорту отчетов](https://docs.appsec-hub.ru/2024.1/ug/security%20issues/?h=импор#_3)
2. [Схема отчета AppSec.HUB](https://docs.appsec-hub.ru/2024.1/gi/appendix%202/)
3. [Пример отчета в формате AppSec.HUB](https://docs.appsec-hub.ru/2024.1/gi/appendix%202/#_1)

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


### Параметры запуска


| Параметр      | Описание                                                   | Обязательный             |
|---------------|------------------------------------------------------------|--------------------------|
| scanner       | Тип сканера (--help для просмотра всех типов)              | Да                       |
| filename      | Путь до отчета сканера                                     | Да                       |
| output        | Путь где будет создан отчет в формате AppSec.HUB           | Да                       |
| source-name   | Название репозитория в AppSec.Hub                          | Да                       |
| source-url    | Урл репозитория                                            | Да                       |
| source-branch | Ветка в репозитории, по которой запускалось сканирование   | Нет, по умолчанию master |
| source-commit | Коммит в репозитории, по которому запускалось сканирование | Нет, по умолчанию master |


## Пример запуска

python main.py -s gitleaks -f ./tests/gitleaks/gitleaks8_many.json -o wow.json -sn test -su test

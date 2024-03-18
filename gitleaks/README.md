# gitleaks-converter

Пример конвертора из отчета gitleaks в формат AppSec.HUB

## Параметры запуска

| Параметр       | Описание                                                   | Обязательный             |
|----------------|------------------------------------------------------------|--------------------------|
| gitLeaksReport | Путь до отчета в формате gitleaks                          | Да                       |
| hubReport      | Путь где будет создан отчет в формате AppSec.HUB           | Да                       |
| sourceName     | Название репозитория в AppSec.Hub                          | Да                       |
| sourceUrl      | Урл репозитория                                            | Да                       |
| sourceBranch   | Ветка в репозитории, по которой запускалось сканирование   | Нет, по умолчанию master |
| sourceCommit   | Коммит в репозитории, по которому запускалось сканирование | Нет, по умолчанию master |

## Пример запуска

python gitleaks_converter.py -gitLeaksReport gitleaks8_many.json -hubReport hub.json -sourceName github-repository-master -sourceUrl https://github.com/serpol1/dvju.git -sourceBranch main -sourceCommit main

## Необходимые библиотеки
Необходим python 3. Код тестировался на версии 3.10.7.
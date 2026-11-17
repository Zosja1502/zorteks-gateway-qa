# Vanguard Terminal + Zorteks QA Inspector

![Zorteks Go QA Suite](https://github.com)
![Go Version](https://shields.io)
![Python FastAPI](https://shields.io)

Демонстрационный стенд инженерного агентства **[Zorteks QA & Development](https://zorteks.ru)**: корпоративный платёжный шлюз **Vanguard** в связке с интерактивным QA-инспектором и многопоточными автотестами на языке **Go**.

## Быстрый запуск

1. Запуск сервера и дашборда:
```bash
py -m pip install -r requirements.txt
py -m uvicorn main:app --reload
```
Стенд откроется по адресу `http://127.0.0.1:8000`.

2. Запуск многопоточных автотестов на Go (во втором окне терминала):
```bash
go test -v ./...
```

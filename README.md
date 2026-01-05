# CodeSage-AI

## 📜 License
This project is licensed under the [MIT License](LICENSE).

[📜 Политика конфиденциальности](PRIVACY_POLICY.md)

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI Status](https://github.com/Konstantin051087/CodeSage-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/Konstantin051087/CodeSage-AI/actions)

## 🚀 Что это?
Open-source инструмент для анализа кода с ИИ, который объясняет ошибки **на языке бизнеса** (экономия денег/времени).

## ⚡️ Быстрый старт
```bash
pip install codesage
codesage analyze --path ./your_project

## 🛠️ Детекторы
CodeSage находит:
- SQL-инъекции через f-строки, конкатенацию и %-форматирование.
- Использование `eval()`, `exec()`, `pickle.loads()`.

## 🧪 Тестирование

Запуск тестов с отчётом о покрытии:
```bash
pytest tests/ --cov=core --cov-report=html

## Пример работы
[![asciicast](https://asciinema.org/a/LgOfUcPNC0ROyrogX4iDCdZGz.png)](https://asciinema.org/a/LgOfUcPNC0ROyrogX4iDCdZGz)
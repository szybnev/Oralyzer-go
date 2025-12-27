### Введение

Oralyzer — это инструмент безопасности для обнаружения уязвимостей Open Redirect на веб-сайтах. Он фаззит URL-адреса с помощью пейлоадов для выявления уязвимых параметров перенаправления.

### Возможности

Oralyzer способен обнаруживать следующие типы уязвимостей Open Redirect:
 - На основе заголовков (3xx редиректы)
 - На основе JavaScript (DOM-редиректы)
 - На основе Meta-тегов (http-equiv refresh)

Дополнительные возможности:
- Обнаружение CRLF-инъекций
- Получение URL из Wayback Machine
- Параллельное сканирование с настраиваемым количеством воркеров
- Вывод в формате JSON
- Поддержка прокси

### Установка

```bash
git clone https://github.com/szybnev/Oralyzer-go && cd Oralyzer && go build -o oralyzer .
```

### Использование

```bash
# Сканирование одного URL
./oralyzer -u "http://example.com/?redirect=test"

# Несколько URL из файла с 20 параллельными воркерами
./oralyzer -l urls.txt -c 20

# Сканирование на CRLF-инъекции
./oralyzer -u "http://example.com/?param=test" --crlf

# Получение URL из Wayback Machine
./oralyzer -u "example.com" --wayback

# Вывод в JSON с использованием прокси
./oralyzer -u "http://example.com/?url=test" --json --proxy http://127.0.0.1:8080

# Сохранение результатов в файл
./oralyzer -u "http://example.com/?next=test" -o results.txt
```

### Флаги

| Флаг | Описание |
|------|----------|
| `-u, --url` | Целевой URL |
| `-l, --list` | Файл со списком URL |
| `-p, --payloads` | Файл с пользовательскими пейлоадами |
| `--crlf` | Режим сканирования на CRLF-инъекции |
| `--wayback` | Получить URL из archive.org |
| `--proxy` | URL прокси-сервера |
| `-c, --concurrency` | Количество параллельных воркеров (по умолчанию: 10) |
| `-o, --output` | Файл для сохранения результатов |
| `--json` | Вывод в формате JSON |
| `-t, --timeout` | Таймаут HTTP-запросов (по умолчанию: 10s) |

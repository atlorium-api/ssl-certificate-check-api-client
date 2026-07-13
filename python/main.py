"""
Клиент API проверки SSL/TLS-сертификата Atlorium — мониторинг срока действия.

Запуск (работает сразу, без регистрации — на демо-ключе):
    pip install -r requirements.txt
    python main.py
    python main.py atlorium.com github.com

Программа задумана как ПРОВЕРКА для cron или CI, а не как «печаталка JSON»:
она возвращает ненулевой код выхода, если с сертификатом что-то не так.

    0 — OK: все сертификаты валидны, до истечения больше 30 дней
    1 — WARNING: до истечения меньше 30 дней — пора продлевать
    2 — CRITICAL: меньше 7 дней, сертификат невалиден или хост не покрыт SAN
    3 — проверку выполнить не удалось (ошибка API или сети)

Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
ATLORIUM_API_KEY. Код при этом не меняется.
"""

import os
import sys
import time
from dataclasses import dataclass, field

import requests

# Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
# данными): сертификат сгенерирован, а не снят с настоящего хоста. Ответы
# детерминированы — один и тот же хост всегда даёт один и тот же результат,
# поэтому на них можно писать стабильные тесты.
SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1"

API_KEY = os.environ.get("ATLORIUM_API_KEY", SANDBOX_KEY)
BASE_URL = os.environ.get("ATLORIUM_BASE_URL", "https://atlorium.com")

# Проверка сертификата — это настоящий TCP+TLS handshake с чужим хостом.
# Он может тянуть с ответом, поэтому таймаут щедрый.
TIMEOUT = 30

# ── Пороги светофора ─────────────────────────────────────────────────────────
# Классика мониторинга: 30 дней — время спокойно продлить, 7 дней — время
# будить дежурного. Let's Encrypt живёт 90 дней, поэтому 30/7 — рабочие пороги.
WARNING_DAYS = 30
CRITICAL_DAYS = 7

# Пакетный эндпоинт принимает не больше 10 хостов за запрос.
BATCH_LIMIT = 10

# 429 — повтор один раз с паузой.
RETRY_DELAY = 20
MAX_RETRIES = 1

# Потолок ожидания. Исчерпав ЧАСОВОЙ лимит, сервер честно просит подождать 40+
# минут — и клиент, слепо доверяющий Retry-After, зависнет на эти 40 минут
# (а в CI просто съест бюджет джоба). Дольше потолка не ждём: честно сообщаем,
# что квота исчерпана, и выходим.
MAX_RETRY_DELAY = 120

# Уровни светофора. Значение уровня — это и есть код выхода программы.
OK, WARNING, CRITICAL = 0, 1, 2
LEVEL_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL"}


class AtloriumError(RuntimeError):
    """Ошибка API. Код HTTP разложен в человекочитаемую причину."""

    REASONS = {
        400: "Хост не указан или порт вне диапазона 1–65535",
        401: "API-ключ отсутствует, просрочен или недействителен",
        402: "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        429: "Превышен лимит запросов — повторите позже",
        500: "Не удалось снять сертификат: хост недоступен, таймаут "
             "или на порту нет TLS (за неудачную проверку деньги не списываются)",
    }

    def __init__(self, status: int, body: str):
        reason = self.REASONS.get(status, "Неизвестная ошибка")
        super().__init__(f"HTTP {status}: {reason}. Ответ сервера: {body[:200]}")
        self.status = status


def _retry_after(response: requests.Response) -> int:
    """Сколько ждать после 429. Мусор и слишком большие значения не берём на веру.

    Значение 0 означало бы «повторяй немедленно» — клиент ушёл бы в busy-loop.
    Значение в 40+ минут (так сервер отвечает на исчерпанный часовой лимит)
    означало бы «спи почти час». Возвращаем 0, если ждать бессмысленно долго:
    вызывающий сдастся и честно скажет, что квота исчерпана.
    """
    try:
        seconds = int(response.headers.get("Retry-After", ""))
    except ValueError:
        seconds = 0

    if seconds <= 0:
        return RETRY_DELAY
    return seconds if seconds <= MAX_RETRY_DELAY else 0


def _get(path: str, params: dict):
    for attempt in range(MAX_RETRIES + 1):
        response = requests.get(
            f"{BASE_URL}{path}",
            params=params,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )

        if response.status_code == 429 and attempt < MAX_RETRIES:
            delay = _retry_after(response)
            if delay == 0:
                break  # ждать пришлось бы дольше потолка — не ждём
            print(f"429: лимит запросов. Повтор через {delay} с…", file=sys.stderr)
            time.sleep(delay)
            continue

        if not response.ok:
            raise AtloriumError(response.status_code, response.text)
        return response.json()

    raise AtloriumError(429, "Квота исчерпана, повтор бессмыслен")


# ── Эндпоинты ────────────────────────────────────────────────────────────────


def check_host(host: str, port: int = 443) -> dict:
    """Сертификат одного хоста: GET /api/Certificate?host=…&port=…"""
    return _get("/api/Certificate", {"host": host, "port": port})


def check_url(url: str) -> dict:
    """Сертификат по URL — хост и порт извлекаются автоматически.

    Удобно, когда URL скопировали из браузера: GET /api/Certificate/url?url=…
    """
    return _get("/api/Certificate/url", {"url": url})


def check_batch(hosts: list[str], port: int = 443) -> list[dict]:
    """Пакетная проверка: GET /api/Certificate/batch?hosts=a,b,c&port=…

    До 10 хостов ЗА ОДИН запрос. Это не только быстрее (сервер проверяет их
    параллельно) — это ещё и один вызов по тарификации и по rate-limit вместо
    десяти. Для мониторинга парка доменов разница принципиальная.
    """
    if len(hosts) > BATCH_LIMIT:
        raise ValueError(f"Не больше {BATCH_LIMIT} хостов за один запрос")
    return _get("/api/Certificate/batch", {"hosts": ",".join(hosts), "port": port})


# ── Применение данных: мониторинг сертификатов ───────────────────────────────
# Ответ API сам по себе — просто JSON. Ценность появляется, когда из него делают
# вывод: будить дежурного или можно спать. Ниже — ровно те проверки, которые
# отличают «сертификат есть» от «сертификат работает».


@dataclass
class Report:
    host: str
    cert: dict
    level: int = OK
    problems: list[str] = field(default_factory=list)

    def fail(self, level: int, problem: str) -> None:
        self.level = max(self.level, level)
        self.problems.append(problem)


def covers_host(host: str, names: list[str]) -> bool:
    """Покрывает ли SAN-список запрошенный хост — с учётом wildcard-масок.

    Браузер сверяет имя хоста с subjectAlternativeNames, а НЕ с CN. Сертификат
    может быть идеально валиден и при этом не подходить домену: типичная авария —
    сертификат на `*.example.com` повесили на `example.com` (маска покрывает
    ровно один уровень поддомена и не покрывает сам домен).
    """
    host = host.strip().rstrip(".").lower()

    for raw in names or []:
        name = raw.strip().rstrip(".").lower()
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # "*.example.com" → ".example.com"
            if host.endswith(suffix):
                label = host[: -len(suffix)]
                # Ровно один уровень: foo.example.com — да, a.foo.example.com — нет.
                if label and "." not in label:
                    return True
    return False


def monitor_expiry(host: str, cert: dict) -> Report:
    """Светофор по одному сертификату. Уровень отчёта = код выхода программы."""
    report = Report(host=host, cert=cert)

    # 1. Валидность и ошибки цепочки: истёкший, самоподписанный, отозванный,
    #    неизвестный УЦ. Браузер на таком покажет красный экран — значит, это
    #    авария независимо от того, сколько дней осталось.
    if not cert.get("isValid", False):
        report.fail(CRITICAL, "Сертификат невалиден")
    for error in cert.get("errors") or []:
        report.fail(CRITICAL, f"Ошибка проверки: {error}")
    if cert.get("isSelfSigned"):
        report.fail(CRITICAL, "Самоподписанный сертификат — клиенты его не примут")
    for link in cert.get("certificateChain") or []:
        for error in link.get("errors") or []:
            report.fail(CRITICAL, f"Цепочка ({link.get('subject')}): {error}")

    # 2. Несовпадение SAN. Сертификат валиден, но выписан на другое имя —
    #    браузер покажет NET::ERR_CERT_COMMON_NAME_INVALID.
    names = cert.get("subjectAlternativeNames") or []
    if not covers_host(host, names):
        report.fail(
            CRITICAL,
            f"MISMATCH: {host} не покрыт SAN ({', '.join(names) if names else 'список пуст'})",
        )

    # 3. Срок действия — светофор.
    days = cert.get("daysRemaining")
    if days is None:
        report.fail(CRITICAL, "API не вернул срок действия")
    elif days < 0:
        report.fail(CRITICAL, f"Сертификат истёк {-days} дн. назад")
    elif days < CRITICAL_DAYS:
        report.fail(CRITICAL, f"Истекает через {days} дн. — меньше порога {CRITICAL_DAYS}")
    elif days < WARNING_DAYS:
        report.fail(WARNING, f"Истекает через {days} дн. — пора продлевать")

    return report


# ── Печать отчёта ────────────────────────────────────────────────────────────


def _short_issuer(issuer: str) -> str:
    """Из «CN=R3, O=Let's Encrypt, C=US» получаем «Let's Encrypt»."""
    for part in (issuer or "").split(","):
        part = part.strip()
        if part.startswith("O="):
            return part[2:]
    return issuer or "—"


def print_report(reports: list[Report]) -> None:
    print(f"{'ХОСТ':<26}{'ДНЕЙ':>5}  {'ИСТЕКАЕТ':<12}{'TLS':<8}{'ИЗДАТЕЛЬ':<20}СТАТУС")
    for report in reports:
        cert = report.cert
        print(
            f"{report.host:<26}"
            f"{cert.get('daysRemaining', 0):>5}  "
            f"{(cert.get('expirationDate') or '')[:10]:<12}"
            f"{cert.get('tlsVersion') or '—':<8}"
            f"{_short_issuer(cert.get('issuer', ''))[:19]:<20}"
            f"{LEVEL_NAMES[report.level]}"
        )

    for report in reports:
        if report.problems:
            print(f"\n[{LEVEL_NAMES[report.level]}] {report.host}")
            for problem in report.problems:
                print(f"  - {problem}")


def main() -> int:
    if API_KEY == SANDBOX_KEY:
        print("Демо-ключ: сертификат сгенерирован (мок), а не снят с реального хоста.\n")

    # Хосты можно передать и списком аргументов, и через запятую.
    raw = " ".join(sys.argv[1:]).replace(",", " ").split()
    hosts = raw or ["atlorium.com"]

    try:
        # Несколько хостов — ОДИН запрос к /batch вместо N отдельных.
        if len(hosts) == 1:
            certs = [check_host(hosts[0])]
        else:
            certs = check_batch(hosts)
    except (AtloriumError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 3  # проверка не выполнена — это не «всё хорошо»

    # Батч отвечает одним объектом на хост и в том же порядке. Если это вдруг
    # не так — молча проверять «не те» хосты хуже, чем честно упасть.
    if len(certs) != len(hosts):
        print(f"Ошибка: API вернул {len(certs)} результатов на {len(hosts)} хостов", file=sys.stderr)
        return 3

    print(f"Проверено хостов: {len(hosts)} — запросов к API: 1\n")

    reports = [monitor_expiry(host, cert) for host, cert in zip(hosts, certs)]
    print_report(reports)

    worst = max(report.level for report in reports)
    print()
    if worst == OK:
        print(f"Вердикт: OK — все сертификаты валидны, запас больше {WARNING_DAYS} дн.")
    elif worst == WARNING:
        print(f"Вердикт: WARNING — есть сертификаты со сроком меньше {WARNING_DAYS} дн.")
    else:
        print("Вердикт: CRITICAL — требуется вмешательство.")

    # Ключевая деталь: код выхода. Именно он делает из примера рабочую проверку
    # для cron и CI — шаг workflow покраснеет сам, без внешнего парсинга вывода.
    print(f"Код выхода: {worst}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main())

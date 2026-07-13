<?php

/**
 * Клиент API проверки SSL/TLS-сертификата Atlorium — мониторинг срока действия.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   php main.php
 *   php main.php atlorium.com github.com
 *
 * Программа задумана как ПРОВЕРКА для cron или CI, а не как «печаталка JSON»:
 * она возвращает ненулевой код выхода, если с сертификатом что-то не так.
 *
 *   0 — OK: все сертификаты валидны, до истечения больше 30 дней
 *   1 — WARNING: до истечения меньше 30 дней — пора продлевать
 *   2 — CRITICAL: меньше 7 дней, сертификат невалиден или хост не покрыт SAN
 *   3 — проверку выполнить не удалось (ошибка API или сети)
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

declare(strict_types=1);

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными): сертификат сгенерирован, а не снят с настоящего хоста. Ответы
 * детерминированы: один и тот же хост всегда даёт один и тот же результат,
 * поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

/** Проверка сертификата — настоящий TCP+TLS handshake с чужим хостом, он может тянуть. */
const TIMEOUT = 30;

// ── Пороги светофора ─────────────────────────────────────────────────────────
// Классика мониторинга: 30 дней — время спокойно продлить, 7 дней — время
// будить дежурного. Let's Encrypt живёт 90 дней, поэтому 30/7 — рабочие пороги.
const WARNING_DAYS = 30;
const CRITICAL_DAYS = 7;

/** Пакетный эндпоинт принимает не больше 10 хостов за запрос. */
const BATCH_LIMIT = 10;

/** 429 — повтор один раз с паузой. */
const RETRY_DELAY = 20;
const MAX_RETRIES = 1;

/**
 * Потолок ожидания. Исчерпав ЧАСОВОЙ лимит, сервер честно просит подождать 40+
 * минут — и клиент, слепо доверяющий Retry-After, зависнет на эти 40 минут
 * (а в CI просто съест бюджет джоба). Дольше потолка не ждём.
 */
const MAX_RETRY_DELAY = 120;

/** Уровни светофора. Значение уровня — это и есть код выхода программы. */
const LEVEL_OK = 0;
const LEVEL_WARNING = 1;
const LEVEL_CRITICAL = 2;

const LEVEL_NAMES = [
    LEVEL_OK => 'OK',
    LEVEL_WARNING => 'WARNING',
    LEVEL_CRITICAL => 'CRITICAL',
];

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
final class AtloriumError extends RuntimeException
{
    private const REASONS = [
        400 => 'Хост не указан или порт вне диапазона 1–65535',
        401 => 'API-ключ отсутствует, просрочен или недействителен',
        402 => 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
        429 => 'Превышен лимит запросов — повторите позже',
        500 => 'Не удалось снять сертификат: хост недоступен, таймаут или на порту нет TLS '
             . '(за неудачную проверку деньги не списываются)',
    ];

    public function __construct(public readonly int $status, string $body)
    {
        $reason = self::REASONS[$status] ?? 'Неизвестная ошибка';
        parent::__construct(sprintf('HTTP %d: %s. Ответ сервера: %s', $status, $reason, mb_substr($body, 0, 200)));
    }
}

final class CertificateClient
{
    private string $apiKey;
    private string $baseUrl;

    public function __construct(?string $apiKey = null, ?string $baseUrl = null)
    {
        $this->apiKey = $apiKey ?? (getenv('ATLORIUM_API_KEY') ?: SANDBOX_KEY);
        $this->baseUrl = $baseUrl ?? (getenv('ATLORIUM_BASE_URL') ?: 'https://atlorium.com');
    }

    public function isSandbox(): bool
    {
        return $this->apiKey === SANDBOX_KEY;
    }

    /**
     * Сколько ждать после 429. Мусор и слишком большие значения не берём на веру:
     * 0 означало бы busy-loop, 40+ минут — «спи почти час». Возвращаем 0, если
     * ждать бессмысленно долго: вызывающий сдастся.
     */
    private function retryAfter(string $headers): int
    {
        if (preg_match('/^Retry-After:\s*(\d+)/mi', $headers, $match) !== 1) {
            return RETRY_DELAY;
        }
        $seconds = (int) $match[1];
        if ($seconds <= 0) {
            return RETRY_DELAY;
        }

        return $seconds <= MAX_RETRY_DELAY ? $seconds : 0;
    }

    /**
     * @param array<string, string> $params
     * @return array<mixed>
     */
    private function get(string $path, array $params): array
    {
        for ($attempt = 0; $attempt <= MAX_RETRIES; $attempt++) {
            $curl = curl_init($this->baseUrl . $path . '?' . http_build_query($params));
            curl_setopt_array($curl, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_TIMEOUT => TIMEOUT,
                CURLOPT_HTTPHEADER => [
                    'Authorization: Bearer ' . $this->apiKey,
                    'Accept: application/json',
                ],
            ]);

            $raw = curl_exec($curl);
            if ($raw === false) {
                $error = curl_error($curl);
                curl_close($curl);
                throw new RuntimeException("Сетевая ошибка: {$error}");
            }

            $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            $headerSize = (int) curl_getinfo($curl, CURLINFO_HEADER_SIZE);
            curl_close($curl);

            $raw = (string) $raw;
            $headers = substr($raw, 0, $headerSize);
            $body = substr($raw, $headerSize);

            if ($status === 429 && $attempt < MAX_RETRIES) {
                $delay = $this->retryAfter($headers);
                if ($delay === 0) {
                    break; // ждать пришлось бы дольше потолка — не ждём
                }
                fwrite(STDERR, "429: лимит запросов. Повтор через {$delay} с…\n");
                sleep($delay);
                continue;
            }

            if ($status !== 200) {
                throw new AtloriumError($status, $body);
            }

            return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        }

        throw new AtloriumError(429, 'Квота исчерпана, повтор бессмыслен');
    }

    // ── Эндпоинты ────────────────────────────────────────────────────────────

    /**
     * Сертификат одного хоста: GET /api/Certificate?host=…&port=…
     *
     * @return array<string, mixed>
     */
    public function checkHost(string $host, int $port = 443): array
    {
        return $this->get('/api/Certificate', ['host' => $host, 'port' => (string) $port]);
    }

    /**
     * Сертификат по URL — хост и порт извлекаются автоматически.
     *
     * @return array<string, mixed>
     */
    public function checkUrl(string $url): array
    {
        return $this->get('/api/Certificate/url', ['url' => $url]);
    }

    /**
     * Пакетная проверка: GET /api/Certificate/batch?hosts=a,b,c&port=…
     *
     * До 10 хостов ЗА ОДИН запрос. Это не только быстрее (сервер проверяет их
     * параллельно) — это ещё и один вызов по тарификации и по rate-limit вместо
     * десяти. Для мониторинга парка доменов разница принципиальная.
     *
     * @param list<string> $hosts
     * @return list<array<string, mixed>>
     */
    public function checkBatch(array $hosts, int $port = 443): array
    {
        if (count($hosts) > BATCH_LIMIT) {
            throw new InvalidArgumentException('Не больше ' . BATCH_LIMIT . ' хостов за один запрос');
        }

        return $this->get('/api/Certificate/batch', [
            'hosts' => implode(',', $hosts),
            'port' => (string) $port,
        ]);
    }
}

// ── Применение данных: мониторинг сертификатов ───────────────────────────────
// Ответ API сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: будить дежурного или можно спать. Ниже — ровно те проверки, которые
// отличают «сертификат есть» от «сертификат работает».

/**
 * Покрывает ли SAN-список запрошенный хост — с учётом wildcard-масок.
 *
 * Браузер сверяет имя хоста с subjectAlternativeNames, а НЕ с CN. Сертификат
 * может быть идеально валиден и при этом не подходить домену: типичная авария —
 * сертификат на *.example.com повесили на example.com (маска покрывает ровно
 * один уровень поддомена и не покрывает сам домен).
 *
 * @param list<string> $names
 */
function coversHost(string $host, array $names): bool
{
    $target = strtolower(rtrim(trim($host), '.'));

    foreach ($names as $raw) {
        $name = strtolower(rtrim(trim($raw), '.'));
        if ($name === $target) {
            return true;
        }
        if (str_starts_with($name, '*.')) {
            $suffix = substr($name, 1); // "*.example.com" → ".example.com"
            if (str_ends_with($target, $suffix)) {
                $label = substr($target, 0, -strlen($suffix));
                // Ровно один уровень: foo.example.com — да, a.foo.example.com — нет.
                if ($label !== '' && !str_contains($label, '.')) {
                    return true;
                }
            }
        }
    }

    return false;
}

/**
 * Светофор по одному сертификату. Уровень отчёта = код выхода программы.
 *
 * @param array<string, mixed> $cert
 * @return array{host: string, cert: array<string, mixed>, level: int, problems: list<string>}
 */
function monitorExpiry(string $host, array $cert): array
{
    $level = LEVEL_OK;
    $problems = [];

    $fail = static function (int $next, string $problem) use (&$level, &$problems): void {
        $level = max($level, $next);
        $problems[] = $problem;
    };

    // 1. Валидность и ошибки цепочки: истёкший, самоподписанный, отозванный,
    //    неизвестный УЦ. Браузер на таком покажет красный экран — значит, это
    //    авария независимо от того, сколько дней осталось.
    if (!($cert['isValid'] ?? false)) {
        $fail(LEVEL_CRITICAL, 'Сертификат невалиден');
    }
    foreach ($cert['errors'] ?? [] as $error) {
        $fail(LEVEL_CRITICAL, "Ошибка проверки: {$error}");
    }
    if ($cert['isSelfSigned'] ?? false) {
        $fail(LEVEL_CRITICAL, 'Самоподписанный сертификат — клиенты его не примут');
    }
    foreach ($cert['certificateChain'] ?? [] as $link) {
        foreach ($link['errors'] ?? [] as $error) {
            $fail(LEVEL_CRITICAL, "Цепочка ({$link['subject']}): {$error}");
        }
    }

    // 2. Несовпадение SAN. Сертификат валиден, но выписан на другое имя —
    //    браузер покажет NET::ERR_CERT_COMMON_NAME_INVALID.
    $names = $cert['subjectAlternativeNames'] ?? [];
    if (!coversHost($host, $names)) {
        $listed = $names === [] ? 'список пуст' : implode(', ', $names);
        $fail(LEVEL_CRITICAL, "MISMATCH: {$host} не покрыт SAN ({$listed})");
    }

    // 3. Срок действия — светофор.
    $days = (int) ($cert['daysRemaining'] ?? 0);
    if ($days < 0) {
        $fail(LEVEL_CRITICAL, 'Сертификат истёк ' . (-$days) . ' дн. назад');
    } elseif ($days < CRITICAL_DAYS) {
        $fail(LEVEL_CRITICAL, "Истекает через {$days} дн. — меньше порога " . CRITICAL_DAYS);
    } elseif ($days < WARNING_DAYS) {
        $fail(LEVEL_WARNING, "Истекает через {$days} дн. — пора продлевать");
    }

    return ['host' => $host, 'cert' => $cert, 'level' => $level, 'problems' => $problems];
}

// ── Печать отчёта ────────────────────────────────────────────────────────────

/** Из «CN=R3, O=Let's Encrypt, C=US» получаем «Let's Encrypt». */
function shortIssuer(string $issuer): string
{
    foreach (explode(',', $issuer) as $part) {
        $part = trim($part);
        if (str_starts_with($part, 'O=')) {
            return substr($part, 2);
        }
    }

    return $issuer === '' ? '—' : $issuer;
}

/** str_pad считает БАЙТЫ, а кириллица в UTF-8 занимает два — колонки бы разъехались. */
function pad(string $value, int $width): string
{
    $cut = mb_substr($value, 0, $width);

    return $cut . str_repeat(' ', max(0, $width - mb_strlen($cut)));
}

/** То же самое, но выравнивание вправо (для колонки с числом дней). */
function padLeft(string $value, int $width): string
{
    return str_repeat(' ', max(0, $width - mb_strlen($value))) . $value;
}

/** @param list<array{host: string, cert: array<string, mixed>, level: int, problems: list<string>}> $reports */
function printReport(array $reports): void
{
    echo pad('ХОСТ', 26) . padLeft('ДНЕЙ', 5) . '  '
        . pad('ИСТЕКАЕТ', 12) . pad('TLS', 8) . pad('ИЗДАТЕЛЬ', 20) . "СТАТУС\n";

    foreach ($reports as $report) {
        $cert = $report['cert'];
        echo pad($report['host'], 26)
            . padLeft((string) ($cert['daysRemaining'] ?? 0), 5) . '  '
            . pad(substr((string) ($cert['expirationDate'] ?? ''), 0, 10), 12)
            . pad(($cert['tlsVersion'] ?? '') ?: '—', 8)
            . pad(shortIssuer((string) ($cert['issuer'] ?? '')), 20)
            . LEVEL_NAMES[$report['level']] . "\n";
    }

    foreach ($reports as $report) {
        if ($report['problems'] === []) {
            continue;
        }
        echo "\n[" . LEVEL_NAMES[$report['level']] . "] {$report['host']}\n";
        foreach ($report['problems'] as $problem) {
            echo "  - {$problem}\n";
        }
    }
}

// ── Демонстрация ─────────────────────────────────────────────────────────────

$client = new CertificateClient();

if ($client->isSandbox()) {
    echo "Демо-ключ: сертификат сгенерирован (мок), а не снят с реального хоста.\n\n";
}

// Хосты можно передать и списком аргументов, и через запятую.
$hosts = [];
foreach (array_slice($argv, 1) as $argument) {
    foreach (explode(',', $argument) as $part) {
        $part = trim($part);
        if ($part !== '') {
            $hosts[] = $part;
        }
    }
}
if ($hosts === []) {
    $hosts = ['atlorium.com'];
}

try {
    // Несколько хостов — ОДИН запрос к /batch вместо N отдельных.
    $certs = count($hosts) === 1
        ? [$client->checkHost($hosts[0])]
        : $client->checkBatch($hosts);
} catch (AtloriumError | InvalidArgumentException $error) {
    fwrite(STDERR, "Ошибка: {$error->getMessage()}\n");
    exit(3); // проверка не выполнена — это не «всё хорошо»
}

// Батч отвечает одним объектом на хост и в том же порядке. Если это вдруг
// не так — молча проверять «не те» хосты хуже, чем честно упасть.
if (count($certs) !== count($hosts)) {
    fwrite(STDERR, 'Ошибка: API вернул ' . count($certs) . ' результатов на ' . count($hosts) . " хостов\n");
    exit(3);
}

echo 'Проверено хостов: ' . count($hosts) . " — запросов к API: 1\n\n";

$reports = [];
$worst = LEVEL_OK;
foreach ($hosts as $index => $host) {
    $report = monitorExpiry($host, $certs[$index]);
    $reports[] = $report;
    $worst = max($worst, $report['level']);
}

printReport($reports);

echo "\n";
if ($worst === LEVEL_OK) {
    echo 'Вердикт: OK — все сертификаты валидны, запас больше ' . WARNING_DAYS . " дн.\n";
} elseif ($worst === LEVEL_WARNING) {
    echo 'Вердикт: WARNING — есть сертификаты со сроком меньше ' . WARNING_DAYS . " дн.\n";
} else {
    echo "Вердикт: CRITICAL — требуется вмешательство.\n";
}

// Ключевая деталь: код выхода. Именно он делает из примера рабочую проверку
// для cron и CI — шаг workflow покраснеет сам, без внешнего парсинга вывода.
echo "Код выхода: {$worst}\n";
exit($worst);

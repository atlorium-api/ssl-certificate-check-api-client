// Клиент API проверки SSL/TLS-сертификата Atlorium — мониторинг срока действия.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//     dotnet run
//     dotnet run atlorium.com github.com
//
// Программа задумана как ПРОВЕРКА для cron или CI, а не как «печаталка JSON»:
// она возвращает ненулевой код выхода, если с сертификатом что-то не так.
//
//     0 — OK: все сертификаты валидны, до истечения больше 30 дней
//     1 — WARNING: до истечения меньше 30 дней — пора продлевать
//     2 — CRITICAL: меньше 7 дней, сертификат невалиден или хост не покрыт SAN
//     3 — проверку выполнить не удалось (ошибка API или сети)
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

// Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
// данными): сертификат сгенерирован, а не снят с настоящего хоста. Ответы
// детерминированы: один и тот же хост всегда даёт один и тот же результат,
// поэтому на них можно писать стабильные тесты.
const string SandboxKey = "ak_sandbox_demo_mockdata_v1";

var apiKey = Environment.GetEnvironmentVariable("ATLORIUM_API_KEY") ?? SandboxKey;
var baseUrl = Environment.GetEnvironmentVariable("ATLORIUM_BASE_URL") ?? "https://atlorium.com";

using var http = new HttpClient
{
    BaseAddress = new Uri(baseUrl),
    // Проверка сертификата — настоящий TCP+TLS handshake с чужим хостом, он может тянуть.
    Timeout = TimeSpan.FromSeconds(30),
};
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

var client = new CertificateClient(http);

if (apiKey == SandboxKey)
{
    Console.WriteLine("Демо-ключ: сертификат сгенерирован (мок), а не снят с реального хоста.\n");
}

// Хосты можно передать и списком аргументов, и через запятую.
var hosts = args
    .SelectMany(argument => argument.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    .ToList();
if (hosts.Count == 0)
{
    hosts = ["atlorium.com"];
}

IReadOnlyList<Certificate> certificates;
try
{
    // Несколько хостов — ОДИН запрос к /batch вместо N отдельных.
    if (hosts.Count == 1)
    {
        certificates = new List<Certificate> { await client.CheckHostAsync(hosts[0]) };
    }
    else
    {
        certificates = await client.CheckBatchAsync(hosts);
    }
}
catch (Exception error) when (error is AtloriumException or ArgumentException)
{
    Console.Error.WriteLine($"Ошибка: {error.Message}");
    return 3; // проверка не выполнена — это не «всё хорошо»
}

// Батч отвечает одним объектом на хост и в том же порядке. Если это вдруг
// не так — молча проверять «не те» хосты хуже, чем честно упасть.
if (certificates.Count != hosts.Count)
{
    Console.Error.WriteLine($"Ошибка: API вернул {certificates.Count} результатов на {hosts.Count} хостов");
    return 3;
}

Console.WriteLine($"Проверено хостов: {hosts.Count} — запросов к API: 1\n");

var reports = hosts
    .Select((host, index) => ExpiryMonitor.MonitorExpiry(host, certificates[index]))
    .ToList();

ExpiryMonitor.PrintReport(reports);

var worst = reports.Max(report => report.Level);
Console.WriteLine();
Console.WriteLine(worst switch
{
    Level.Ok => $"Вердикт: OK — все сертификаты валидны, запас больше {ExpiryMonitor.WarningDays} дн.",
    Level.Warning => $"Вердикт: WARNING — есть сертификаты со сроком меньше {ExpiryMonitor.WarningDays} дн.",
    _ => "Вердикт: CRITICAL — требуется вмешательство.",
});

// Ключевая деталь: код выхода. Именно он делает из примера рабочую проверку
// для cron и CI — шаг workflow покраснеет сам, без внешнего парсинга вывода.
Console.WriteLine($"Код выхода: {(int)worst}");
return (int)worst;

// ── Клиент ───────────────────────────────────────────────────────────────────

/// <summary>Ошибка API: HTTP-код разложен в человекочитаемую причину.</summary>
public sealed class AtloriumException(HttpStatusCode status, string body)
    : Exception($"HTTP {(int)status}: {Explain(status)}. Ответ сервера: {body[..Math.Min(200, body.Length)]}")
{
    public HttpStatusCode Status { get; } = status;

    private static string Explain(HttpStatusCode status) => (int)status switch
    {
        400 => "Хост не указан или порт вне диапазона 1–65535",
        401 => "API-ключ отсутствует, просрочен или недействителен",
        402 => "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
        429 => "Превышен лимит запросов — повторите позже",
        500 => "Не удалось снять сертификат: хост недоступен, таймаут или на порту нет TLS "
               + "(за неудачную проверку деньги не списываются)",
        _ => "Неизвестная ошибка",
    };
}

public sealed class CertificateClient(HttpClient http)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>Пакетный эндпоинт принимает не больше 10 хостов за запрос.</summary>
    public const int BatchLimit = 10;

    // 429 — повтор один раз с паузой. MaxRetryDelay — потолок ожидания: исчерпав
    // ЧАСОВОЙ лимит, сервер честно просит подождать 40+ минут, и клиент, слепо
    // доверяющий Retry-After, зависнет на эти 40 минут (а в CI съест бюджет джоба).
    private const int RetryDelay = 20;
    private const int MaxRetries = 1;
    private const int MaxRetryDelay = 120;

    /// <summary>Сертификат одного хоста: GET /api/Certificate?host=…&amp;port=…</summary>
    public async Task<Certificate> CheckHostAsync(string host, int port = 443)
        => await GetAsync<Certificate>($"/api/Certificate?host={Uri.EscapeDataString(host)}&port={port}");

    /// <summary>Сертификат по URL — хост и порт извлекаются автоматически.</summary>
    public async Task<Certificate> CheckUrlAsync(string url)
        => await GetAsync<Certificate>($"/api/Certificate/url?url={Uri.EscapeDataString(url)}");

    /// <summary>
    /// Пакетная проверка: GET /api/Certificate/batch?hosts=a,b,c&amp;port=…
    ///
    /// До 10 хостов ЗА ОДИН запрос. Это не только быстрее (сервер проверяет их
    /// параллельно) — это ещё и один вызов по тарификации и по rate-limit вместо
    /// десяти. Для мониторинга парка доменов разница принципиальная.
    /// </summary>
    public async Task<IReadOnlyList<Certificate>> CheckBatchAsync(IReadOnlyList<string> hosts, int port = 443)
    {
        if (hosts.Count > BatchLimit)
        {
            throw new ArgumentException($"Не больше {BatchLimit} хостов за один запрос", nameof(hosts));
        }

        var list = Uri.EscapeDataString(string.Join(',', hosts));
        return await GetAsync<List<Certificate>>($"/api/Certificate/batch?hosts={list}&port={port}");
    }

    private async Task<T> GetAsync<T>(string path)
    {
        for (var attempt = 0; attempt <= MaxRetries; attempt++)
        {
            using var response = await http.GetAsync(path);

            if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < MaxRetries)
            {
                var delay = RetryAfter(response);
                if (delay == 0)
                {
                    break; // ждать пришлось бы дольше потолка — не ждём
                }

                Console.Error.WriteLine($"429: лимит запросов. Повтор через {delay} с…");
                await Task.Delay(TimeSpan.FromSeconds(delay));
                continue;
            }

            var body = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                throw new AtloriumException(response.StatusCode, body);
            }

            return JsonSerializer.Deserialize<T>(body, JsonOptions)
                   ?? throw new InvalidOperationException("Пустой ответ API.");
        }

        throw new AtloriumException(HttpStatusCode.TooManyRequests, "Квота исчерпана, повтор бессмыслен");
    }

    /// <summary>
    /// Сколько ждать после 429. Мусор и слишком большие значения не берём на веру:
    /// 0 означало бы busy-loop, 40+ минут — «спи почти час». Возвращаем 0, если
    /// ждать бессмысленно долго: вызывающий сдастся.
    /// </summary>
    private static int RetryAfter(HttpResponseMessage response)
    {
        var seconds = (int?)response.Headers.RetryAfter?.Delta?.TotalSeconds ?? 0;
        if (seconds <= 0)
        {
            return RetryDelay;
        }
        return seconds <= MaxRetryDelay ? seconds : 0;
    }
}

// ── Модель ответа ────────────────────────────────────────────────────────────

/// <summary>Звено цепочки сертификатов.</summary>
public sealed record ChainLink
{
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string? ValidFrom { get; init; }
    public string? ValidTo { get; init; }
    public string? Thumbprint { get; init; }
    public bool IsValid { get; init; }
    public IReadOnlyList<string> Errors { get; init; } = [];
}

/// <summary>Ответ API: данные TLS-сертификата хоста.</summary>
public sealed record Certificate
{
    public bool IsValid { get; init; }
    public string? ExpirationDate { get; init; }
    public int DaysRemaining { get; init; }
    public string Issuer { get; init; } = "";
    public string Subject { get; init; } = "";
    public IReadOnlyList<string> SubjectAlternativeNames { get; init; } = [];
    public IReadOnlyList<string> Errors { get; init; } = [];
    public string? TlsVersion { get; init; }
    public string? ValidFrom { get; init; }
    public string? SerialNumber { get; init; }
    public string? Thumbprint { get; init; }
    public string? SignatureAlgorithm { get; init; }
    public string? PublicKeyAlgorithm { get; init; }
    public int KeySize { get; init; }
    public bool HasPrivateKey { get; init; }
    public bool IsSelfSigned { get; init; }
    public IReadOnlyList<ChainLink> CertificateChain { get; init; } = [];
    public string? ConnectionTime { get; init; }
    public string Host { get; init; } = "";
    public int Port { get; init; }
    public string? CheckedAt { get; init; }
}

// ── Применение данных: мониторинг сертификатов ───────────────────────────────
// Ответ API сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: будить дежурного или можно спать. Ниже — ровно те проверки, которые
// отличают «сертификат есть» от «сертификат работает».

/// <summary>Уровни светофора. Значение уровня — это и есть код выхода программы.</summary>
public enum Level
{
    Ok = 0,
    Warning = 1,
    Critical = 2,
}

public sealed record Report(string Host, Certificate Cert)
{
    public Level Level { get; private set; } = Level.Ok;

    private readonly List<string> _problems = [];

    public IReadOnlyList<string> Problems => _problems;

    public void Fail(Level level, string problem)
    {
        if (level > Level)
        {
            Level = level;
        }
        _problems.Add(problem);
    }
}

public static class ExpiryMonitor
{
    // Пороги светофора. Классика мониторинга: 30 дней — время спокойно продлить,
    // 7 дней — время будить дежурного. Let's Encrypt живёт 90 дней, поэтому 30/7 —
    // рабочие пороги.
    public const int WarningDays = 30;
    public const int CriticalDays = 7;

    /// <summary>
    /// Покрывает ли SAN-список запрошенный хост — с учётом wildcard-масок.
    ///
    /// Браузер сверяет имя хоста с subjectAlternativeNames, а НЕ с CN. Сертификат
    /// может быть идеально валиден и при этом не подходить домену: типичная авария —
    /// сертификат на *.example.com повесили на example.com (маска покрывает ровно
    /// один уровень поддомена и не покрывает сам домен).
    /// </summary>
    public static bool CoversHost(string host, IReadOnlyList<string> names)
    {
        var target = host.Trim().TrimEnd('.').ToLowerInvariant();

        foreach (var raw in names)
        {
            var name = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (name == target)
            {
                return true;
            }

            if (!name.StartsWith("*.", StringComparison.Ordinal))
            {
                continue;
            }

            var suffix = name[1..]; // "*.example.com" → ".example.com"
            if (!target.EndsWith(suffix, StringComparison.Ordinal))
            {
                continue;
            }

            var label = target[..^suffix.Length];
            // Ровно один уровень: foo.example.com — да, a.foo.example.com — нет.
            if (label.Length > 0 && !label.Contains('.'))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Светофор по одному сертификату. Уровень отчёта = код выхода программы.</summary>
    public static Report MonitorExpiry(string host, Certificate cert)
    {
        var report = new Report(host, cert);

        // 1. Валидность и ошибки цепочки: истёкший, самоподписанный, отозванный,
        //    неизвестный УЦ. Браузер на таком покажет красный экран — значит, это
        //    авария независимо от того, сколько дней осталось.
        if (!cert.IsValid)
        {
            report.Fail(Level.Critical, "Сертификат невалиден");
        }

        foreach (var error in cert.Errors)
        {
            report.Fail(Level.Critical, $"Ошибка проверки: {error}");
        }

        if (cert.IsSelfSigned)
        {
            report.Fail(Level.Critical, "Самоподписанный сертификат — клиенты его не примут");
        }

        foreach (var link in cert.CertificateChain)
        {
            foreach (var error in link.Errors)
            {
                report.Fail(Level.Critical, $"Цепочка ({link.Subject}): {error}");
            }
        }

        // 2. Несовпадение SAN. Сертификат валиден, но выписан на другое имя —
        //    браузер покажет NET::ERR_CERT_COMMON_NAME_INVALID.
        if (!CoversHost(host, cert.SubjectAlternativeNames))
        {
            var names = cert.SubjectAlternativeNames.Count > 0
                ? string.Join(", ", cert.SubjectAlternativeNames)
                : "список пуст";
            report.Fail(Level.Critical, $"MISMATCH: {host} не покрыт SAN ({names})");
        }

        // 3. Срок действия — светофор.
        switch (cert.DaysRemaining)
        {
            case < 0:
                report.Fail(Level.Critical, $"Сертификат истёк {-cert.DaysRemaining} дн. назад");
                break;
            case < CriticalDays:
                report.Fail(Level.Critical,
                    $"Истекает через {cert.DaysRemaining} дн. — меньше порога {CriticalDays}");
                break;
            case < WarningDays:
                report.Fail(Level.Warning, $"Истекает через {cert.DaysRemaining} дн. — пора продлевать");
                break;
        }

        return report;
    }

    // ── Печать отчёта ────────────────────────────────────────────────────────

    /// <summary>Из «CN=R3, O=Let's Encrypt, C=US» получаем «Let's Encrypt».</summary>
    private static string ShortIssuer(string issuer)
    {
        var org = issuer
            .Split(',')
            .Select(part => part.Trim())
            .FirstOrDefault(part => part.StartsWith("O=", StringComparison.Ordinal));

        if (org is not null)
        {
            return org[2..];
        }
        return string.IsNullOrEmpty(issuer) ? "—" : issuer;
    }

    private static string Pad(string value, int width)
        => (value.Length > width ? value[..width] : value).PadRight(width);

    private static string LevelName(Level level) => level switch
    {
        Level.Ok => "OK",
        Level.Warning => "WARNING",
        _ => "CRITICAL",
    };

    public static void PrintReport(IReadOnlyList<Report> reports)
    {
        Console.WriteLine(Pad("ХОСТ", 26) + "ДНЕЙ".PadLeft(5) + "  "
                          + Pad("ИСТЕКАЕТ", 12) + Pad("TLS", 8) + Pad("ИЗДАТЕЛЬ", 20) + "СТАТУС");

        foreach (var report in reports)
        {
            var cert = report.Cert;
            var expires = cert.ExpirationDate is { Length: >= 10 } date ? date[..10] : "";

            Console.WriteLine(Pad(report.Host, 26)
                              + cert.DaysRemaining.ToString().PadLeft(5) + "  "
                              + Pad(expires, 12)
                              + Pad(string.IsNullOrEmpty(cert.TlsVersion) ? "—" : cert.TlsVersion, 8)
                              + Pad(ShortIssuer(cert.Issuer), 20)
                              + LevelName(report.Level));
        }

        foreach (var report in reports.Where(report => report.Problems.Count > 0))
        {
            Console.WriteLine($"\n[{LevelName(report.Level)}] {report.Host}");
            foreach (var problem in report.Problems)
            {
                Console.WriteLine($"  - {problem}");
            }
        }
    }
}

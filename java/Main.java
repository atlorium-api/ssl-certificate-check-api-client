/*
 * Клиент API проверки SSL/TLS-сертификата Atlorium — мониторинг срока действия.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе).
 * Начиная с Java 11 файл запускается напрямую, без компиляции и без зависимостей:
 *
 *     java Main.java
 *     java Main.java atlorium.com github.com
 *
 * Программа задумана как ПРОВЕРКА для cron или CI, а не как «печаталка JSON»:
 * она возвращает ненулевой код выхода, если с сертификатом что-то не так.
 *
 *     0 — OK: все сертификаты валидны, до истечения больше 30 дней
 *     1 — WARNING: до истечения меньше 30 дней — пора продлевать
 *     2 — CRITICAL: меньше 7 дней, сертификат невалиден или хост не покрыт SAN
 *     3 — проверку выполнить не удалось (ошибка API или сети)
 *
 * Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
 * ATLORIUM_API_KEY. Код при этом не меняется.
 */

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    /**
     * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
     * данными): сертификат сгенерирован, а не снят с настоящего хоста. Ответы
     * детерминированы — один и тот же хост всегда даёт один и тот же результат,
     * поэтому на них можно писать стабильные тесты.
     */
    static final String SANDBOX_KEY = "ak_sandbox_demo_mockdata_v1";

    static final String API_KEY = envOr("ATLORIUM_API_KEY", SANDBOX_KEY);
    static final String BASE_URL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com");

    // ── Пороги светофора ─────────────────────────────────────────────────────
    // Классика мониторинга: 30 дней — время спокойно продлить, 7 дней — время
    // будить дежурного. Let's Encrypt живёт 90 дней, поэтому 30/7 — рабочие пороги.
    static final int WARNING_DAYS = 30;
    static final int CRITICAL_DAYS = 7;

    /** Пакетный эндпоинт принимает не больше 10 хостов за запрос. */
    static final int BATCH_LIMIT = 10;

    /** 429 — повтор один раз с паузой. */
    static final int RETRY_DELAY = 20;
    static final int MAX_RETRIES = 1;

    /**
     * Потолок ожидания. Исчерпав ЧАСОВОЙ лимит, сервер честно просит подождать 40+
     * минут — и клиент, слепо доверяющий Retry-After, зависнет на эти 40 минут
     * (а в CI просто съест бюджет джоба). Дольше потолка не ждём.
     */
    static final int MAX_RETRY_DELAY = 120;

    /** Уровни светофора. Значение уровня — это и есть код выхода программы. */
    static final int OK = 0;
    static final int WARNING = 1;
    static final int CRITICAL = 2;

    static final Map<Integer, String> LEVEL_NAMES = Map.of(
            OK, "OK", WARNING, "WARNING", CRITICAL, "CRITICAL");

    /** Проверка сертификата — настоящий TCP+TLS handshake с чужим хостом, он может тянуть. */
    static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    static String envOr(String key, String fallback) {
        String value = System.getenv(key);
        return (value == null || value.isBlank()) ? fallback : value;
    }

    /** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
    static class AtloriumException extends RuntimeException {
        private static final Map<Integer, String> REASONS = Map.of(
                400, "Хост не указан или порт вне диапазона 1–65535",
                401, "API-ключ отсутствует, просрочен или недействителен",
                402, "Недостаточно кредитов на балансе — пополните на https://atlorium.com",
                429, "Превышен лимит запросов — повторите позже",
                500, "Не удалось снять сертификат: хост недоступен, таймаут или на порту нет TLS "
                        + "(за неудачную проверку деньги не списываются)");

        final int status;

        AtloriumException(int status, String body) {
            super("HTTP " + status + ": "
                    + REASONS.getOrDefault(status, "Неизвестная ошибка")
                    + ". Ответ сервера: " + body.substring(0, Math.min(200, body.length())));
            this.status = status;
        }
    }

    /**
     * Сколько ждать после 429. Мусор и слишком большие значения не берём на веру:
     * 0 означало бы busy-loop, 40+ минут — «спи почти час». Возвращаем 0, если
     * ждать бессмысленно долго: вызывающий сдастся.
     */
    static int retryAfter(HttpResponse<String> response) {
        int seconds;
        try {
            seconds = Integer.parseInt(response.headers().firstValue("Retry-After").orElse(""));
        } catch (NumberFormatException ignored) {
            seconds = 0;
        }
        if (seconds <= 0) {
            return RETRY_DELAY;
        }
        return seconds <= MAX_RETRY_DELAY ? seconds : 0;
    }

    static String get(String path, String query) throws IOException, InterruptedException {
        for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(BASE_URL + path + "?" + query))
                    .header("Authorization", "Bearer " + API_KEY)
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            HttpResponse<String> response = CLIENT.send(request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            if (response.statusCode() == 429 && attempt < MAX_RETRIES) {
                int delay = retryAfter(response);
                if (delay == 0) {
                    break; // ждать пришлось бы дольше потолка — не ждём
                }
                System.err.println("429: лимит запросов. Повтор через " + delay + " с…");
                Thread.sleep(delay * 1000L);
                continue;
            }

            if (response.statusCode() != 200) {
                throw new AtloriumException(response.statusCode(), response.body());
            }
            return response.body();
        }

        throw new AtloriumException(429, "Квота исчерпана, повтор бессмыслен");
    }

    // ── Эндпоинты ────────────────────────────────────────────────────────────

    /** Сертификат одного хоста: GET /api/Certificate?host=…&port=… */
    static String checkHost(String host, int port) throws IOException, InterruptedException {
        return get("/api/Certificate",
                "host=" + URLEncoder.encode(host, StandardCharsets.UTF_8) + "&port=" + port);
    }

    /** Сертификат по URL — хост и порт извлекаются автоматически. */
    static String checkUrl(String url) throws IOException, InterruptedException {
        return get("/api/Certificate/url", "url=" + URLEncoder.encode(url, StandardCharsets.UTF_8));
    }

    /**
     * Пакетная проверка: GET /api/Certificate/batch?hosts=a,b,c&port=…
     *
     * До 10 хостов ЗА ОДИН запрос. Это не только быстрее (сервер проверяет их
     * параллельно) — это ещё и один вызов по тарификации и по rate-limit вместо
     * десяти. Для мониторинга парка доменов разница принципиальная.
     */
    static String checkBatch(List<String> hosts, int port) throws IOException, InterruptedException {
        if (hosts.size() > BATCH_LIMIT) {
            throw new IllegalArgumentException("Не больше " + BATCH_LIMIT + " хостов за один запрос");
        }
        String list = URLEncoder.encode(String.join(",", hosts), StandardCharsets.UTF_8);
        return get("/api/Certificate/batch", "hosts=" + list + "&port=" + port);
    }

    // ── Разбор JSON ──────────────────────────────────────────────────────────
    // Пример намеренно оставлен без внешних зависимостей, чтобы запускаться одной
    // командой `java Main.java`. В рабочем проекте берите Jackson или Gson и
    // маппьте ответ в полноценную запись — эти регулярки существуют только ради
    // отсутствия pom.xml.

    /** Массив объектов верхнего уровня — режем на элементы по балансу скобок. */
    static List<String> splitObjects(String json) {
        List<String> objects = new ArrayList<>();
        int depth = 0;
        int start = -1;
        boolean inString = false;
        boolean escaped = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (escaped) {
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '{') {
                if (depth == 0) {
                    start = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && start >= 0) {
                    objects.add(json.substring(start, i + 1));
                }
            }
        }
        return objects;
    }

    static String str(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(json);
        return matcher.find() ? matcher.group(1).replace("\\\"", "\"") : null;
    }

    static boolean bool(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*(true|false)").matcher(json);
        return matcher.find() && "true".equals(matcher.group(1));
    }

    static int number(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        return matcher.find() ? Integer.parseInt(matcher.group(1)) : 0;
    }

    /** Массив строк: "subjectAlternativeNames": ["a", "b"] */
    static List<String> strings(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(json);
        List<String> values = new ArrayList<>();
        if (!matcher.find()) {
            return values;
        }
        Matcher item = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(matcher.group(1));
        while (item.find()) {
            values.add(item.group(1));
        }
        return values;
    }

    // ── Применение данных: мониторинг сертификатов ───────────────────────────
    // Ответ API сам по себе — просто JSON. Ценность появляется, когда из него делают
    // вывод: будить дежурного или можно спать. Ниже — ровно те проверки, которые
    // отличают «сертификат есть» от «сертификат работает».

    static final class Report {
        final String host;
        final String cert;
        int level = OK;
        final List<String> problems = new ArrayList<>();

        Report(String host, String cert) {
            this.host = host;
            this.cert = cert;
        }

        void fail(int level, String problem) {
            this.level = Math.max(this.level, level);
            this.problems.add(problem);
        }
    }

    /**
     * Покрывает ли SAN-список запрошенный хост — с учётом wildcard-масок.
     *
     * Браузер сверяет имя хоста с subjectAlternativeNames, а НЕ с CN. Сертификат
     * может быть идеально валиден и при этом не подходить домену: типичная авария —
     * сертификат на *.example.com повесили на example.com (маска покрывает ровно
     * один уровень поддомена и не покрывает сам домен).
     */
    static boolean coversHost(String host, List<String> names) {
        String target = host.trim().toLowerCase();
        if (target.endsWith(".")) {
            target = target.substring(0, target.length() - 1);
        }

        for (String raw : names) {
            String name = raw.trim().toLowerCase();
            if (name.endsWith(".")) {
                name = name.substring(0, name.length() - 1);
            }
            if (name.equals(target)) {
                return true;
            }
            if (name.startsWith("*.")) {
                String suffix = name.substring(1); // "*.example.com" → ".example.com"
                if (target.endsWith(suffix)) {
                    String label = target.substring(0, target.length() - suffix.length());
                    // Ровно один уровень: foo.example.com — да, a.foo.example.com — нет.
                    if (!label.isEmpty() && !label.contains(".")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** Светофор по одному сертификату. Уровень отчёта = код выхода программы. */
    static Report monitorExpiry(String host, String cert) {
        Report report = new Report(host, cert);

        // 1. Валидность и ошибки цепочки: истёкший, самоподписанный, отозванный,
        //    неизвестный УЦ. Браузер на таком покажет красный экран — значит, это
        //    авария независимо от того, сколько дней осталось.
        if (!bool(cert, "isValid")) {
            report.fail(CRITICAL, "Сертификат невалиден");
        }
        for (String error : strings(cert, "errors")) {
            report.fail(CRITICAL, "Ошибка проверки: " + error);
        }
        if (bool(cert, "isSelfSigned")) {
            report.fail(CRITICAL, "Самоподписанный сертификат — клиенты его не примут");
        }

        // 2. Несовпадение SAN. Сертификат валиден, но выписан на другое имя —
        //    браузер покажет NET::ERR_CERT_COMMON_NAME_INVALID.
        List<String> names = strings(cert, "subjectAlternativeNames");
        if (!coversHost(host, names)) {
            report.fail(CRITICAL, "MISMATCH: " + host + " не покрыт SAN ("
                    + (names.isEmpty() ? "список пуст" : String.join(", ", names)) + ")");
        }

        // 3. Срок действия — светофор.
        int days = number(cert, "daysRemaining");
        if (days < 0) {
            report.fail(CRITICAL, "Сертификат истёк " + (-days) + " дн. назад");
        } else if (days < CRITICAL_DAYS) {
            report.fail(CRITICAL, "Истекает через " + days + " дн. — меньше порога " + CRITICAL_DAYS);
        } else if (days < WARNING_DAYS) {
            report.fail(WARNING, "Истекает через " + days + " дн. — пора продлевать");
        }

        return report;
    }

    // ── Печать отчёта ────────────────────────────────────────────────────────

    /** Из «CN=R3, O=Let's Encrypt, C=US» получаем «Let's Encrypt». */
    static String shortIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return "—";
        }
        for (String part : issuer.split(",")) {
            part = part.trim();
            if (part.startsWith("O=")) {
                return part.substring(2);
            }
        }
        return issuer;
    }

    static String pad(String value, int width) {
        String cut = value.length() > width ? value.substring(0, width) : value;
        return String.format("%-" + width + "s", cut);
    }

    static void printReport(List<Report> reports) {
        System.out.println(pad("ХОСТ", 26) + String.format("%5s", "ДНЕЙ") + "  "
                + pad("ИСТЕКАЕТ", 12) + pad("TLS", 8) + pad("ИЗДАТЕЛЬ", 20) + "СТАТУС");

        for (Report report : reports) {
            String expiration = str(report.cert, "expirationDate");
            String expires = expiration == null ? "" : expiration.substring(0, Math.min(10, expiration.length()));
            String tls = str(report.cert, "tlsVersion");

            System.out.println(pad(report.host, 26)
                    + String.format("%5d", number(report.cert, "daysRemaining")) + "  "
                    + pad(expires, 12)
                    + pad(tls == null ? "—" : tls, 8)
                    + pad(shortIssuer(str(report.cert, "issuer")), 20)
                    + LEVEL_NAMES.get(report.level));
        }

        for (Report report : reports) {
            if (report.problems.isEmpty()) {
                continue;
            }
            System.out.println("\n[" + LEVEL_NAMES.get(report.level) + "] " + report.host);
            for (String problem : report.problems) {
                System.out.println("  - " + problem);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        if (API_KEY.equals(SANDBOX_KEY)) {
            System.out.println("Демо-ключ: сертификат сгенерирован (мок), а не снят с реального хоста.\n");
        }

        // Хосты можно передать и списком аргументов, и через запятую.
        List<String> hosts = new ArrayList<>();
        for (String arg : args) {
            for (String part : arg.split(",")) {
                if (!part.isBlank()) {
                    hosts.add(part.trim());
                }
            }
        }
        if (hosts.isEmpty()) {
            hosts = List.of("atlorium.com");
        }

        List<String> certs;
        try {
            // Несколько хостов — ОДИН запрос к /batch вместо N отдельных.
            certs = hosts.size() == 1
                    ? List.of(checkHost(hosts.get(0), 443))
                    : splitObjects(checkBatch(hosts, 443));
        } catch (AtloriumException | IllegalArgumentException error) {
            System.err.println("Ошибка: " + error.getMessage());
            System.exit(3); // проверка не выполнена — это не «всё хорошо»
            return;
        }

        // Батч отвечает одним объектом на хост и в том же порядке. Если это вдруг
        // не так — молча проверять «не те» хосты хуже, чем честно упасть.
        if (certs.size() != hosts.size()) {
            System.err.println("Ошибка: API вернул " + certs.size() + " результатов на " + hosts.size() + " хостов");
            System.exit(3);
            return;
        }

        System.out.println("Проверено хостов: " + hosts.size() + " — запросов к API: 1\n");

        List<Report> reports = new ArrayList<>();
        int worst = OK;
        for (int i = 0; i < hosts.size(); i++) {
            Report report = monitorExpiry(hosts.get(i), certs.get(i));
            reports.add(report);
            worst = Math.max(worst, report.level);
        }
        printReport(reports);

        System.out.println();
        if (worst == OK) {
            System.out.println("Вердикт: OK — все сертификаты валидны, запас больше " + WARNING_DAYS + " дн.");
        } else if (worst == WARNING) {
            System.out.println("Вердикт: WARNING — есть сертификаты со сроком меньше " + WARNING_DAYS + " дн.");
        } else {
            System.out.println("Вердикт: CRITICAL — требуется вмешательство.");
        }

        // Ключевая деталь: код выхода. Именно он делает из примера рабочую проверку
        // для cron и CI — шаг workflow покраснеет сам, без внешнего парсинга вывода.
        System.out.println("Код выхода: " + worst);
        System.exit(worst);
    }
}

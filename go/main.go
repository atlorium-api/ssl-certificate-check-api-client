// Клиент API проверки SSL/TLS-сертификата Atlorium — мониторинг срока действия.
//
// Запуск (работает сразу, без регистрации — на демо-ключе):
//
//	go run .
//	go run . atlorium.com github.com
//
// Программа задумана как ПРОВЕРКА для cron или CI, а не как «печаталка JSON»:
// она возвращает ненулевой код выхода, если с сертификатом что-то не так.
//
//	0 — OK: все сертификаты валидны, до истечения больше 30 дней
//	1 — WARNING: до истечения меньше 30 дней — пора продлевать
//	2 — CRITICAL: меньше 7 дней, сертификат невалиден или хост не покрыт SAN
//	3 — проверку выполнить не удалось (ошибка API или сети)
//
// Боевой ключ: получить на https://atlorium.com и положить в переменную окружения
// ATLORIUM_API_KEY. Код при этом не меняется.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// SandboxKey — публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ:
// сертификат сгенерирован, а не снят с настоящего хоста. Ответы детерминированы —
// на них можно писать стабильные тесты.
const SandboxKey = "ak_sandbox_demo_mockdata_v1"

// Пороги светофора. Классика мониторинга: 30 дней — время спокойно продлить,
// 7 дней — время будить дежурного. Let's Encrypt живёт 90 дней, поэтому 30/7 —
// рабочие пороги.
const (
	WarningDays  = 30
	CriticalDays = 7
)

// BatchLimit — пакетный эндпоинт принимает не больше 10 хостов за запрос.
const BatchLimit = 10

// 429 — повтор один раз с паузой. MaxRetryDelay — потолок ожидания: исчерпав
// ЧАСОВОЙ лимит, сервер честно просит подождать 40+ минут, и клиент, слепо
// доверяющий Retry-After, зависнет на эти 40 минут (а в CI съест бюджет джоба).
// Дольше потолка не ждём.
const (
	RetryDelay    = 20 * time.Second
	MaxRetries    = 1
	MaxRetryDelay = 120 * time.Second
)

// Уровни светофора. Значение уровня — это и есть код выхода программы.
const (
	LevelOK       = 0
	LevelWarning  = 1
	LevelCritical = 2
)

var levelNames = map[int]string{
	LevelOK:       "OK",
	LevelWarning:  "WARNING",
	LevelCritical: "CRITICAL",
}

var (
	apiKey  = envOr("ATLORIUM_API_KEY", SandboxKey)
	baseURL = envOr("ATLORIUM_BASE_URL", "https://atlorium.com")
	// Проверка сертификата — настоящий TCP+TLS handshake с чужим хостом, он может тянуть.
	client = &http.Client{Timeout: 30 * time.Second}
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// ChainLink — звено цепочки сертификатов.
type ChainLink struct {
	Subject    string   `json:"subject"`
	Issuer     string   `json:"issuer"`
	ValidFrom  string   `json:"validFrom"`
	ValidTo    string   `json:"validTo"`
	Thumbprint string   `json:"thumbprint"`
	IsValid    bool     `json:"isValid"`
	Errors     []string `json:"errors"`
}

// Certificate — ответ API: данные TLS-сертификата хоста.
type Certificate struct {
	IsValid                 bool        `json:"isValid"`
	ExpirationDate          string      `json:"expirationDate"`
	DaysRemaining           int         `json:"daysRemaining"`
	Issuer                  string      `json:"issuer"`
	Subject                 string      `json:"subject"`
	SubjectAlternativeNames []string    `json:"subjectAlternativeNames"`
	Errors                  []string    `json:"errors"`
	TLSVersion              string      `json:"tlsVersion"`
	ValidFrom               string      `json:"validFrom"`
	SerialNumber            string      `json:"serialNumber"`
	Thumbprint              string      `json:"thumbprint"`
	SignatureAlgorithm      string      `json:"signatureAlgorithm"`
	PublicKeyAlgorithm      string      `json:"publicKeyAlgorithm"`
	KeySize                 int         `json:"keySize"`
	HasPrivateKey           bool        `json:"hasPrivateKey"`
	IsSelfSigned            bool        `json:"isSelfSigned"`
	CertificateChain        []ChainLink `json:"certificateChain"`
	ConnectionTime          string      `json:"connectionTime"`
	Host                    string      `json:"host"`
	Port                    int         `json:"port"`
	CheckedAt               string      `json:"checkedAt"`
}

// APIError раскладывает HTTP-код в человекочитаемую причину.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	reasons := map[int]string{
		400: "хост не указан или порт вне диапазона 1–65535",
		401: "API-ключ отсутствует, просрочен или недействителен",
		402: "недостаточно кредитов на балансе — пополните на https://atlorium.com",
		429: "превышен лимит запросов — повторите позже",
		500: "не удалось снять сертификат: хост недоступен, таймаут или на порту нет TLS " +
			"(за неудачную проверку деньги не списываются)",
	}
	reason, ok := reasons[e.Status]
	if !ok {
		reason = "неизвестная ошибка"
	}
	return fmt.Sprintf("HTTP %d: %s. Ответ сервера: %s", e.Status, reason, e.Body)
}

// retryAfter сообщает, сколько ждать после 429. Мусор и слишком большие значения
// не берём на веру: 0 означало бы busy-loop, 40+ минут — «спи почти час».
// Возвращаем 0, если ждать бессмысленно долго: вызывающий сдастся.
func retryAfter(response *http.Response) time.Duration {
	seconds, err := strconv.Atoi(response.Header.Get("Retry-After"))
	if err != nil || seconds <= 0 {
		return RetryDelay
	}
	delay := time.Duration(seconds) * time.Second
	if delay > MaxRetryDelay {
		return 0
	}
	return delay
}

func get(path string, query url.Values, out any) error {
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		request, err := http.NewRequest(http.MethodGet, baseURL+path+"?"+query.Encode(), nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+apiKey)
		request.Header.Set("Accept", "application/json")

		response, err := client.Do(request)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return err
		}

		if response.StatusCode == http.StatusTooManyRequests && attempt < MaxRetries {
			delay := retryAfter(response)
			if delay == 0 {
				break // ждать пришлось бы дольше потолка — не ждём
			}
			fmt.Fprintf(os.Stderr, "429: лимит запросов. Повтор через %s…\n", delay)
			time.Sleep(delay)
			continue
		}

		if response.StatusCode != http.StatusOK {
			return &APIError{Status: response.StatusCode, Body: string(body)}
		}
		return json.Unmarshal(body, out)
	}

	return &APIError{Status: http.StatusTooManyRequests, Body: "квота исчерпана, повтор бессмыслен"}
}

// ── Эндпоинты ────────────────────────────────────────────────────────────────

// CheckHost возвращает сертификат одного хоста: GET /api/Certificate?host=…&port=…
func CheckHost(host string, port int) (*Certificate, error) {
	var certificate Certificate
	err := get("/api/Certificate", url.Values{
		"host": {host},
		"port": {strconv.Itoa(port)},
	}, &certificate)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

// CheckURL возвращает сертификат по URL — хост и порт извлекаются автоматически.
// Удобно, когда URL скопировали из браузера.
func CheckURL(target string) (*Certificate, error) {
	var certificate Certificate
	if err := get("/api/Certificate/url", url.Values{"url": {target}}, &certificate); err != nil {
		return nil, err
	}
	return &certificate, nil
}

// CheckBatch — пакетная проверка: GET /api/Certificate/batch?hosts=a,b,c&port=…
//
// До 10 хостов ЗА ОДИН запрос. Это не только быстрее (сервер проверяет их
// параллельно) — это ещё и один вызов по тарификации и по rate-limit вместо
// десяти. Для мониторинга парка доменов разница принципиальная.
func CheckBatch(hosts []string, port int) ([]Certificate, error) {
	if len(hosts) > BatchLimit {
		return nil, fmt.Errorf("не больше %d хостов за один запрос", BatchLimit)
	}
	var certificates []Certificate
	err := get("/api/Certificate/batch", url.Values{
		"hosts": {strings.Join(hosts, ",")},
		"port":  {strconv.Itoa(port)},
	}, &certificates)
	if err != nil {
		return nil, err
	}
	return certificates, nil
}

// ── Применение данных: мониторинг сертификатов ───────────────────────────────
// Ответ API сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: будить дежурного или можно спать. Ниже — ровно те проверки, которые
// отличают «сертификат есть» от «сертификат работает».

// Report — результат светофора по одному хосту.
type Report struct {
	Host     string
	Cert     *Certificate
	Level    int
	Problems []string
}

func (r *Report) fail(level int, problem string) {
	if level > r.Level {
		r.Level = level
	}
	r.Problems = append(r.Problems, problem)
}

// CoversHost сообщает, покрывает ли SAN-список запрошенный хост — с учётом
// wildcard-масок.
//
// Браузер сверяет имя хоста с subjectAlternativeNames, а НЕ с CN. Сертификат
// может быть идеально валиден и при этом не подходить домену: типичная авария —
// сертификат на *.example.com повесили на example.com (маска покрывает ровно
// один уровень поддомена и не покрывает сам домен).
func CoversHost(host string, names []string) bool {
	target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))

	for _, raw := range names {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if name == target {
			return true
		}
		if strings.HasPrefix(name, "*.") {
			suffix := name[1:] // "*.example.com" → ".example.com"
			if strings.HasSuffix(target, suffix) {
				label := strings.TrimSuffix(target, suffix)
				// Ровно один уровень: foo.example.com — да, a.foo.example.com — нет.
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		}
	}
	return false
}

// MonitorExpiry — светофор по одному сертификату.
// Уровень отчёта = код выхода программы.
func MonitorExpiry(host string, cert *Certificate) *Report {
	report := &Report{Host: host, Cert: cert, Level: LevelOK}

	// 1. Валидность и ошибки цепочки: истёкший, самоподписанный, отозванный,
	//    неизвестный УЦ. Браузер на таком покажет красный экран — значит, это
	//    авария независимо от того, сколько дней осталось.
	if !cert.IsValid {
		report.fail(LevelCritical, "Сертификат невалиден")
	}
	for _, e := range cert.Errors {
		report.fail(LevelCritical, "Ошибка проверки: "+e)
	}
	if cert.IsSelfSigned {
		report.fail(LevelCritical, "Самоподписанный сертификат — клиенты его не примут")
	}
	for _, link := range cert.CertificateChain {
		for _, e := range link.Errors {
			report.fail(LevelCritical, fmt.Sprintf("Цепочка (%s): %s", link.Subject, e))
		}
	}

	// 2. Несовпадение SAN. Сертификат валиден, но выписан на другое имя —
	//    браузер покажет NET::ERR_CERT_COMMON_NAME_INVALID.
	if !CoversHost(host, cert.SubjectAlternativeNames) {
		names := "список пуст"
		if len(cert.SubjectAlternativeNames) > 0 {
			names = strings.Join(cert.SubjectAlternativeNames, ", ")
		}
		report.fail(LevelCritical, fmt.Sprintf("MISMATCH: %s не покрыт SAN (%s)", host, names))
	}

	// 3. Срок действия — светофор.
	switch days := cert.DaysRemaining; {
	case days < 0:
		report.fail(LevelCritical, fmt.Sprintf("Сертификат истёк %d дн. назад", -days))
	case days < CriticalDays:
		report.fail(LevelCritical,
			fmt.Sprintf("Истекает через %d дн. — меньше порога %d", days, CriticalDays))
	case days < WarningDays:
		report.fail(LevelWarning, fmt.Sprintf("Истекает через %d дн. — пора продлевать", days))
	}

	return report
}

// ── Печать отчёта ────────────────────────────────────────────────────────────

// shortIssuer из «CN=R3, O=Let's Encrypt, C=US» достаёт «Let's Encrypt».
func shortIssuer(issuer string) string {
	for _, part := range strings.Split(issuer, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "O=") {
			return part[2:]
		}
	}
	if issuer == "" {
		return "—"
	}
	return issuer
}

// pad дополняет строку пробелами по числу РУН, а не байтов: кириллица в UTF-8
// занимает два байта, и обычный %-20s разъехался бы.
func pad(value string, width int) string {
	runes := []rune(value)
	if len(runes) > width {
		return string(runes[:width])
	}
	return value + strings.Repeat(" ", width-len(runes))
}

func printReport(reports []*Report) {
	fmt.Printf("%s%5s  %s%s%s%s\n",
		pad("ХОСТ", 26), "ДНЕЙ", pad("ИСТЕКАЕТ", 12), pad("TLS", 8), pad("ИЗДАТЕЛЬ", 20), "СТАТУС")

	for _, report := range reports {
		cert := report.Cert
		expires := cert.ExpirationDate
		if len(expires) > 10 {
			expires = expires[:10]
		}
		tls := cert.TLSVersion
		if tls == "" {
			tls = "—"
		}
		fmt.Printf("%s%5d  %s%s%s%s\n",
			pad(report.Host, 26),
			cert.DaysRemaining,
			pad(expires, 12),
			pad(tls, 8),
			pad(pad(shortIssuer(cert.Issuer), 19), 20),
			levelNames[report.Level])
	}

	for _, report := range reports {
		if len(report.Problems) == 0 {
			continue
		}
		fmt.Printf("\n[%s] %s\n", levelNames[report.Level], report.Host)
		for _, problem := range report.Problems {
			fmt.Println("  -", problem)
		}
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	if apiKey == SandboxKey {
		fmt.Println("Демо-ключ: сертификат сгенерирован (мок), а не снят с реального хоста.")
		fmt.Println()
	}

	// Хосты можно передать и списком аргументов, и через запятую.
	hosts := make([]string, 0, len(os.Args))
	for _, arg := range os.Args[1:] {
		for _, part := range strings.Split(arg, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hosts = append(hosts, part)
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []string{"atlorium.com"}
	}

	var (
		certificates []Certificate
		err          error
	)
	// Несколько хостов — ОДИН запрос к /batch вместо N отдельных.
	if len(hosts) == 1 {
		var one *Certificate
		if one, err = CheckHost(hosts[0], 443); err == nil {
			certificates = []Certificate{*one}
		}
	} else {
		certificates, err = CheckBatch(hosts, 443)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		return 3 // проверка не выполнена — это не «всё хорошо»
	}

	// Батч отвечает одним объектом на хост и в том же порядке. Если это вдруг
	// не так — молча проверять «не те» хосты хуже, чем честно упасть.
	if len(certificates) != len(hosts) {
		fmt.Fprintf(os.Stderr, "Ошибка: API вернул %d результатов на %d хостов\n", len(certificates), len(hosts))
		return 3
	}

	fmt.Printf("Проверено хостов: %d — запросов к API: 1\n\n", len(hosts))

	reports := make([]*Report, 0, len(hosts))
	worst := LevelOK
	for i, host := range hosts {
		report := MonitorExpiry(host, &certificates[i])
		reports = append(reports, report)
		if report.Level > worst {
			worst = report.Level
		}
	}
	printReport(reports)

	fmt.Println()
	switch worst {
	case LevelOK:
		fmt.Printf("Вердикт: OK — все сертификаты валидны, запас больше %d дн.\n", WarningDays)
	case LevelWarning:
		fmt.Printf("Вердикт: WARNING — есть сертификаты со сроком меньше %d дн.\n", WarningDays)
	default:
		fmt.Println("Вердикт: CRITICAL — требуется вмешательство.")
	}

	// Ключевая деталь: код выхода. Именно он делает из примера рабочую проверку
	// для cron и CI — шаг workflow покраснеет сам, без внешнего парсинга вывода.
	fmt.Printf("Код выхода: %d\n", worst)
	return worst
}

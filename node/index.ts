/**
 * Клиент API проверки SSL/TLS-сертификата Atlorium — мониторинг срока действия.
 *
 * Запуск (работает сразу, без регистрации — на демо-ключе):
 *   npm install
 *   npm start
 *   npm start -- atlorium.com github.com
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

/**
 * Публичный демо-ключ. С ним API отвечает правдоподобными МОКАМИ (не реальными
 * данными): сертификат сгенерирован, а не снят с настоящего хоста. Ответы
 * детерминированы — один и тот же хост всегда даёт один и тот же результат,
 * поэтому на них можно писать стабильные тесты.
 */
const SANDBOX_KEY = 'ak_sandbox_demo_mockdata_v1';

const API_KEY = process.env.ATLORIUM_API_KEY ?? SANDBOX_KEY;
const BASE_URL = process.env.ATLORIUM_BASE_URL ?? 'https://atlorium.com';

/** Проверка сертификата — настоящий TCP+TLS handshake с чужим хостом, он может тянуть. */
const TIMEOUT_MS = 30_000;

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
export const Level = { OK: 0, WARNING: 1, CRITICAL: 2 } as const;
export type Level = (typeof Level)[keyof typeof Level];

const LEVEL_NAMES: Record<Level, string> = {
  [Level.OK]: 'OK',
  [Level.WARNING]: 'WARNING',
  [Level.CRITICAL]: 'CRITICAL',
};

/** Звено цепочки сертификатов. */
export interface ChainLink {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  thumbprint: string;
  isValid: boolean;
  errors: string[];
}

/** Ответ API: данные TLS-сертификата хоста. */
export interface Certificate {
  isValid: boolean;
  expirationDate: string;
  daysRemaining: number;
  issuer: string;
  subject: string;
  subjectAlternativeNames: string[];
  errors: string[];
  tlsVersion: string;
  validFrom: string;
  serialNumber: string;
  thumbprint: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  keySize: number;
  hasPrivateKey: boolean;
  isSelfSigned: boolean;
  certificateChain: ChainLink[];
  connectionTime: string;
  host: string;
  port: number;
  checkedAt: string;
}

const ERROR_REASONS: Record<number, string> = {
  400: 'Хост не указан или порт вне диапазона 1–65535',
  401: 'API-ключ отсутствует, просрочен или недействителен',
  402: 'Недостаточно кредитов на балансе — пополните на https://atlorium.com',
  429: 'Превышен лимит запросов — повторите позже',
  500: 'Не удалось снять сертификат: хост недоступен, таймаут или на порту нет TLS '
    + '(за неудачную проверку деньги не списываются)',
};

/** Ошибка API: HTTP-код разложен в человекочитаемую причину. */
export class AtloriumError extends Error {
  constructor(readonly status: number, body: string) {
    const reason = ERROR_REASONS[status] ?? 'Неизвестная ошибка';
    super(`HTTP ${status}: ${reason}. Ответ сервера: ${body.slice(0, 200)}`);
    this.name = 'AtloriumError';
  }
}

const sleep = (seconds: number) => new Promise((resolve) => setTimeout(resolve, seconds * 1000));

/**
 * Сколько ждать после 429. Мусор и слишком большие значения не берём на веру:
 * 0 означало бы busy-loop, 40+ минут — «спи почти час». Возвращаем 0, если ждать
 * бессмысленно долго: вызывающий сдастся и честно скажет, что квота исчерпана.
 */
function retryAfter(response: Response): number {
  const seconds = Number.parseInt(response.headers.get('Retry-After') ?? '', 10);
  if (!Number.isFinite(seconds) || seconds <= 0) return RETRY_DELAY;
  return seconds <= MAX_RETRY_DELAY ? seconds : 0;
}

async function request<T>(path: string, params: Record<string, string>): Promise<T> {
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    const url = new URL(path, BASE_URL);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(key, value);
    }

    const response = await fetch(url, {
      headers: { Authorization: `Bearer ${API_KEY}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    if (response.status === 429 && attempt < MAX_RETRIES) {
      const delay = retryAfter(response);
      if (delay === 0) break; // ждать пришлось бы дольше потолка — не ждём
      console.error(`429: лимит запросов. Повтор через ${delay} с…`);
      await sleep(delay);
      continue;
    }

    if (!response.ok) {
      throw new AtloriumError(response.status, await response.text());
    }
    return (await response.json()) as T;
  }

  throw new AtloriumError(429, 'Квота исчерпана, повтор бессмыслен');
}

// ── Эндпоинты ────────────────────────────────────────────────────────────────

/** Сертификат одного хоста: GET /api/Certificate?host=…&port=… */
export async function checkHost(host: string, port = 443): Promise<Certificate> {
  return request<Certificate>('/api/Certificate', { host, port: String(port) });
}

/** Сертификат по URL — хост и порт извлекаются автоматически. */
export async function checkUrl(url: string): Promise<Certificate> {
  return request<Certificate>('/api/Certificate/url', { url });
}

/**
 * Пакетная проверка: GET /api/Certificate/batch?hosts=a,b,c&port=…
 *
 * До 10 хостов ЗА ОДИН запрос. Это не только быстрее (сервер проверяет их
 * параллельно) — это ещё и один вызов по тарификации и по rate-limit вместо
 * десяти. Для мониторинга парка доменов разница принципиальная.
 */
export async function checkBatch(hosts: string[], port = 443): Promise<Certificate[]> {
  if (hosts.length > BATCH_LIMIT) {
    throw new Error(`Не больше ${BATCH_LIMIT} хостов за один запрос`);
  }
  return request<Certificate[]>('/api/Certificate/batch', {
    hosts: hosts.join(','),
    port: String(port),
  });
}

// ── Применение данных: мониторинг сертификатов ───────────────────────────────
// Ответ API сам по себе — просто JSON. Ценность появляется, когда из него делают
// вывод: будить дежурного или можно спать. Ниже — ровно те проверки, которые
// отличают «сертификат есть» от «сертификат работает».

export interface Report {
  host: string;
  cert: Certificate;
  level: Level;
  problems: string[];
}

/**
 * Покрывает ли SAN-список запрошенный хост — с учётом wildcard-масок.
 *
 * Браузер сверяет имя хоста с subjectAlternativeNames, а НЕ с CN. Сертификат
 * может быть идеально валиден и при этом не подходить домену: типичная авария —
 * сертификат на `*.example.com` повесили на `example.com` (маска покрывает ровно
 * один уровень поддомена и не покрывает сам домен).
 */
export function coversHost(host: string, names: string[]): boolean {
  const target = host.trim().replace(/\.$/, '').toLowerCase();

  for (const raw of names ?? []) {
    const name = raw.trim().replace(/\.$/, '').toLowerCase();
    if (name === target) return true;

    if (name.startsWith('*.')) {
      const suffix = name.slice(1); // "*.example.com" → ".example.com"
      if (target.endsWith(suffix)) {
        const label = target.slice(0, -suffix.length);
        // Ровно один уровень: foo.example.com — да, a.foo.example.com — нет.
        if (label.length > 0 && !label.includes('.')) return true;
      }
    }
  }
  return false;
}

/** Светофор по одному сертификату. Уровень отчёта = код выхода программы. */
export function monitorExpiry(host: string, cert: Certificate): Report {
  const problems: string[] = [];
  let level: Level = Level.OK;

  const fail = (next: Level, problem: string): void => {
    level = Math.max(level, next) as Level;
    problems.push(problem);
  };

  // 1. Валидность и ошибки цепочки: истёкший, самоподписанный, отозванный,
  //    неизвестный УЦ. Браузер на таком покажет красный экран — значит, это
  //    авария независимо от того, сколько дней осталось.
  if (!cert.isValid) fail(Level.CRITICAL, 'Сертификат невалиден');
  for (const error of cert.errors ?? []) fail(Level.CRITICAL, `Ошибка проверки: ${error}`);
  if (cert.isSelfSigned) fail(Level.CRITICAL, 'Самоподписанный сертификат — клиенты его не примут');
  for (const link of cert.certificateChain ?? []) {
    for (const error of link.errors ?? []) fail(Level.CRITICAL, `Цепочка (${link.subject}): ${error}`);
  }

  // 2. Несовпадение SAN. Сертификат валиден, но выписан на другое имя —
  //    браузер покажет NET::ERR_CERT_COMMON_NAME_INVALID.
  const names = cert.subjectAlternativeNames ?? [];
  if (!coversHost(host, names)) {
    fail(Level.CRITICAL, `MISMATCH: ${host} не покрыт SAN (${names.length ? names.join(', ') : 'список пуст'})`);
  }

  // 3. Срок действия — светофор.
  const days = cert.daysRemaining;
  if (days < 0) {
    fail(Level.CRITICAL, `Сертификат истёк ${-days} дн. назад`);
  } else if (days < CRITICAL_DAYS) {
    fail(Level.CRITICAL, `Истекает через ${days} дн. — меньше порога ${CRITICAL_DAYS}`);
  } else if (days < WARNING_DAYS) {
    fail(Level.WARNING, `Истекает через ${days} дн. — пора продлевать`);
  }

  return { host, cert, level, problems };
}

// ── Печать отчёта ────────────────────────────────────────────────────────────

/** Из «CN=R3, O=Let's Encrypt, C=US» получаем «Let's Encrypt». */
function shortIssuer(issuer: string): string {
  const org = (issuer ?? '').split(',').map((part) => part.trim()).find((part) => part.startsWith('O='));
  return org ? org.slice(2) : issuer || '—';
}

const pad = (value: string, width: number) => value.padEnd(width);

function printReport(reports: Report[]): void {
  console.log(
    `${pad('ХОСТ', 26)}${'ДНЕЙ'.padStart(5)}  ${pad('ИСТЕКАЕТ', 12)}${pad('TLS', 8)}${pad('ИЗДАТЕЛЬ', 20)}СТАТУС`,
  );

  for (const { host, cert, level } of reports) {
    console.log(
      pad(host, 26)
      + String(cert.daysRemaining).padStart(5) + '  '
      + pad((cert.expirationDate ?? '').slice(0, 10), 12)
      + pad(cert.tlsVersion || '—', 8)
      + pad(shortIssuer(cert.issuer).slice(0, 19), 20)
      + LEVEL_NAMES[level],
    );
  }

  for (const { host, level, problems } of reports) {
    if (problems.length === 0) continue;
    console.log(`\n[${LEVEL_NAMES[level]}] ${host}`);
    problems.forEach((problem) => console.log(`  - ${problem}`));
  }
}

async function main(): Promise<number> {
  if (API_KEY === SANDBOX_KEY) {
    console.log('Демо-ключ: сертификат сгенерирован (мок), а не снят с реального хоста.\n');
  }

  // Хосты можно передать и списком аргументов, и через запятую.
  const args = process.argv.slice(2).join(' ').replace(/,/g, ' ').split(/\s+/).filter(Boolean);
  const hosts = args.length > 0 ? args : ['atlorium.com'];

  let certs: Certificate[];
  try {
    // Несколько хостов — ОДИН запрос к /batch вместо N отдельных.
    certs = hosts.length === 1
      ? [await checkHost(hosts[0] as string)]
      : await checkBatch(hosts);
  } catch (error: unknown) {
    console.error('Ошибка:', error instanceof Error ? error.message : error);
    return 3; // проверка не выполнена — это не «всё хорошо»
  }

  // Батч отвечает одним объектом на хост и в том же порядке. Если это вдруг
  // не так — молча проверять «не те» хосты хуже, чем честно упасть.
  if (certs.length !== hosts.length) {
    console.error(`Ошибка: API вернул ${certs.length} результатов на ${hosts.length} хостов`);
    return 3;
  }

  console.log(`Проверено хостов: ${hosts.length} — запросов к API: 1\n`);

  const reports = hosts.map((host, index) => monitorExpiry(host, certs[index] as Certificate));
  printReport(reports);

  const worst = reports.reduce<Level>((max, report) => (report.level > max ? report.level : max), Level.OK);
  console.log();
  if (worst === Level.OK) {
    console.log(`Вердикт: OK — все сертификаты валидны, запас больше ${WARNING_DAYS} дн.`);
  } else if (worst === Level.WARNING) {
    console.log(`Вердикт: WARNING — есть сертификаты со сроком меньше ${WARNING_DAYS} дн.`);
  } else {
    console.log('Вердикт: CRITICAL — требуется вмешательство.');
  }

  // Ключевая деталь: код выхода. Именно он делает из примера рабочую проверку
  // для cron и CI — шаг workflow покраснеет сам, без внешнего парсинга вывода.
  console.log(`Код выхода: ${worst}`);
  return worst;
}

// Запуск только когда файл выполняется напрямую, а не импортируется.
if (process.argv[1]?.includes('index')) {
  main().then((code) => process.exit(code));
}

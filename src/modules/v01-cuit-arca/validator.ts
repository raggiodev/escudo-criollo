import {
  CuitEntityType,
  CuitValidationResult,
  DataFiscalAuditResult,
  MAX_SCANNED_TEXT_CHARS,
  MAX_URL_LENGTH,
  parseSafeHttpUrl,
  safeTruncate,
} from '../../types';
import {
  getSafeAttr,
  getSafeDocumentUrl,
  isAnchorElement,
  isHtmlElement,
  isImageElement,
} from '../../utils/dom-safety';

const VALID_CUIT_PREFIXES = new Set([
  '20',
  '23',
  '24',
  '25',
  '26',
  '27',
  '30',
  '33',
  '34',
]);

const MODULO_11_WEIGHTS = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2] as const;

// Strict format for standalone CUIT input: 11 digits or XX-XXXXXXXX-X (hyphens, spaces, or dots only; zero letters)
const STRICT_CUIT_FORMAT_REGEX = /^\d{2}[-\s.]?\d{8}[-\s.]?\d$/;
const INVALID_CUIT_CHARS_REGEX = /[a-zA-Z]|[^\d\s.-]/;

// Linear-time O(n) CUIT extraction patterns for page text
const FORMATTED_CUIT_REGEX = /\b(20|23|24|25|26|27|30|33|34)([-\s]?)\d{8}\2\d\b/g;
const LABELED_CUIT_REGEX =
  /\bC\.?U\.?I\.?(?:T|L)\.?[:\s#º°.-]{0,6}(\d{2}[-\s.]?\d{8}[-\s.]?\d)\b/gi;

// Linear-time O(n) Data Fiscal / ARCA / AFIP F.960 seal indicator (avoids matching "marca"/"barca")
const DATA_FISCAL_SEAL_REGEX =
  /(?:data[\s._-]{0,2}fiscal)|(?:(?:^|[^a-z0-9])(?:f\.?960|afip|arca)(?:$|[^a-z0-9]))/i;

// Linear-time O(n) hydration payload matcher for official ARCA/AFIP QR validation endpoints
const HYDRATION_OFFICIAL_QR_REGEX =
  /https?:\/\/(?:qr|serviciosweb|servicios1)\.(?:afip|arca)\.gob\.ar\/[^\s"'<>`\\]{4,512}/gi;

const FORMAT_LETTERS_ERROR =
  'Formato inválido: el CUIT solo puede contener 11 números (sin letras).';

function classifyCuitPrefix(prefix: string): {
  entityType: CuitEntityType;
  entityLabel: string;
} {
  switch (prefix) {
    case '20':
      return {
        entityType: 'PERSONA_HUMANA_MASC',
        entityLabel: 'Persona Humana (Prefijo 20)',
      };
    case '27':
      return {
        entityType: 'PERSONA_HUMANA_FEM',
        entityLabel: 'Persona Humana (Prefijo 27)',
      };
    case '23':
    case '24':
    case '25':
    case '26':
      return {
        entityType: 'PERSONA_HUMANA_MIXTA',
        entityLabel: `Persona Humana (Prefijo ${prefix})`,
      };
    case '30':
    case '33':
    case '34':
      return {
        entityType: 'PERSONA_JURIDICA',
        entityLabel: `Empresa / Persona Jurídica (Prefijo ${prefix})`,
      };
    default:
      return {
        entityType: 'DESCONOCIDO',
        entityLabel: `Prefijo no oficial (${prefix || '??'})`,
      };
  }
}

function isTrivialRepeatedMiddle(middleEight: string): boolean {
  if (middleEight.length !== 8) {
    return true;
  }
  const firstChar = middleEight[0];
  let allSame = true;
  for (let i = 1; i < 8; i++) {
    if (middleEight[i] !== firstChar) {
      allSame = false;
      break;
    }
  }
  if (allSame) {
    return true;
  }
  const numericVal = Number(middleEight);
  return !Number.isFinite(numericVal) || numericVal < 10_000;
}

function computeExpectedVerifier(firstTenDigits: string): number {
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    const digit = firstTenDigits.charCodeAt(i) - 48;
    const weight = MODULO_11_WEIGHTS[i] ?? 0;
    sum += digit * weight;
  }
  const remainder = sum % 11;
  const diff = 11 - remainder;
  if (diff === 11) {
    return 0;
  }
  if (diff === 10) {
    return 9;
  }
  return diff;
}

/**
 * Formats an 11-digit numeric CUIT string into standard Argentine XX-XXXXXXXX-X notation.
 * Does not strip letters from malformed alphanumeric strings.
 */
export function formatCUIT(raw: string): string {
  const trimmed = typeof raw === 'string' ? raw.trim().slice(0, 128) : '';
  if (!trimmed || INVALID_CUIT_CHARS_REGEX.test(trimmed)) {
    return safeTruncate(trimmed, 32);
  }
  const digits = trimmed.replace(/\D/g, '');
  if (digits.length !== 11) {
    return safeTruncate(trimmed, 32);
  }
  return `${digits.slice(0, 2)}-${digits.slice(2, 10)}-${digits.slice(10)}`;
}

/**
 * Performs strict Argentine CUIT/CUIL format, prefix, anti-trivial, and Modulo 11 validation.
 * Immediately rejects any input containing letters or invalid symbols.
 */
export function validateCUIT(raw: string): CuitValidationResult {
  const trimmedRaw = typeof raw === 'string' ? raw.trim() : '';
  const safeRaw = safeTruncate(trimmedRaw, 64);

  if (!trimmedRaw || INVALID_CUIT_CHARS_REGEX.test(trimmedRaw)) {
    return {
      raw: safeRaw,
      digits: '',
      formatted: safeTruncate(trimmedRaw, 24),
      prefix: '',
      isValid: false,
      entityType: 'DESCONOCIDO',
      entityLabel: 'Formato inválido',
      reason: FORMAT_LETTERS_ERROR,
      errorReason: FORMAT_LETTERS_ERROR,
    };
  }

  const digits = trimmedRaw.replace(/\D/g, '');
  const prefix = digits.slice(0, 2);
  const { entityType, entityLabel } = classifyCuitPrefix(prefix);

  if (digits.length !== 11) {
    const lengthMsg = `Debe tener exactamente 11 dígitos numéricos (se detectaron ${digits.length}).`;
    return {
      raw: safeRaw,
      digits,
      formatted: safeTruncate(trimmedRaw, 24),
      prefix,
      isValid: false,
      entityType: 'DESCONOCIDO',
      entityLabel: 'Longitud inválida',
      reason: lengthMsg,
      errorReason: lengthMsg,
    };
  }

  if (!STRICT_CUIT_FORMAT_REGEX.test(trimmedRaw)) {
    return {
      raw: safeRaw,
      digits,
      formatted: safeTruncate(trimmedRaw, 24),
      prefix,
      isValid: false,
      entityType: 'DESCONOCIDO',
      entityLabel: 'Formato inválido',
      reason: FORMAT_LETTERS_ERROR,
      errorReason: FORMAT_LETTERS_ERROR,
    };
  }

  const formatted = `${digits.slice(0, 2)}-${digits.slice(2, 10)}-${digits.slice(10)}`;

  if (!VALID_CUIT_PREFIXES.has(prefix)) {
    const prefixMsg = `El prefijo "${prefix}" no existe en el padrón oficial de ARCA/AFIP.`;
    return {
      raw: safeRaw,
      digits,
      formatted,
      prefix,
      isValid: false,
      entityType: 'DESCONOCIDO',
      entityLabel,
      reason: prefixMsg,
      errorReason: prefixMsg,
    };
  }

  const middleEight = digits.slice(2, 10);
  if (isTrivialRepeatedMiddle(middleEight)) {
    const trivialMsg =
      'CUIT apócrifo: contiene una secuencia repetitiva o ficticia de relleno.';
    return {
      raw: safeRaw,
      digits,
      formatted,
      prefix,
      isValid: false,
      entityType,
      entityLabel,
      reason: trivialMsg,
      errorReason: trivialMsg,
    };
  }

  const expectedVerifier = computeExpectedVerifier(digits.slice(0, 10));
  const actualVerifier = digits.charCodeAt(10) - 48;

  if (actualVerifier !== expectedVerifier) {
    const modMsg = `Falla matemática Módulo 11: el dígito verificador debería ser ${expectedVerifier}, pero figura ${actualVerifier}.`;
    return {
      raw: safeRaw,
      digits,
      formatted,
      prefix,
      isValid: false,
      entityType,
      entityLabel,
      reason: modMsg,
      errorReason: modMsg,
    };
  }

  return {
    raw: safeRaw,
    digits,
    formatted,
    prefix,
    isValid: true,
    entityType,
    entityLabel,
    reason: 'Dígito verificador Módulo 11 válido y prefijo oficial de ARCA/AFIP.',
  };
}

/**
 * Boolean check for strict format + Modulo 11 + prefix + anti-trivial sequence CUIT validity.
 */
export function isValidCUIT(raw: string): boolean {
  return validateCUIT(raw).isValid;
}

/**
 * Scans bounded text (capped at 150 KB) for formatted or explicitly labeled CUIT strings.
 * Deduplicates by 11-digit key and distinguishes valid CUITs from forged/invalid CUITs.
 */
export function extractCUITsFromText(text: string): CuitValidationResult[] {
  if (typeof text !== 'string' || text.length === 0) {
    return [];
  }

  const boundedText = text.slice(0, MAX_SCANNED_TEXT_CHARS);
  const seenDigits = new Map<string, CuitValidationResult>();

  // Pass 1: Explicitly labeled CUIT / CUIL mentions
  LABELED_CUIT_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = LABELED_CUIT_REGEX.exec(boundedText)) !== null) {
    const candidate = match[1];
    if (!candidate) {
      continue;
    }
    const validated = validateCUIT(candidate);
    if (validated.digits.length === 11 && !seenDigits.has(validated.digits)) {
      seenDigits.set(validated.digits, validated);
    }
    if (seenDigits.size >= 25) {
      break;
    }
  }

  // Pass 2: Official-prefix 11-digit sequences (XX-XXXXXXXX-X, XX XXXXXXXX X, or XXXXXXXXXXX)
  FORMATTED_CUIT_REGEX.lastIndex = 0;
  while (seenDigits.size < 25 && (match = FORMATTED_CUIT_REGEX.exec(boundedText)) !== null) {
    const candidate = match[0];
    const startIdx = match.index;
    const precedingContext = boundedText
      .slice(Math.max(0, startIdx - 12), startIdx)
      .toLowerCase();
    const isPhoneContext =
      !candidate.includes('-') &&
      (precedingContext.includes('+54') ||
        precedingContext.includes('tel') ||
        precedingContext.includes('wa.me'));
    if (isPhoneContext) {
      continue;
    }

    const validated = validateCUIT(candidate);
    if (validated.digits.length === 11 && !seenDigits.has(validated.digits)) {
      seenDigits.set(validated.digits, validated);
    }
  }

  return Array.from(seenDigits.values());
}

function isOfficialArcaQrValidationUrl(url: URL): boolean {
  const host = url.hostname.toLowerCase();
  const isOfficialDomain =
    host === 'afip.gob.ar' ||
    host.endsWith('.afip.gob.ar') ||
    host === 'arca.gob.ar' ||
    host.endsWith('.arca.gob.ar');

  if (!isOfficialDomain) {
    return false;
  }

  let hasNonEmptyQueryValue = false;
  url.searchParams.forEach((value) => {
    if (value.trim().length > 0) {
      hasNonEmptyQueryValue = true;
    }
  });

  if (!hasNonEmptyQueryValue) {
    return false;
  }

  const pathLower = url.pathname.toLowerCase();
  const isQrHostOrPath =
    host.startsWith('qr.') ||
    host.startsWith('serviciosweb.') ||
    host.startsWith('servicios1.') ||
    pathLower.includes('qr') ||
    pathLower.includes('publicinfod') ||
    pathLower.includes('datafiscal') ||
    url.searchParams.has('qr');

  return isQrHostOrPath;
}

function isSealMentionedInString(value: string): boolean {
  if (!value) {
    return false;
  }
  return DATA_FISCAL_SEAL_REGEX.test(value.slice(0, 512));
}

/**
 * Normalizes legacy ARCA/AFIP `/clavefiscal/qr/response.aspx?qr=...` links
 * (such as CompraGamer's footer link) to the public F.960 viewer `http://qr.afip.gob.ar/?qr=...`
 * so clicking "QR Oficial Verificado" opens the public Data Fiscal sheet instead of Clave Fiscal login.
 */
export function normalizeOfficialAfipQrUrl(url: URL): string {
  const pathLower = url.pathname.toLowerCase();
  if (
    (pathLower.includes('/clavefiscal/qr/response.aspx') ||
      pathLower.includes('/qr/response.aspx')) &&
    url.searchParams.has('qr')
  ) {
    const rawMatch = /[?&]qr=([^&#]+)/i.exec(url.search);
    const rawQrToken = rawMatch?.[1]
      ? rawMatch[1].trim()
      : (url.searchParams.get('qr') ?? '').trim();
    if (rawQrToken.length > 0) {
      return safeTruncate(
        `http://qr.afip.gob.ar/?qr=${rawQrToken}`,
        MAX_URL_LENGTH,
      );
    }
  }
  return safeTruncate(url.href, MAX_URL_LENGTH);
}

/**
 * Scans inline hydration payloads (<script type="application/ld+json">, <noscript>, inline <script>)
 * up to 150 KB so VTEX, Next.js, and Angular SPAs with lazy-loaded footers are recognized immediately.
 */
function scanHydrationPayloadsForOfficialQr(doc: Document): string | null {
  const hydrationNodes = doc.querySelectorAll(
    'script[type="application/ld+json" i], noscript, script:not([src])',
  );
  const maxNodes = Math.min(hydrationNodes.length, 80);
  const chunks: string[] = [];
  let totalChars = 0;

  for (let i = 0; i < maxNodes; i++) {
    if (totalChars >= MAX_SCANNED_TEXT_CHARS) {
      break;
    }
    const node = hydrationNodes[i];
    if (!isHtmlElement(node, doc)) {
      continue;
    }
    const rawText = typeof node.textContent === 'string' ? node.textContent : '';
    if (!rawText || (!rawText.includes('afip.gob.ar') && !rawText.includes('arca.gob.ar'))) {
      continue;
    }
    const remaining = MAX_SCANNED_TEXT_CHARS - totalChars;
    const slice = rawText.slice(0, remaining);
    chunks.push(slice);
    totalChars += slice.length;
  }

  if (chunks.length === 0) {
    return null;
  }

  const normalizedPayload = chunks
    .join('\n')
    .slice(0, MAX_SCANNED_TEXT_CHARS)
    .replace(/\\\//g, '/')
    .replace(/\\u002[fF]/g, '/')
    .replace(/\\u0026/g, '&')
    .replace(/&amp;/gi, '&');

  HYDRATION_OFFICIAL_QR_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = HYDRATION_OFFICIAL_QR_REGEX.exec(normalizedPayload)) !== null) {
    const candidate = match[0];
    const parsed = parseSafeHttpUrl(candidate);
    if (parsed && isOfficialArcaQrValidationUrl(parsed)) {
      return normalizeOfficialAfipQrUrl(parsed);
    }
  }

  return null;
}

export const NON_ECOMMERCE_PLATFORMS = [
  'github.com',
  'gitlab.com',
  'bitbucket.org',
  'stackoverflow.com',
  'google.com',
  'google.com.ar',
  'youtube.com',
  'youtu.be',
  'x.com',
  'twitter.com',
  'linkedin.com',
  'reddit.com',
  'wikipedia.org',
  'medium.com',
  'substack.com',
  'orcid.org',
  'linktr.ee',
  'discord.com',
  'whatsapp.com',
  'telegram.org',
  't.me',
  'gmail.com',
  'outlook.com',
  'live.com',
  'chatgpt.com',
  'openai.com',
  'gemini.google.com',
  'claude.ai',
] as const;

export function isNonEcommercePlatformHost(hostname: string): boolean {
  if (!hostname) {
    return false;
  }
  const clean = hostname.toLowerCase();
  return NON_ECOMMERCE_PLATFORMS.some(
    (domain) => clean === domain || clean.endsWith(`.${domain}`),
  );
}

const CODE_OR_DOC_CONTAINER_SELECTOR =
  'code, pre, article.markdown-body, [class*="markdown" i], [data-hpc], .react-directory-row, .Box-row';

const FOOTER_CONTAINER_SELECTOR =
  'footer, [role="contentinfo"], [class*="footer" i], [id*="footer" i], [class*="pie-pagina" i]';

const STRICT_SEAL_TEXT_REGEX =
  /^(?:data\s*fiscal|formulario\s*960|f\.?\s*960(?:\s*afip|\s*arca)?|sello\s*afip|qr\s*afip|qr\s*arca)$/i;

function isInsideCodeOrDocContainer(el: Element): boolean {
  try {
    return el.closest(CODE_OR_DOC_CONTAINER_SELECTOR) !== null;
  } catch {
    return false;
  }
}

/**
 * Forensic DOM & SPA hydration inspector for Argentine F.960 Data Fiscal QR seals.
 * Detects genuine clickable ARCA/AFIP validation links vs. forged static/broken scam seals.
 */
export function inspectDataFiscalDOM(
  doc: Document,
  explicitPageUrl?: string,
): DataFiscalAuditResult {
  const baseUrlObj = getSafeDocumentUrl(doc, explicitPageUrl);
  const baseUrlStr = baseUrlObj ? baseUrlObj.href : 'https://localhost/';
  const pageHost = baseUrlObj ? baseUrlObj.hostname.toLowerCase() : '';

  const isGovPortal = pageHost === 'gob.ar' || pageHost.endsWith('.gob.ar');
  const isNonEcommercePlatform = isNonEcommercePlatformHost(pageHost);

  if (isNonEcommercePlatform) {
    return {
      status: 'MISSING_DATA_FISCAL',
      officialQrUrl: null,
      forgedEvidence: null,
      summary:
        'Plataforma informativa, red social o repositorio de código (no aplica sello comercial F.960).',
    };
  }

  const verifiedAnchors = new Set<HTMLAnchorElement>();
  let firstOfficialQrUrl: string | null = null;

  // Step 1: Inspect all mounted <a> elements safely (capped at 1,500 anchors)
  const anchorNodes = doc.querySelectorAll('a');
  const maxAnchors = Math.min(anchorNodes.length, 1500);

  for (let i = 0; i < maxAnchors; i++) {
    const node = anchorNodes[i];
    if (!isAnchorElement(node, doc) || isInsideCodeOrDocContainer(node)) {
      continue;
    }
    const rawHref = node.getAttribute('href');
    if (!rawHref) {
      continue;
    }
    const parsed = parseSafeHttpUrl(rawHref, baseUrlStr);
    if (parsed && isOfficialArcaQrValidationUrl(parsed)) {
      verifiedAnchors.add(node);
      if (!firstOfficialQrUrl) {
        firstOfficialQrUrl = normalizeOfficialAfipQrUrl(parsed);
      }
    }
  }

  if (firstOfficialQrUrl) {
    return {
      status: 'VERIFIED_OFFICIAL_QR',
      officialQrUrl: firstOfficialQrUrl,
      forgedEvidence: null,
      summary:
        'Sello F.960 Data Fiscal oficial detectado con enlace verificable a ARCA/AFIP.',
    };
  }

  if (isGovPortal) {
    return {
      status: 'MISSING_DATA_FISCAL',
      officialQrUrl: null,
      forgedEvidence: null,
      summary: 'Portal gubernamental oficial (.gob.ar).',
    };
  }

  // Step 2: Check for FORGED_STATIC_SEAL on mounted <img> elements
  const imgNodes = doc.querySelectorAll('img');
  const maxImages = Math.min(imgNodes.length, 1000);

  for (let i = 0; i < maxImages; i++) {
    const node = imgNodes[i];
    if (!isImageElement(node, doc) || isInsideCodeOrDocContainer(node)) {
      continue;
    }

    const rawSrc = getSafeAttr(node, 'src', 512);
    const rawDataSrc =
      getSafeAttr(node, 'data-src', 512) || getSafeAttr(node, 'srcset', 512);
    const rawAlt = getSafeAttr(node, 'alt', 256);
    const rawTitle = getSafeAttr(node, 'title', 256);

    const mentionsDataFiscal =
      isSealMentionedInString(rawSrc) ||
      isSealMentionedInString(rawDataSrc) ||
      isSealMentionedInString(rawAlt) ||
      isSealMentionedInString(rawTitle);

    if (!mentionsDataFiscal) {
      continue;
    }

    const parentAnchor = node.closest('a');
    if (parentAnchor && isAnchorElement(parentAnchor, doc) && verifiedAnchors.has(parentAnchor)) {
      continue;
    }

    let wrapperDetail = 'imagen estática sin enlace oficial';
    if (parentAnchor && isAnchorElement(parentAnchor, doc)) {
      const rawWrapperHref = (parentAnchor.getAttribute('href') ?? '').trim();
      if (
        rawWrapperHref === '' ||
        rawWrapperHref === '#' ||
        rawWrapperHref.toLowerCase().startsWith('javascript:')
      ) {
        wrapperDetail = `enlace vacío o desactivado (href="${safeTruncate(rawWrapperHref || '#', 48)}")`;
      } else {
        const parsedWrapper = parseSafeHttpUrl(rawWrapperHref, baseUrlStr);
        if (parsedWrapper) {
          wrapperDetail = `apunta a "${safeTruncate(parsedWrapper.hostname + parsedWrapper.pathname, 80)}" sin validación QR de ARCA/AFIP`;
        } else {
          wrapperDetail = 'enlace con protocolo bloqueado o inválido';
        }
      }
    }

    const labelSnippet = rawAlt || rawTitle || rawSrc.split('/').pop() || 'Data Fiscal';
    return {
      status: 'FORGED_STATIC_SEAL',
      officialQrUrl: null,
      forgedEvidence: safeTruncate(`${labelSnippet} (${wrapperDetail})`, 256),
      summary:
        '¡ALERTA! Se detectó una imagen de Data Fiscal / ARCA / AFIP pegada sin vínculo oficial válido (sello trucho o desactivado).',
    };
  }

  // Step 3: Check <a> links inside a footer explicitly claiming to be the tax seal itself that point nowhere
  for (let i = 0; i < maxAnchors; i++) {
    const node = anchorNodes[i];
    if (
      !isAnchorElement(node, doc) ||
      !isHtmlElement(node, doc) ||
      isInsideCodeOrDocContainer(node)
    ) {
      continue;
    }

    let isInFooter = false;
    try {
      isInFooter = node.closest(FOOTER_CONTAINER_SELECTOR) !== null;
    } catch {
      isInFooter = false;
    }
    if (!isInFooter) {
      continue;
    }

    const anchorText = safeTruncate(node.textContent ?? '', 160).trim();
    if (
      anchorText.length > 0 &&
      anchorText.length <= 45 &&
      STRICT_SEAL_TEXT_REGEX.test(anchorText)
    ) {
      const rawHref = (node.getAttribute('href') ?? '').trim();
      const parsed = parseSafeHttpUrl(rawHref, baseUrlStr);
      if (!parsed || !isOfficialArcaQrValidationUrl(parsed)) {
        const targetDesc = parsed
          ? `${parsed.hostname}${parsed.pathname}`
          : rawHref || '#';
        return {
          status: 'FORGED_STATIC_SEAL',
          officialQrUrl: null,
          forgedEvidence: safeTruncate(
            `Enlace "${anchorText}" falso -> ${targetDesc}`,
            256,
          ),
          summary:
            '¡ALERTA! El enlace de Data Fiscal F.960 no dirige al validador oficial de ARCA/AFIP.',
        };
      }
    }
  }

  // Step 4: Deep scan inline SPA hydration state (VTEX __STATE__, Next.js, Angular, JSON-LD, <noscript>)
  const hydratedOfficialQrUrl = scanHydrationPayloadsForOfficialQr(doc);
  if (hydratedOfficialQrUrl) {
    return {
      status: 'VERIFIED_OFFICIAL_QR',
      officialQrUrl: hydratedOfficialQrUrl,
      forgedEvidence: null,
      summary:
        'Sello F.960 Data Fiscal oficial verificado en estado de hidratación del sitio (ARCA/AFIP).',
    };
  }

  return {
    status: 'MISSING_DATA_FISCAL',
    officialQrUrl: null,
    forgedEvidence: null,
    summary: 'No se encontró código QR F.960 Data Fiscal de ARCA/AFIP en esta página.',
  };
}

export const inspectDataFiscal = inspectDataFiscalDOM;

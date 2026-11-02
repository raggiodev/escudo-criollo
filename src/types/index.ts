export const MAX_SCANNED_TEXT_CHARS = 150_000;
export const MAX_FIELD_LENGTH = 256;
export const MAX_URL_LENGTH = 2048;

export type RiskLevel = 'SAFE' | 'WARNING' | 'DANGER' | 'NEUTRAL';
export type FindingSeverity = 'SAFE' | 'WARNING' | 'DANGER';

export interface AuditFinding {
  id: string;
  severity: FindingSeverity;
  title: string;
  detail: string;
  evidence?: string;
}

export type CuitEntityType =
  | 'PERSONA_HUMANA_MASC'
  | 'PERSONA_HUMANA_FEM'
  | 'PERSONA_HUMANA_MIXTA'
  | 'PERSONA_JURIDICA'
  | 'DESCONOCIDO';

export interface CuitValidationResult {
  raw: string;
  digits: string;
  formatted: string;
  prefix: string;
  isValid: boolean;
  entityType: CuitEntityType;
  entityLabel: string;
  reason: string;
}

export type DataFiscalStatus =
  | 'VERIFIED_OFFICIAL_QR'
  | 'FORGED_STATIC_SEAL'
  | 'MISSING_DATA_FISCAL';

export interface DataFiscalAuditResult {
  status: DataFiscalStatus;
  officialQrUrl: string | null;
  forgedEvidence: string | null;
  summary: string;
}

export type EcommercePlatform =
  | 'TIENDANUBE'
  | 'SHOPIFY'
  | 'WOOCOMMERCE'
  | 'MERCADOLIBRE'
  | 'MERCADOSHOPS'
  | 'VTEX'
  | 'PRESTASHOP'
  | 'MAGENTO'
  | 'TIENDA_ARGENTINA'
  | 'SITIO_OFICIAL'
  | 'NO_ECOMMERCE';

export interface EcommerceContext {
  isEcommerce: boolean;
  isWhitelistedOfficial: boolean;
  platform: EcommercePlatform;
  platformLabel: string;
  isFreeSubdomain: boolean;
  hasArsPricing: boolean;
  hasCartControls: boolean;
}

export interface StoreAuditReport {
  url: string;
  hostname: string;
  pageTitle: string;
  isHttps: boolean;
  timestamp: number;
  ecommerce: EcommerceContext;
  trustScore: number;
  riskLevel: RiskLevel;
  pillHeadline: string;
  cuits: CuitValidationResult[];
  dataFiscal: DataFiscalAuditResult;
  findings: AuditFinding[];
}

export interface SanitizeResult {
  originalUrl: string;
  cleanUrl: string;
  removedParams: string[];
  removedCount: number;
  isModified: boolean;
  isValidHttpUrl: boolean;
}

export type BadgePosition = 'bottom-left' | 'bottom-right';

export interface ExtensionSettings {
  showFloatingBadge: boolean;
  alwaysShowBadge: boolean;
  autoCleanCopiedLinks: boolean;
  badgePosition: BadgePosition;
  dismissedDomains: string[];
}

export const DEFAULT_SETTINGS: ExtensionSettings = {
  showFloatingBadge: true,
  alwaysShowBadge: false,
  autoCleanCopiedLinks: true,
  badgePosition: 'bottom-left',
  dismissedDomains: [],
};

export interface ToastNotificationPayload {
  variant: 'SAFE' | 'WARNING' | 'DANGER' | 'INFO';
  title: string;
  detail: string;
  copyText?: string;
}

export type ExtensionMessage =
  | {
      type: 'REPORT_STORE_AUDIT';
      payload: StoreAuditReport;
    }
  | {
      type: 'GET_TAB_AUDIT';
    }
  | {
      type: 'CONTEXT_MENU_TOAST';
      payload: ToastNotificationPayload;
    };

export type ExtensionMessageResponse =
  | {
      ok: true;
      report?: StoreAuditReport;
    }
  | {
      ok: false;
      error: string;
    };

/**
 * Sanitizes untrusted text extracted from hostile DOM nodes:
 * strips control characters and Unicode BiDi override spoofing chars,
 * normalizes whitespace, and enforces strict length cap (<= 256 by default).
 */
export function safeTruncate(input: unknown, maxLength: number = MAX_FIELD_LENGTH): string {
  if (typeof input !== 'string') {
    return '';
  }
  const cap = Math.max(1, Math.min(maxLength, MAX_URL_LENGTH));
  // Slice early before character filtering to avoid large intermediate allocations
  const rawSlice = input.slice(0, cap * 2);
  let cleaned = '';
  for (let i = 0; i < rawSlice.length; i++) {
    const code = rawSlice.charCodeAt(i);
    // Strip ASCII control chars (0x00-0x1F, 0x7F) and BiDi spoofing overrides (U+202A..U+202E, U+2066..U+2069)
    const isControl = code <= 0x1f || code === 0x7f;
    const isBidiOverride =
      (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
    if (isBidiOverride) {
      continue;
    }
    cleaned += isControl ? ' ' : rawSlice[i];
  }
  const collapsed = cleaned.replace(/\s+/g, ' ').trim();
  if (collapsed.length <= cap) {
    return collapsed;
  }
  return `${collapsed.slice(0, Math.max(1, cap - 1))}…`;
}

/**
 * Zero-Trust URL parser with strict http:/https: protocol whitelisting.
 * Explicitly blocks javascript:, data:, vbscript:, file:, blob:, etc.
 */
export function parseSafeHttpUrl(rawUrl: unknown, baseUrl?: string): URL | null {
  if (typeof rawUrl !== 'string') {
    return null;
  }
  const trimmed = rawUrl.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_URL_LENGTH * 2) {
    return null;
  }
  try {
    const parsed = baseUrl ? new URL(trimmed, baseUrl) : new URL(trimmed);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}


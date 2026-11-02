import { browser } from 'wxt/browser';
import {
  AuditFinding,
  BadgePosition,
  CuitValidationResult,
  DEFAULT_SETTINGS,
  DataFiscalAuditResult,
  EcommerceContext,
  ExtensionMessage,
  ExtensionSettings,
  FindingSeverity,
  MAX_URL_LENGTH,
  RiskLevel,
  StoreAuditReport,
  ToastNotificationPayload,
  safeTruncate,
} from '../types';

export const SETTINGS_STORAGE_KEY = 'escudo_criollo_settings_v1';
export const TAB_AUDITS_STORAGE_KEY = 'escudo_criollo_tab_audits_v1';

const VALID_RISK_LEVELS = new Set<RiskLevel>([
  'SAFE',
  'WARNING',
  'DANGER',
  'NEUTRAL',
]);

const VALID_SEVERITIES = new Set<FindingSeverity>([
  'SAFE',
  'WARNING',
  'DANGER',
]);

const VALID_BADGE_POSITIONS = new Set<BadgePosition>([
  'bottom-left',
  'bottom-right',
]);

function isPlainRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

/**
 * Verifies that an incoming runtime message originates strictly from this extension's own ID.
 */
export function isTrustedExtensionSender(sender: { id?: string } | undefined): boolean {
  const ownId = browser?.runtime?.id;
  if (!ownId || !sender || typeof sender.id !== 'string') {
    return false;
  }
  return sender.id === ownId;
}

/**
 * Runtime validator & normalizer for ExtensionSettings read from untrusted/corrupted storage.
 */
export function validateSettings(raw: unknown): ExtensionSettings {
  if (!isPlainRecord(raw)) {
    return { ...DEFAULT_SETTINGS };
  }

  const showFloatingBadge =
    typeof raw.showFloatingBadge === 'boolean'
      ? raw.showFloatingBadge
      : DEFAULT_SETTINGS.showFloatingBadge;

  const alwaysShowBadge =
    typeof raw.alwaysShowBadge === 'boolean'
      ? raw.alwaysShowBadge
      : DEFAULT_SETTINGS.alwaysShowBadge;

  const autoCleanCopiedLinks =
    typeof raw.autoCleanCopiedLinks === 'boolean'
      ? raw.autoCleanCopiedLinks
      : DEFAULT_SETTINGS.autoCleanCopiedLinks;

  const badgePosition: BadgePosition =
    typeof raw.badgePosition === 'string' &&
    VALID_BADGE_POSITIONS.has(raw.badgePosition as BadgePosition)
      ? (raw.badgePosition as BadgePosition)
      : DEFAULT_SETTINGS.badgePosition;

  const dismissedDomains: string[] = [];
  if (Array.isArray(raw.dismissedDomains)) {
    for (const item of raw.dismissedDomains.slice(0, 200)) {
      if (typeof item === 'string') {
        const cleanHost = safeTruncate(item.toLowerCase(), 128);
        if (cleanHost && !dismissedDomains.includes(cleanHost)) {
          dismissedDomains.push(cleanHost);
        }
      }
    }
  }

  return {
    showFloatingBadge,
    alwaysShowBadge,
    autoCleanCopiedLinks,
    badgePosition,
    dismissedDomains,
  };
}

function validateFinding(raw: unknown): AuditFinding | null {
  if (!isPlainRecord(raw)) {
    return null;
  }
  if (
    typeof raw.id !== 'string' ||
    typeof raw.severity !== 'string' ||
    !VALID_SEVERITIES.has(raw.severity as FindingSeverity) ||
    typeof raw.title !== 'string' ||
    typeof raw.detail !== 'string'
  ) {
    return null;
  }
  return {
    id: safeTruncate(raw.id, 80),
    severity: raw.severity as FindingSeverity,
    title: safeTruncate(raw.title, 180),
    detail: safeTruncate(raw.detail, 256),
    evidence:
      typeof raw.evidence === 'string'
        ? safeTruncate(raw.evidence, 256)
        : undefined,
  };
}

function validateCuitItem(raw: unknown): CuitValidationResult | null {
  if (!isPlainRecord(raw)) {
    return null;
  }
  if (
    typeof raw.digits !== 'string' ||
    typeof raw.formatted !== 'string' ||
    typeof raw.isValid !== 'boolean'
  ) {
    return null;
  }
  return {
    raw: safeTruncate(raw.raw, 64),
    digits: safeTruncate(raw.digits, 16),
    formatted: safeTruncate(raw.formatted, 20),
    prefix: safeTruncate(raw.prefix, 4),
    isValid: raw.isValid,
    entityType:
      typeof raw.entityType === 'string'
        ? (raw.entityType as CuitValidationResult['entityType'])
        : 'DESCONOCIDO',
    entityLabel: safeTruncate(raw.entityLabel, 120),
    reason: safeTruncate(raw.reason, 220),
  };
}

function validateDataFiscal(raw: unknown): DataFiscalAuditResult | null {
  if (!isPlainRecord(raw) || typeof raw.status !== 'string') {
    return null;
  }
  if (
    raw.status !== 'VERIFIED_OFFICIAL_QR' &&
    raw.status !== 'FORGED_STATIC_SEAL' &&
    raw.status !== 'MISSING_DATA_FISCAL'
  ) {
    return null;
  }
  return {
    status: raw.status,
    officialQrUrl:
      typeof raw.officialQrUrl === 'string'
        ? safeTruncate(raw.officialQrUrl, MAX_URL_LENGTH)
        : null,
    forgedEvidence:
      typeof raw.forgedEvidence === 'string'
        ? safeTruncate(raw.forgedEvidence, 256)
        : null,
    summary: safeTruncate(raw.summary, 256),
  };
}

function validateEcommerceContext(raw: unknown): EcommerceContext | null {
  if (!isPlainRecord(raw) || typeof raw.isEcommerce !== 'boolean') {
    return null;
  }
  return {
    isEcommerce: raw.isEcommerce,
    isWhitelistedOfficial: Boolean(raw.isWhitelistedOfficial),
    platform:
      typeof raw.platform === 'string'
        ? (raw.platform as EcommerceContext['platform'])
        : 'NO_ECOMMERCE',
    platformLabel: safeTruncate(raw.platformLabel, 80) || 'Sitio Web',
    isFreeSubdomain: Boolean(raw.isFreeSubdomain),
    hasArsPricing: Boolean(raw.hasArsPricing),
    hasCartControls: Boolean(raw.hasCartControls),
  };
}

/**
 * Strict runtime type guard and sanitizer for StoreAuditReport objects crossing IPC/storage boundaries.
 */
export function validateStoreAuditReport(raw: unknown): StoreAuditReport | null {
  if (!isPlainRecord(raw)) {
    return null;
  }
  if (
    typeof raw.url !== 'string' ||
    typeof raw.hostname !== 'string' ||
    typeof raw.trustScore !== 'number' ||
    typeof raw.riskLevel !== 'string' ||
    !VALID_RISK_LEVELS.has(raw.riskLevel as RiskLevel)
  ) {
    return null;
  }

  const ecommerce = validateEcommerceContext(raw.ecommerce);
  const dataFiscal = validateDataFiscal(raw.dataFiscal);
  if (!ecommerce || !dataFiscal) {
    return null;
  }

  const cuits: CuitValidationResult[] = [];
  if (Array.isArray(raw.cuits)) {
    for (const item of raw.cuits.slice(0, 25)) {
      const validItem = validateCuitItem(item);
      if (validItem) {
        cuits.push(validItem);
      }
    }
  }

  const findings: AuditFinding[] = [];
  if (Array.isArray(raw.findings)) {
    for (const item of raw.findings.slice(0, 25)) {
      const validFinding = validateFinding(item);
      if (validFinding) {
        findings.push(validFinding);
      }
    }
  }

  return {
    url: safeTruncate(raw.url, MAX_URL_LENGTH),
    hostname: safeTruncate(raw.hostname, 256),
    pageTitle: safeTruncate(raw.pageTitle, 256),
    isHttps: Boolean(raw.isHttps),
    timestamp:
      typeof raw.timestamp === 'number' && Number.isFinite(raw.timestamp)
        ? raw.timestamp
        : Date.now(),
    ecommerce,
    trustScore: Math.max(0, Math.min(100, Math.round(raw.trustScore))),
    riskLevel: raw.riskLevel as RiskLevel,
    pillHeadline: safeTruncate(raw.pillHeadline, 120) || 'Escudo Criollo',
    cuits,
    dataFiscal,
    findings,
  };
}

function validateToastPayload(raw: unknown): ToastNotificationPayload | null {
  if (!isPlainRecord(raw)) {
    return null;
  }
  const variant = raw.variant;
  if (
    variant !== 'SAFE' &&
    variant !== 'WARNING' &&
    variant !== 'DANGER' &&
    variant !== 'INFO'
  ) {
    return null;
  }
  if (typeof raw.title !== 'string' || typeof raw.detail !== 'string') {
    return null;
  }
  return {
    variant,
    title: safeTruncate(raw.title, 140),
    detail: safeTruncate(raw.detail, 256),
    copyText:
      typeof raw.copyText === 'string'
        ? safeTruncate(raw.copyText, MAX_URL_LENGTH)
        : undefined,
  };
}

/**
 * Strict runtime validator for all browser.runtime.onMessage payloads.
 */
export function validateExtensionMessage(raw: unknown): ExtensionMessage | null {
  if (!isPlainRecord(raw) || typeof raw.type !== 'string') {
    return null;
  }

  switch (raw.type) {
    case 'GET_TAB_AUDIT':
      return { type: 'GET_TAB_AUDIT' };

    case 'REPORT_STORE_AUDIT': {
      const report = validateStoreAuditReport(raw.payload);
      if (!report) {
        return null;
      }
      return {
        type: 'REPORT_STORE_AUDIT',
        payload: report,
      };
    }

    case 'CONTEXT_MENU_TOAST': {
      const toast = validateToastPayload(raw.payload);
      if (!toast) {
        return null;
      }
      return {
        type: 'CONTEXT_MENU_TOAST',
        payload: toast,
      };
    }

    default:
      return null;
  }
}

export async function getSettings(): Promise<ExtensionSettings> {
  try {
    const result = await browser.storage.local.get(SETTINGS_STORAGE_KEY);
    return validateSettings(result[SETTINGS_STORAGE_KEY]);
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(
  partial: Partial<ExtensionSettings>,
): Promise<ExtensionSettings> {
  const current = await getSettings();
  const merged = validateSettings({
    ...current,
    ...partial,
  });
  await browser.storage.local.set({
    [SETTINGS_STORAGE_KEY]: merged,
  });
  return merged;
}

export async function dismissDomainForSite(
  hostname: string,
): Promise<ExtensionSettings> {
  const cleanHost = safeTruncate(hostname.toLowerCase(), 128);
  const current = await getSettings();
  if (!cleanHost || current.dismissedDomains.includes(cleanHost)) {
    return current;
  }
  return saveSettings({
    dismissedDomains: [...current.dismissedDomains, cleanHost],
  });
}

export function subscribeToSettings(
  callback: (settings: ExtensionSettings) => void,
): () => void {
  const listener = (
    changes: Record<string, { newValue?: unknown }>,
    areaName: string,
  ) => {
    if (areaName === 'local' && SETTINGS_STORAGE_KEY in changes) {
      const updated = validateSettings(changes[SETTINGS_STORAGE_KEY]?.newValue);
      callback(updated);
    }
  };
  browser.storage.onChanged.addListener(listener);
  return () => {
    browser.storage.onChanged.removeListener(listener);
  };
}

/**
 * Persists bounded per-tab audit reports in storage.local (max 20 entries)
 * so the MV3 service worker remains 100% stateless across restarts.
 */
export async function saveTabAuditCache(
  tabId: number,
  report: StoreAuditReport,
): Promise<void> {
  try {
    const raw = await browser.storage.local.get(TAB_AUDITS_STORAGE_KEY);
    const existingMap = isPlainRecord(raw[TAB_AUDITS_STORAGE_KEY])
      ? { ...(raw[TAB_AUDITS_STORAGE_KEY] as Record<string, unknown>) }
      : {};

    existingMap[String(tabId)] = report;

    // Evict oldest entries if map exceeds 20 tabs
    const entries = Object.entries(existingMap);
    if (entries.length > 20) {
      entries.sort((a, b) => {
        const tsA = isPlainRecord(a[1]) && typeof a[1].timestamp === 'number' ? a[1].timestamp : 0;
        const tsB = isPlainRecord(b[1]) && typeof b[1].timestamp === 'number' ? b[1].timestamp : 0;
        return tsB - tsA;
      });
      const pruned = Object.fromEntries(entries.slice(0, 20));
      await browser.storage.local.set({ [TAB_AUDITS_STORAGE_KEY]: pruned });
      return;
    }

    await browser.storage.local.set({ [TAB_AUDITS_STORAGE_KEY]: existingMap });
  } catch {
    // Non-fatal storage error
  }
}

export async function getCachedTabAudit(
  tabId: number,
): Promise<StoreAuditReport | null> {
  try {
    const raw = await browser.storage.local.get(TAB_AUDITS_STORAGE_KEY);
    const map = raw[TAB_AUDITS_STORAGE_KEY];
    if (!isPlainRecord(map)) {
      return null;
    }
    return validateStoreAuditReport(map[String(tabId)]);
  } catch {
    return null;
  }
}


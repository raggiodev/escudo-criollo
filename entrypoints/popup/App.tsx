import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  ChevronRight,
  ClipboardPaste,
  Copy,
  ExternalLink,
  Link2,
  Lock,
  Megaphone,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Unlock,
} from 'lucide-react';
import { browser } from 'wxt/browser';
import { sanitizeUrl } from '../../src/modules/v01-clean-links/sanitizer';
import { validateCUIT } from '../../src/modules/v01-cuit-arca/validator';
import { isRaggiodevCreatorUrl } from '../../src/modules/v01-store-heuristics/detector';
import {
  AuditFinding,
  DEFAULT_SETTINGS,
  ExtensionSettings,
  RiskLevel,
  ScoreBreakdownItem,
  StoreAuditReport,
  parseSafeHttpUrl,
  safeTruncate,
} from '../../src/types';
import { copyTextSafely } from '../../src/utils/clipboard';
import { buildSafeXAlertTweet } from '../../src/utils/share';
import {
  getCachedTabAudit,
  getSettings,
  saveSettings,
  validateStoreAuditReport,
} from '../../src/utils/storage';

const BCRA_DEUDORES_URL =
  'https://www.bcra.gob.ar/BCRAyVos/Situacion_Crediticia.asp';
const RAGGIODEV_PORTFOLIO_URL = 'https://raggiodev.com';

type TabId = 'scanner' | 'manual' | 'settings';

function sanitizeCuitInputCharacters(rawValue: string): string {
  return rawValue.replace(/[^\d-]/g, '').slice(0, 13);
}

function getRiskPalette(risk: RiskLevel): {
  label: string;
  color: string;
  bg: string;
  border: string;
} {
  switch (risk) {
    case 'SAFE':
      return {
        label: 'TIENDA VERIFICADA',
        color: '#34D399',
        bg: 'rgba(6, 78, 59, 0.65)',
        border: '#10B981',
      };
    case 'WARNING':
      return {
        label: 'PRECAUCIÓN',
        color: '#FBBF24',
        bg: 'rgba(69, 26, 3, 0.65)',
        border: '#F59E0B',
      };
    case 'DANGER':
      return {
        label: 'ALERTA DE ESTAFA',
        color: '#F87171',
        bg: 'rgba(69, 10, 10, 0.75)',
        border: '#EF4444',
      };
    case 'NEUTRAL':
    default:
      return {
        label: 'SITIO GENERAL',
        color: '#C4B5FD',
        bg: 'rgba(31, 25, 61, 0.85)',
        border: '#4F46E5',
      };
  }
}

function getFindingIcon(severity: AuditFinding['severity']): string {
  switch (severity) {
    case 'SAFE':
      return '🟢';
    case 'WARNING':
      return '🟡';
    case 'DANGER':
      return '🔴';
  }
}

function formatBreakdownDelta(item: ScoreBreakdownItem): {
  text: string;
  color: string;
} {
  const sign = item.delta > 0 ? '+' : '';
  const text = `${sign}${item.delta}`;
  switch (item.type) {
    case 'base':
      return { text, color: '#C4B5FD' };
    case 'positive':
      return { text, color: '#34D399' };
    case 'negative':
      return { text, color: '#F87171' };
    case 'neutral':
    default:
      return { text, color: '#94A3B8' };
  }
}

function buildFallbackUrlReport(rawTabUrl: string): StoreAuditReport | null {
  const parsed = parseSafeHttpUrl(rawTabUrl);
  if (!parsed) {
    return null;
  }
  const hostname = safeTruncate(parsed.hostname.toLowerCase(), 256);

  if (isRaggiodevCreatorUrl(parsed.href)) {
    return {
      url: safeTruncate(parsed.href, 2048),
      hostname,
      pageTitle: hostname,
      isHttps: true,
      timestamp: Date.now(),
      ecommerce: {
        isEcommerce: true,
        isWhitelistedOfficial: true,
        platform: 'RAGGIODEV_HQ',
        platformLabel: '🟢 Easter Egg encontrado',
        isFreeSubdomain: false,
        hasArsPricing: false,
        hasCartControls: false,
      },
      trustScore: 100,
      scoreBreakdown: [
        {
          label: '🎮 Easter Egg encontrado (Guiño del Creador)',
          delta: 90,
          type: 'base',
        },
        {
          label: '✨ Sello Oficial Fernando Andres Raggio (Raggiodev)',
          delta: 10,
          type: 'positive',
        },
      ],
      riskLevel: 'SAFE',
      pillHeadline: '🎮 Easter Egg encontrado · Raggiodev',
      cuits: [],
      dataFiscal: {
        status: 'MISSING_DATA_FISCAL',
        officialQrUrl: null,
        forgedEvidence: null,
        summary:
          'Perfil oficial del creador de Escudo Criollo: Fernando Andres Raggio (Raggiodev).',
      },
      findings: [
        {
          id: 'raggiodev-creator-easter-egg',
          severity: 'SAFE',
          title: '🟢 ¡Easter Egg encontrado! · Perfil Oficial del Creador',
          detail:
            '¡Encontraste un secreto oculto de Escudo Criollo! Estás visitando una web o red oficial de su creador: Fernando Andres Raggio (Raggiodev). Nota: este puntaje es un guiño humorístico y de color para la comunidad 😉.',
          evidence:
            'Easter Egg Desbloqueado · Desarrollado por Fernando Andres Raggio (Raggiodev)',
        },
      ],
    };
  }

  const isHttps = parsed.protocol === 'https:';
  const scoreBreakdown: ScoreBreakdownItem[] = [
    { label: 'Base vista previa URL', delta: 60, type: 'base' },
    isHttps
      ? { label: 'Conexión cifrada HTTPS', delta: 10, type: 'positive' }
      : { label: 'Conexión sin cifrado HTTPS', delta: -20, type: 'negative' },
  ];
  return {
    url: safeTruncate(parsed.href, 2048),
    hostname,
    pageTitle: hostname,
    isHttps,
    timestamp: Date.now(),
    ecommerce: {
      isEcommerce: false,
      isWhitelistedOfficial: hostname.endsWith('.gob.ar'),
      platform: hostname.endsWith('.gob.ar') ? 'SITIO_OFICIAL' : 'NO_ECOMMERCE',
      platformLabel: hostname.endsWith('.gob.ar')
        ? 'Portal Oficial (.gob.ar)'
        : 'Vista Previa URL',
      isFreeSubdomain:
        hostname.endsWith('.mitiendanube.com') ||
        hostname.endsWith('.myshopify.com'),
      hasArsPricing: false,
      hasCartControls: false,
    },
    trustScore: isHttps ? 70 : 40,
    scoreBreakdown,
    riskLevel: isHttps ? 'NEUTRAL' : 'WARNING',
    pillHeadline: isHttps
      ? 'Recargá la pestaña para auditar el DOM'
      : 'Precaución · Sitio sin HTTPS',
    cuits: [],
    dataFiscal: {
      status: 'MISSING_DATA_FISCAL',
      officialQrUrl: null,
      forgedEvidence: null,
      summary:
        'Recargá la página actual (F5) para que Escudo Criollo inspeccione el DOM completo.',
    },
    findings: [
      {
        id: 'reload-tab-for-full-dom-scan',
        severity: isHttps ? 'SAFE' : 'WARNING',
        title: isHttps
          ? 'Conexión HTTPS activa (Recargá para escaneo DOM)'
          : 'Conexión sin cifrado HTTPS',
        detail: isHttps
          ? 'Esta pestaña estaba abierta antes de activar la extensión. Presioná F5 en la página para auditar CUIT, Data Fiscal y redes.'
          : 'El sitio utiliza HTTP plano sin cifrado. No ingreses datos sensibles.',
      },
    ],
  };
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabId>('scanner');
  const [report, setReport] = useState<StoreAuditReport | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(true);
  const [scanError, setScanError] = useState<string | null>(null);

  // Manual Auditor state
  const [manualCuit, setManualCuit] = useState<string>('');
  const [manualUrl, setManualUrl] = useState<string>('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Settings state
  const [settings, setSettings] = useState<ExtensionSettings>(DEFAULT_SETTINGS);
  const [liveStatus, setLiveStatus] = useState<string>('');

  const tabRefs = useRef<Record<TabId, HTMLButtonElement | null>>({
    scanner: null,
    manual: null,
    settings: null,
  });

  const triggerCopyFeedback = async (
    key: string,
    textToCopy: string,
    announceLabel: string,
  ) => {
    const ok = await copyTextSafely(textToCopy);
    if (ok) {
      setCopiedKey(key);
      setLiveStatus(announceLabel);
      window.setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 2200);
    }
  };

  const scanCurrentBrowserTab = useCallback(async () => {
    setIsScanning(true);
    setScanError(null);

    try {
      const tabs = await browser.tabs.query({
        active: true,
        currentWindow: true,
      });
      const current = tabs[0];

      if (!current || typeof current.id !== 'number') {
        setReport(null);
        setScanError(
          'No se detectó una pestaña activa para auditar. Usá el Auditor Manual.',
        );
        setIsScanning(false);
        return;
      }

      // 1. Request live DOM forensic report directly from content script
      try {
        const rawResponse: unknown = await browser.tabs.sendMessage(
          current.id,
          {
            type: 'GET_TAB_AUDIT',
          },
        );
        if (
          rawResponse &&
          typeof rawResponse === 'object' &&
          'report' in rawResponse
        ) {
          const validated = validateStoreAuditReport(
            (rawResponse as { report?: unknown }).report,
          );
          if (validated) {
            setReport(validated);
            setIsScanning(false);
            return;
          }
        }
      } catch {
        // Content script not injected on internal chrome:// pages or pre-install tabs
      }

      // 2. Fallback to background storage cache for this tabId
      const cached = await getCachedTabAudit(current.id);
      if (cached) {
        setReport(cached);
        setIsScanning(false);
        return;
      }

      // 3. Fallback URL-level check if activeTab granted current.url
      if (typeof current.url === 'string' && current.url.length > 0) {
        const fallback = buildFallbackUrlReport(current.url);
        if (fallback) {
          setReport(fallback);
          setIsScanning(false);
          return;
        }
      }

      setReport(null);
      setScanError(
        'Esta pestaña es una página interna del navegador o de Chrome Web Store donde las extensiones no tienen permiso de lectura. Probá en cualquier tienda online o usá la pestaña Auditor Manual.',
      );
    } catch {
      setReport(null);
      setScanError(
        'No se pudo comunicar con la pestaña actual. Recargá la página o usá el Auditor Manual.',
      );
    } finally {
      setIsScanning(false);
    }
  }, []);

  useEffect(() => {
    void (async () => {
      const loaded = await getSettings();
      setSettings(loaded);
      await scanCurrentBrowserTab();
    })();
  }, [scanCurrentBrowserTab]);

  const handleUpdateSetting = async (partial: Partial<ExtensionSettings>) => {
    const next = await saveSettings(partial);
    setSettings(next);
    setLiveStatus('Preferencias actualizadas.');
  };

  const manualCuitResult = useMemo(() => {
    const trimmed = manualCuit.trim();
    if (!trimmed) {
      return null;
    }
    return validateCUIT(trimmed);
  }, [manualCuit]);

  const manualSanitizeResult = useMemo(() => {
    const trimmed = manualUrl.trim();
    if (!trimmed) {
      return null;
    }
    return sanitizeUrl(trimmed);
  }, [manualUrl]);

  const handlePasteCuit = async () => {
    try {
      const clip = await navigator.clipboard.readText();
      if (typeof clip === 'string') {
        const filtered = sanitizeCuitInputCharacters(clip.trim());
        setManualCuit(filtered);
        if (!filtered && clip.trim().length > 0) {
          setLiveStatus(
            'El texto del portapapeles no contenía números de CUIT válidos.',
          );
        }
      }
    } catch {
      setLiveStatus('Pegá manualmente con Ctrl+V.');
    }
  };

  const handlePasteUrl = async () => {
    try {
      const clip = await navigator.clipboard.readText();
      if (typeof clip === 'string') {
        setManualUrl(clip.slice(0, 2048).trim());
      }
    } catch {
      setLiveStatus('Pegá manualmente con Ctrl+V.');
    }
  };

  const tabOrder: TabId[] = ['scanner', 'manual', 'settings'];
  const handleTabKeyDown = (
    event: React.KeyboardEvent<HTMLButtonElement>,
    currentId: TabId,
  ) => {
    const idx = tabOrder.indexOf(currentId);
    if (event.key === 'ArrowRight') {
      event.preventDefault();
      const nextTab = tabOrder[(idx + 1) % tabOrder.length] ?? 'scanner';
      setActiveTab(nextTab);
      tabRefs.current[nextTab]?.focus();
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault();
      const prevTab =
        tabOrder[(idx - 1 + tabOrder.length) % tabOrder.length] ?? 'scanner';
      setActiveTab(prevTab);
      tabRefs.current[prevTab]?.focus();
    }
  };

  const riskPalette = useMemo(
    () => getRiskPalette(report?.riskLevel ?? 'NEUTRAL'),
    [report?.riskLevel],
  );

  const popupXAlertUrl = useMemo(
    () =>
      report && report.riskLevel === 'DANGER'
        ? buildSafeXAlertTweet(report).intentUrl
        : null,
    [report],
  );

  const gaugeCircumference = 188.5;
  const gaugeOffset = report
    ? gaugeCircumference - (report.trustScore / 100) * gaugeCircumference
    : gaugeCircumference;

  return (
    <div className="flex min-h-[520px] w-[380px] flex-col bg-raggio-canvas text-slate-100">
      {/* Screen-Reader Polite Announcements */}
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {liveStatus}
      </div>

      {/* Tactical Raggiodev Header */}
      <header
        className="raggio-brand-bg border-b px-4 py-3.5"
        style={{ borderColor: 'rgba(251, 191, 36, 0.35)' }}
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <div
              className="flex h-9 w-9 items-center justify-center rounded-xl border shadow-raggio-gold"
              style={{
                backgroundColor: 'rgba(13, 11, 24, 0.8)',
                borderColor: 'rgba(251, 191, 36, 0.6)',
              }}
            >
              <Shield className="h-5 w-5 text-raggio-gold" aria-hidden="true" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-base font-extrabold tracking-tight text-white m-0 leading-tight">
                  Escudo Criollo
                </h1>
                <span
                  className="rounded-md px-1.5 py-0.5 font-mono text-2xs font-bold"
                  style={{
                    backgroundColor: 'rgba(13, 11, 24, 0.78)',
                    color: '#FBBF24',
                    border: '1px solid rgba(251, 191, 36, 0.4)',
                  }}
                >
                  v0.1.4
                </span>
              </div>
              <p className="text-2xs text-indigo-100/90 m-0 mt-0.5">
                Defensa Anti-Estafas &amp; Privacidad ·{' '}
                <a
                  href={RAGGIODEV_PORTFOLIO_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-semibold text-raggio-goldLight hover:underline"
                >
                  Raggiodev
                </a>
              </p>
            </div>
          </div>

          {activeTab === 'scanner' && (
            <button
              type="button"
              onClick={() => void scanCurrentBrowserTab()}
              aria-label="Volver a escanear pestaña actual"
              className="flex min-h-[32px] min-w-[32px] items-center justify-center rounded-lg border border-white/20 bg-black/25 text-white hover:bg-black/40 transition-colors"
            >
              <RefreshCw
                className={`h-4 w-4 ${isScanning ? 'animate-spin' : ''}`}
                aria-hidden="true"
              />
            </button>
          )}
        </div>
      </header>

      {/* 3-Tab Tactical Navigation */}
      <nav
        aria-label="Secciones principales"
        className="border-b border-raggio-border bg-raggio-card px-2 pt-1.5"
      >
        <div role="tablist" className="grid grid-cols-3 gap-1">
          <button
            ref={(el) => {
              tabRefs.current.scanner = el;
            }}
            id="tab-scanner"
            role="tab"
            type="button"
            aria-selected={activeTab === 'scanner'}
            aria-controls="panel-scanner"
            tabIndex={activeTab === 'scanner' ? 0 : -1}
            onClick={() => setActiveTab('scanner')}
            onKeyDown={(e) => handleTabKeyDown(e, 'scanner')}
            className={`flex items-center justify-center gap-1.5 rounded-t-lg border-b-2 px-2 py-2 text-xs font-semibold transition-colors min-h-[36px] ${
              activeTab === 'scanner'
                ? 'border-raggio-gold bg-raggio-canvas text-raggio-gold'
                : 'border-transparent text-slate-400 hover:bg-raggio-hover hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>Escáner</span>
          </button>

          <button
            ref={(el) => {
              tabRefs.current.manual = el;
            }}
            id="tab-manual"
            role="tab"
            type="button"
            aria-selected={activeTab === 'manual'}
            aria-controls="panel-manual"
            tabIndex={activeTab === 'manual' ? 0 : -1}
            onClick={() => setActiveTab('manual')}
            onKeyDown={(e) => handleTabKeyDown(e, 'manual')}
            className={`flex items-center justify-center gap-1.5 rounded-t-lg border-b-2 px-2 py-2 text-xs font-semibold transition-colors min-h-[36px] ${
              activeTab === 'manual'
                ? 'border-raggio-gold bg-raggio-canvas text-raggio-gold'
                : 'border-transparent text-slate-400 hover:bg-raggio-hover hover:text-slate-200'
            }`}
          >
            <Search className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>Auditor Manual</span>
          </button>

          <button
            ref={(el) => {
              tabRefs.current.settings = el;
            }}
            id="tab-settings"
            role="tab"
            type="button"
            aria-selected={activeTab === 'settings'}
            aria-controls="panel-settings"
            tabIndex={activeTab === 'settings' ? 0 : -1}
            onClick={() => setActiveTab('settings')}
            onKeyDown={(e) => handleTabKeyDown(e, 'settings')}
            className={`flex items-center justify-center gap-1.5 rounded-t-lg border-b-2 px-2 py-2 text-xs font-semibold transition-colors min-h-[36px] ${
              activeTab === 'settings'
                ? 'border-raggio-gold bg-raggio-canvas text-raggio-gold'
                : 'border-transparent text-slate-400 hover:bg-raggio-hover hover:text-slate-200'
            }`}
          >
            <Settings className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span>Ajustes</span>
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <main className="raggio-scrollbar flex-1 overflow-y-auto p-3.5">
        {/* ==================== TAB 1: ESCÁNER ACTUAL ==================== */}
        {activeTab === 'scanner' && (
          <div
            id="panel-scanner"
            role="tabpanel"
            aria-labelledby="tab-scanner"
            className="space-y-3"
          >
            {isScanning ? (
              <div className="flex flex-col items-center justify-center rounded-2xl border border-raggio-border bg-raggio-card p-8 text-center">
                <RefreshCw
                  className="h-7 w-7 animate-spin text-raggio-gold"
                  aria-hidden="true"
                />
                <p className="mt-3 text-xs font-semibold text-slate-200">
                  Auditando seguridad del sitio actual…
                </p>
                <p className="mt-1 text-2xs text-slate-400">
                  Verificando Módulo 11 de CUIT, sello F.960 Data Fiscal y heurísticas.
                </p>
              </div>
            ) : scanError || !report ? (
              <div className="rounded-2xl border border-raggio-border bg-raggio-card p-4 space-y-3">
                <div className="flex items-center gap-2 text-raggio-gold">
                  <ShieldAlert className="h-5 w-5 shrink-0" aria-hidden="true" />
                  <h2 className="text-sm font-bold m-0">
                    Pestaña protegida por el navegador
                  </h2>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed m-0">
                  {scanError}
                </p>
                <button
                  type="button"
                  onClick={() => setActiveTab('manual')}
                  className="w-full rounded-xl border border-raggio-gold/40 bg-raggio-hover px-3 py-2 text-xs font-semibold text-raggio-gold hover:bg-raggio-border/60 transition-colors min-h-[36px]"
                >
                  Ir al Auditor Manual de CUIT y Links →
                </button>
              </div>
            ) : (
              <>
                {/* Trust Score Gauge + Domain Hero Card */}
                <section
                  aria-label="Resumen de confianza"
                  className="rounded-2xl border border-raggio-border bg-raggio-card p-3.5 space-y-3"
                >
                  <div className="flex items-center gap-3.5">
                    {/* Circular SVG Trust Gauge */}
                    <div className="relative flex h-[74px] w-[74px] shrink-0 items-center justify-center">
                      <svg
                        className="h-[74px] w-[74px] -rotate-90"
                        viewBox="0 0 74 74"
                        aria-hidden="true"
                      >
                        <circle
                          cx="37"
                          cy="37"
                          r="30"
                          fill="none"
                          stroke="#2B2354"
                          strokeWidth="6"
                        />
                        <circle
                          cx="37"
                          cy="37"
                          r="30"
                          fill="none"
                          stroke={riskPalette.border}
                          strokeWidth="6"
                          strokeLinecap="round"
                          strokeDasharray={gaugeCircumference}
                          strokeDashoffset={gaugeOffset}
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span
                          className="font-mono text-lg font-extrabold leading-none"
                          style={{ color: riskPalette.color }}
                        >
                          {report.trustScore}
                        </span>
                        <span className="font-mono text-2xs text-slate-400">
                          /100
                        </span>
                      </div>
                    </div>

                    {/* Domain & Verdict Details */}
                    <div className="min-w-0 flex-1 space-y-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className="inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-2xs font-bold"
                          style={{
                            color: riskPalette.color,
                            backgroundColor: riskPalette.bg,
                            borderColor: riskPalette.border,
                          }}
                        >
                          {riskPalette.label}
                        </span>
                        <span
                          className="inline-flex items-center rounded-md border px-1.5 py-0.5 text-2xs font-semibold"
                          style={
                            report.ecommerce.platform === 'RAGGIODEV_HQ'
                              ? {
                                  color: '#34D399',
                                  backgroundColor: 'rgba(6, 78, 59, 0.75)',
                                  borderColor: '#10B981',
                                }
                              : {
                                  color: '#FBBF24',
                                  backgroundColor: '#1F193D',
                                  borderColor: '#2B2354',
                                }
                          }
                        >
                          {report.ecommerce.platformLabel}
                        </span>
                      </div>

                      <div className="flex items-center gap-1.5 font-mono text-xs font-semibold text-white truncate">
                        {report.isHttps ? (
                          <Lock
                            className="h-3.5 w-3.5 shrink-0 text-semaphore-safeText"
                            aria-hidden="true"
                          />
                        ) : (
                          <Unlock
                            className="h-3.5 w-3.5 shrink-0 text-semaphore-warnText"
                            aria-hidden="true"
                          />
                        )}
                        <span className="truncate">{report.hostname}</span>
                      </div>

                      <p className="text-2xs text-slate-300 m-0 leading-snug">
                        {report.pillHeadline}
                      </p>
                    </div>
                  </div>

                  {/* Collapsible Transparent Score Breakdown */}
                  {report.scoreBreakdown.length > 0 && (
                    <details className="group rounded-xl border border-raggio-border bg-raggio-canvas px-3 py-2">
                      <summary className="flex cursor-pointer list-none items-center justify-between gap-2 text-2xs font-semibold text-raggio-goldLight select-none min-h-[24px]">
                        <span>📊 ¿De dónde sale este puntaje? (Desglose)</span>
                        <ChevronRight
                          className="h-3.5 w-3.5 shrink-0 text-raggio-gold transition-transform group-open:rotate-90"
                          aria-hidden="true"
                        />
                      </summary>
                      <ul
                        role="list"
                        className="mt-2 space-y-1.5 border-t border-raggio-border pt-2 m-0 p-0 list-none"
                      >
                        {report.scoreBreakdown.map((item, idx) => {
                          const formatted = formatBreakdownDelta(item);
                          return (
                            <li
                              key={`${item.label}-${idx}`}
                              className="flex items-center justify-between gap-2 text-2xs"
                            >
                              <span className="text-slate-300 leading-snug">
                                {item.label}
                              </span>
                              <span
                                className="shrink-0 font-mono font-bold"
                                style={{ color: formatted.color }}
                              >
                                {formatted.text}
                              </span>
                            </li>
                          );
                        })}
                        <li className="flex items-center justify-between gap-2 border-t border-raggio-border/70 pt-1.5 text-2xs font-bold">
                          <span className="text-slate-100">
                            Puntaje de Confianza Final
                          </span>
                          <span
                            className="font-mono"
                            style={{ color: riskPalette.color }}
                          >
                            {report.trustScore}/100
                          </span>
                        </li>
                      </ul>
                    </details>
                  )}

                  {/* Quick Actions Row */}
                  <div className="flex items-center gap-2 border-t border-raggio-border pt-2.5">
                    <button
                      type="button"
                      onClick={() => {
                        const cleaned = sanitizeUrl(report.url);
                        const urlToCopy = cleaned.isValidHttpUrl
                          ? cleaned.cleanUrl
                          : report.url;
                        void triggerCopyFeedback(
                          'tab-clean-url',
                          urlToCopy,
                          'Enlace limpio copiado al portapapeles.',
                        );
                      }}
                      className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-2xs font-semibold transition-colors min-h-[30px]"
                      style={{
                        backgroundColor: '#0D0B18',
                        borderColor: 'rgba(251, 191, 36, 0.35)',
                        color: '#FBBF24',
                      }}
                    >
                      {copiedKey === 'tab-clean-url' ? (
                        <>
                          <Check
                            className="h-3.5 w-3.5 text-semaphore-safeText"
                            aria-hidden="true"
                          />
                          <span>¡Link Limpio Copiado!</span>
                        </>
                      ) : (
                        <>
                          <Sparkles className="h-3.5 w-3.5" aria-hidden="true" />
                          <span>🧹 Copiar Link Limpio</span>
                        </>
                      )}
                    </button>

                    {report.riskLevel === 'DANGER' && popupXAlertUrl && (
                      <a
                        href={popupXAlertUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex shrink-0 items-center gap-1 rounded-lg border px-2.5 py-1.5 text-2xs font-semibold no-underline min-h-[30px]"
                        style={{
                          backgroundColor: 'rgba(69, 10, 10, 0.75)',
                          borderColor: '#EF4444',
                          color: '#F87171',
                        }}
                      >
                        <Megaphone className="h-3.5 w-3.5" aria-hidden="true" />
                        <span>Alertar en X</span>
                      </a>
                    )}
                  </div>
                </section>

                {/* CUIT & Data Fiscal ARCA Card (shown on Argentine/local sites) */}
                {report.ecommerce.platform !== 'ECOMMERCE_INTERNACIONAL' &&
                  report.ecommerce.platform !== 'RAGGIODEV_HQ' && (
                  <section
                    aria-label="Estado fiscal CUIT y ARCA"
                    className="rounded-2xl border border-raggio-border bg-raggio-card p-3 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <h2 className="text-2xs font-bold uppercase tracking-wider text-slate-400 m-0">
                        Identidad Fiscal (CUIT &amp; ARCA)
                      </h2>
                      <a
                        href={BCRA_DEUDORES_URL}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-2xs font-semibold text-raggio-gold hover:underline min-h-[24px]"
                      >
                        <span>Central de Deudores BCRA</span>
                        <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      </a>
                    </div>

                    {report.cuits.length > 0 ? (
                      <div className="space-y-1.5">
                        {report.cuits.slice(0, 3).map((cuit) => (
                          <div
                            key={cuit.digits}
                            className="flex items-center justify-between gap-2 rounded-xl border border-raggio-border bg-raggio-canvas px-2.5 py-2"
                          >
                            <div className="min-w-0">
                              <div className="flex items-center gap-1.5">
                                <span
                                  className="font-mono text-xs font-bold"
                                  style={{
                                    color: cuit.isValid ? '#34D399' : '#F87171',
                                  }}
                                >
                                  {cuit.formatted}
                                </span>
                                <span
                                  className="rounded border px-1.5 py-0.5 font-mono text-2xs font-bold"
                                  style={
                                    cuit.isValid
                                      ? {
                                          color: '#34D399',
                                          backgroundColor:
                                            'rgba(6, 78, 59, 0.65)',
                                          borderColor: '#10B981',
                                        }
                                      : {
                                          color: '#F87171',
                                          backgroundColor:
                                            'rgba(69, 10, 10, 0.75)',
                                          borderColor: '#EF4444',
                                        }
                                  }
                                >
                                  {cuit.isValid ? 'VÁLIDO' : 'TRUCHO'}
                                </span>
                              </div>
                              <p className="text-2xs text-slate-400 m-0 mt-0.5 truncate">
                                {cuit.entityLabel}
                              </p>
                            </div>

                            <button
                              type="button"
                              onClick={() =>
                                void triggerCopyFeedback(
                                  `cuit-${cuit.digits}`,
                                  cuit.formatted,
                                  `CUIT ${cuit.formatted} copiado.`,
                                )
                              }
                              className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-raggio-border bg-raggio-hover px-2 py-1 text-2xs font-semibold text-slate-200 hover:border-raggio-gold hover:text-raggio-gold min-h-[28px]"
                            >
                              {copiedKey === `cuit-${cuit.digits}` ? (
                                <>
                                  <Check
                                    className="h-3 w-3 text-semaphore-safeText"
                                    aria-hidden="true"
                                  />
                                  <span>Copiado</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="h-3 w-3" aria-hidden="true" />
                                  <span>Copiar</span>
                                </>
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="rounded-xl border border-raggio-border bg-raggio-canvas px-3 py-2 font-mono text-2xs text-slate-400">
                        No se detectó ningún CUIT en la vista actual.
                      </div>
                    )}

                    <div className="flex items-center justify-between pt-1 text-xs">
                      <span className="text-slate-400 text-2xs">
                        Data Fiscal F.960:
                      </span>
                      {report.dataFiscal.status === 'VERIFIED_OFFICIAL_QR' &&
                      report.dataFiscal.officialQrUrl ? (
                        <a
                          href={report.dataFiscal.officialQrUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-2xs font-bold text-semaphore-safeText hover:underline min-h-[24px]"
                        >
                          <span>🟢 QR Oficial Verificado</span>
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </a>
                      ) : report.dataFiscal.status === 'FORGED_STATIC_SEAL' ? (
                        <span className="font-mono text-2xs font-bold text-semaphore-dangerText">
                          🔴 Sello Estático / Falsificado
                        </span>
                      ) : (
                        <span className="font-mono text-2xs text-slate-400">
                          No detectado en vista actual
                        </span>
                      )}
                    </div>
                  </section>
                )}

                {/* Detailed Findings */}
                <section aria-label="Hallazgos detallados">
                  <h2 className="mb-2 text-2xs font-bold uppercase tracking-wider text-slate-400 m-0">
                    Hallazgos Forenses ({report.findings.length})
                  </h2>
                  <ul role="list" className="space-y-2 m-0 p-0 list-none">
                    {report.findings.map((item) => (
                      <li
                        key={item.id}
                        className="rounded-xl border p-2.5"
                        style={{
                          backgroundColor:
                            item.severity === 'DANGER'
                              ? 'rgba(69, 10, 10, 0.42)'
                              : item.severity === 'WARNING'
                                ? 'rgba(69, 26, 3, 0.3)'
                                : 'rgba(6, 78, 59, 0.25)',
                          borderColor:
                            item.severity === 'DANGER'
                              ? 'rgba(239, 68, 68, 0.55)'
                              : item.severity === 'WARNING'
                                ? 'rgba(245, 158, 11, 0.45)'
                                : 'rgba(16, 185, 129, 0.4)',
                        }}
                      >
                        <div className="flex items-start gap-1.5 text-xs font-semibold text-white">
                          <span aria-hidden="true" className="shrink-0">
                            {getFindingIcon(item.severity)}
                          </span>
                          <span>{item.title}</span>
                        </div>
                        <p className="mt-1 text-2xs text-slate-300 leading-relaxed m-0">
                          {item.detail}
                        </p>
                        {item.evidence && (
                          <div className="mt-1.5 rounded-lg bg-black/35 px-2 py-1 font-mono text-2xs text-raggio-goldLight break-all border border-white/5">
                            {item.evidence}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              </>
            )}
          </div>
        )}

        {/* ==================== TAB 2: AUDITOR MANUAL ==================== */}
        {activeTab === 'manual' && (
          <div
            id="panel-manual"
            role="tabpanel"
            aria-labelledby="tab-manual"
            className="space-y-4"
          >
            {/* Card 1: Mathematical CUIT/CUIL Validator */}
            <section
              aria-labelledby="heading-cuit-auditor"
              className="rounded-2xl border border-raggio-border bg-raggio-card p-3.5 space-y-2.5"
            >
              <div className="flex items-center justify-between gap-2">
                <h2
                  id="heading-cuit-auditor"
                  className="text-xs font-bold text-white m-0 flex items-center gap-1.5"
                >
                  <ShieldCheck
                    className="h-4 w-4 text-raggio-gold"
                    aria-hidden="true"
                  />
                  <span>Validador Matemático de CUIT / CUIL</span>
                </h2>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => void handlePasteCuit()}
                    className="inline-flex items-center gap-1 rounded-md border border-raggio-border bg-raggio-hover px-2 py-1 text-2xs font-medium text-slate-200 hover:border-raggio-gold hover:text-raggio-gold min-h-[26px]"
                  >
                    <ClipboardPaste className="h-3 w-3" aria-hidden="true" />
                    <span>Pegar</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setManualCuit('')}
                    aria-label="Limpiar campo de CUIT"
                    className="inline-flex items-center gap-1 rounded-md border border-raggio-border bg-raggio-hover px-2 py-1 text-2xs font-medium text-slate-300 hover:text-white min-h-[26px]"
                  >
                    <Trash2 className="h-3 w-3" aria-hidden="true" />
                    <span>Limpiar</span>
                  </button>
                </div>
              </div>

              <div>
                <label
                  htmlFor="cuit-manual-input"
                  className="block text-2xs text-slate-400 mb-1"
                >
                  Ingresá los 11 dígitos numéricos del vendedor (solo números y guiones):
                </label>
                <input
                  id="cuit-manual-input"
                  type="text"
                  inputMode="numeric"
                  autoComplete="off"
                  maxLength={13}
                  value={manualCuit}
                  onChange={(e) =>
                    setManualCuit(sanitizeCuitInputCharacters(e.target.value))
                  }
                  placeholder="Ej: 30-70308853-4"
                  className="w-full rounded-xl border border-raggio-border bg-raggio-canvas px-3 py-2 font-mono text-sm text-white placeholder-slate-500 focus:border-raggio-gold"
                />
              </div>

              {manualCuitResult && (
                <div
                  className="rounded-xl border p-3 space-y-2"
                  style={
                    manualCuitResult.isValid
                      ? {
                          backgroundColor: 'rgba(6, 78, 59, 0.35)',
                          borderColor: '#10B981',
                        }
                      : {
                          backgroundColor: 'rgba(69, 10, 10, 0.45)',
                          borderColor: '#EF4444',
                        }
                  }
                >
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className="font-mono text-sm font-extrabold"
                      style={{
                        color: manualCuitResult.isValid ? '#34D399' : '#F87171',
                      }}
                    >
                      {manualCuitResult.isValid
                        ? `🟢 ${manualCuitResult.formatted}`
                        : `🔴 ${manualCuitResult.formatted || 'Formato inválido'}`}
                    </span>
                    <span className="font-mono text-2xs font-bold uppercase text-slate-200">
                      {manualCuitResult.isValid ? 'MÓDULO 11 OK' : 'INVÁLIDO'}
                    </span>
                  </div>

                  <div className="text-2xs text-slate-200 font-medium">
                    Tipo:{' '}
                    <span className="text-raggio-goldLight">
                      {manualCuitResult.entityLabel}
                    </span>
                  </div>
                  <p className="text-2xs text-slate-300 m-0 leading-relaxed">
                    {manualCuitResult.errorReason ?? manualCuitResult.reason}
                  </p>

                  <div className="flex items-center gap-2 pt-1">
                    {manualCuitResult.isValid && (
                      <button
                        type="button"
                        onClick={() =>
                          void triggerCopyFeedback(
                            'manual-cuit-copy',
                            manualCuitResult.formatted,
                            `CUIT ${manualCuitResult.formatted} copiado.`,
                          )
                        }
                        className="inline-flex items-center gap-1 rounded-lg border border-raggio-border bg-raggio-canvas px-2.5 py-1.5 text-2xs font-semibold text-slate-100 hover:border-raggio-gold min-h-[28px]"
                      >
                        {copiedKey === 'manual-cuit-copy' ? (
                          <>
                            <Check
                              className="h-3 w-3 text-semaphore-safeText"
                              aria-hidden="true"
                            />
                            <span>Copiado</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" aria-hidden="true" />
                            <span>Copiar CUIT</span>
                          </>
                        )}
                      </button>
                    )}

                    <a
                      href={BCRA_DEUDORES_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex-1 inline-flex items-center justify-center gap-1 rounded-lg border border-raggio-gold/40 bg-raggio-canvas px-2.5 py-1.5 text-2xs font-semibold text-raggio-gold hover:bg-raggio-hover no-underline min-h-[28px]"
                    >
                      <span>Consultar Central BCRA</span>
                      <ExternalLink className="h-3 w-3" aria-hidden="true" />
                    </a>
                  </div>
                </div>
              )}
            </section>

            {/* Card 2: Anti-Tracking Link Sanitizer */}
            <section
              aria-labelledby="heading-link-sanitizer"
              className="rounded-2xl border border-raggio-border bg-raggio-card p-3.5 space-y-2.5"
            >
              <div className="flex items-center justify-between gap-2">
                <h2
                  id="heading-link-sanitizer"
                  className="text-xs font-bold text-white m-0 flex items-center gap-1.5"
                >
                  <Link2
                    className="h-4 w-4 text-raggio-gold"
                    aria-hidden="true"
                  />
                  <span>Sanitizador de Links Anti-Rastreo</span>
                </h2>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => void handlePasteUrl()}
                    className="inline-flex items-center gap-1 rounded-md border border-raggio-border bg-raggio-hover px-2 py-1 text-2xs font-medium text-slate-200 hover:border-raggio-gold hover:text-raggio-gold min-h-[26px]"
                  >
                    <ClipboardPaste className="h-3 w-3" aria-hidden="true" />
                    <span>Pegar</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setManualUrl('')}
                    aria-label="Limpiar campo de enlace"
                    className="inline-flex items-center gap-1 rounded-md border border-raggio-border bg-raggio-hover px-2 py-1 text-2xs font-medium text-slate-300 hover:text-white min-h-[26px]"
                  >
                    <Trash2 className="h-3 w-3" aria-hidden="true" />
                    <span>Limpiar</span>
                  </button>
                </div>
              </div>

              <div>
                <label
                  htmlFor="url-manual-input"
                  className="block text-2xs text-slate-400 mb-1"
                >
                  Pegá un link sucio de Amazon, MercadoLibre, Google Ads, Instagram o X:
                </label>
                <input
                  id="url-manual-input"
                  type="url"
                  autoComplete="off"
                  value={manualUrl}
                  onChange={(e) => setManualUrl(e.target.value.slice(0, 2048))}
                  placeholder="https://www.amazon.com/...?tag=...&gad_source=..."
                  className="w-full rounded-xl border border-raggio-border bg-raggio-canvas px-3 py-2 font-mono text-xs text-white placeholder-slate-500 focus:border-raggio-gold"
                />
              </div>

              {manualSanitizeResult && (
                <div className="rounded-xl border border-raggio-border bg-raggio-canvas p-3 space-y-2.5">
                  {!manualSanitizeResult.isValidHttpUrl ? (
                    <div className="text-2xs font-semibold text-semaphore-dangerText">
                      🔴 URL inválida o protocolo bloqueado por seguridad (solo se aceptan enlaces http:// y https://).
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-2xs font-semibold text-slate-300">
                          {manualSanitizeResult.removedCount > 0
                            ? `🧹 ${manualSanitizeResult.removedCount} ${
                                manualSanitizeResult.removedCount === 1
                                  ? 'rastreador eliminado'
                                  : 'rastreadores eliminados'
                              }:`
                            : '✨ Enlace limpio (0 rastreadores detectados)'}
                        </span>
                      </div>

                      {manualSanitizeResult.removedParams.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {manualSanitizeResult.removedParams.map(
                            (param, idx) => (
                              <span
                                key={`${param}-${idx}`}
                                className="rounded border px-1.5 py-0.5 font-mono text-2xs font-semibold"
                                style={{
                                  backgroundColor: 'rgba(69, 10, 10, 0.65)',
                                  borderColor: 'rgba(239, 68, 68, 0.5)',
                                  color: '#FCA5A5',
                                }}
                              >
                                − {param}
                              </span>
                            ),
                          )}
                        </div>
                      )}

                      <div className="rounded-lg border border-raggio-border bg-raggio-card p-2 font-mono text-2xs text-semaphore-safeText break-all">
                        {manualSanitizeResult.cleanUrl}
                      </div>

                      <button
                        type="button"
                        onClick={() =>
                          void triggerCopyFeedback(
                            'manual-clean-url',
                            manualSanitizeResult.cleanUrl,
                            'Link limpio copiado al portapapeles.',
                          )
                        }
                        className="w-full inline-flex items-center justify-center gap-1.5 rounded-xl border px-3 py-2 text-xs font-bold transition-colors min-h-[34px]"
                        style={{
                          backgroundColor: '#16122B',
                          borderColor: 'rgba(251, 191, 36, 0.45)',
                          color: '#FBBF24',
                        }}
                      >
                        {copiedKey === 'manual-clean-url' ? (
                          <>
                            <Check
                              className="h-4 w-4 text-semaphore-safeText"
                              aria-hidden="true"
                            />
                            <span>¡Link Limpio Copiado!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                            <span>Copiar Link Limpio</span>
                          </>
                        )}
                      </button>
                    </>
                  )}
                </div>
              )}
            </section>
          </div>
        )}

        {/* ==================== TAB 3: AJUSTES ==================== */}
        {activeTab === 'settings' && (
          <div
            id="panel-settings"
            role="tabpanel"
            aria-labelledby="tab-settings"
            className="space-y-3"
          >
            <section
              aria-label="Configuración de Escudo Criollo"
              className="rounded-2xl border border-raggio-border bg-raggio-card p-3.5 space-y-3.5"
            >
              {/* Toggle 1: Floating badge in online stores */}
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div
                    id="lbl-floating-badge"
                    className="text-xs font-semibold text-white"
                  >
                    Mostrar insignia flotante en tiendas online
                  </div>
                  <p className="mt-0.5 text-2xs text-slate-400 m-0 leading-relaxed">
                    Inyecta la píldora preventiva no intrusiva cuando detecta carritos o e-commerce.
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={settings.showFloatingBadge}
                  aria-labelledby="lbl-floating-badge"
                  onClick={() =>
                    void handleUpdateSetting({
                      showFloatingBadge: !settings.showFloatingBadge,
                    })
                  }
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors ${
                    settings.showFloatingBadge
                      ? 'border-raggio-gold bg-raggio-violet'
                      : 'border-raggio-border bg-raggio-canvas'
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                      settings.showFloatingBadge
                        ? 'translate-x-5 bg-raggio-goldLight'
                        : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>

              <div className="border-t border-raggio-border" />

              {/* Toggle 2: Always show badge */}
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div
                    id="lbl-always-show"
                    className="text-xs font-semibold text-white"
                  >
                    Mostrar siempre en cualquier sitio web
                  </div>
                  <p className="mt-0.5 text-2xs text-slate-400 m-0 leading-relaxed">
                    Mantiene visible el escudo incluso en páginas que no son tiendas.
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={settings.alwaysShowBadge}
                  aria-labelledby="lbl-always-show"
                  onClick={() =>
                    void handleUpdateSetting({
                      alwaysShowBadge: !settings.alwaysShowBadge,
                    })
                  }
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors ${
                    settings.alwaysShowBadge
                      ? 'border-raggio-gold bg-raggio-violet'
                      : 'border-raggio-border bg-raggio-canvas'
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                      settings.alwaysShowBadge
                        ? 'translate-x-5 bg-raggio-goldLight'
                        : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>

              <div className="border-t border-raggio-border" />

              {/* Toggle 3: Auto-clean trackers on copy */}
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div
                    id="lbl-auto-clean"
                    className="text-xs font-semibold text-white"
                  >
                    Limpiar trackers automáticamente al copiar URLs
                  </div>
                  <p className="mt-0.5 text-2xs text-slate-400 m-0 leading-relaxed">
                    Elimina parámetros espía (tag, gad_source, igsh, fbclid, matt_tool) al copiar.
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={settings.autoCleanCopiedLinks}
                  aria-labelledby="lbl-auto-clean"
                  onClick={() =>
                    void handleUpdateSetting({
                      autoCleanCopiedLinks: !settings.autoCleanCopiedLinks,
                    })
                  }
                  className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors ${
                    settings.autoCleanCopiedLinks
                      ? 'border-raggio-gold bg-raggio-violet'
                      : 'border-raggio-border bg-raggio-canvas'
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                      settings.autoCleanCopiedLinks
                        ? 'translate-x-5 bg-raggio-goldLight'
                        : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>

              <div className="border-t border-raggio-border" />

              {/* Badge Position Selector */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-white">
                  Posición de la insignia en pantalla
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    aria-pressed={settings.badgePosition === 'bottom-left'}
                    onClick={() =>
                      void handleUpdateSetting({ badgePosition: 'bottom-left' })
                    }
                    className={`rounded-xl border px-3 py-2 text-xs font-semibold transition-colors min-h-[34px] ${
                      settings.badgePosition === 'bottom-left'
                        ? 'border-raggio-gold bg-raggio-hover text-raggio-gold'
                        : 'border-raggio-border bg-raggio-canvas text-slate-300 hover:bg-raggio-hover'
                    }`}
                  >
                    ↙ Abajo Izquierda
                  </button>
                  <button
                    type="button"
                    aria-pressed={settings.badgePosition === 'bottom-right'}
                    onClick={() =>
                      void handleUpdateSetting({ badgePosition: 'bottom-right' })
                    }
                    className={`rounded-xl border px-3 py-2 text-xs font-semibold transition-colors min-h-[34px] ${
                      settings.badgePosition === 'bottom-right'
                        ? 'border-raggio-gold bg-raggio-hover text-raggio-gold'
                        : 'border-raggio-border bg-raggio-canvas text-slate-300 hover:bg-raggio-hover'
                    }`}
                  >
                    ↘ Abajo Derecha
                  </button>
                </div>
              </div>

              {/* Dismissed Domains Reset */}
              {settings.dismissedDomains.length > 0 && (
                <>
                  <div className="border-t border-raggio-border" />
                  <div className="flex items-center justify-between gap-2">
                    <div className="text-2xs text-slate-300">
                      Sitios ocultados manualmente:{' '}
                      <span className="font-mono font-bold text-raggio-gold">
                        {settings.dismissedDomains.length}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        void handleUpdateSetting({ dismissedDomains: [] })
                      }
                      className="inline-flex items-center gap-1 rounded-lg border border-raggio-border bg-raggio-canvas px-2.5 py-1 text-2xs font-semibold text-raggio-gold hover:border-raggio-gold min-h-[28px]"
                    >
                      <RotateCcw className="h-3 w-3" aria-hidden="true" />
                      <span>Restaurar todos</span>
                    </button>
                  </div>
                </>
              )}
            </section>

            {/* Zero-Trust Privacy Guarantee Box */}
            <section
              aria-label="Garantía de privacidad local"
              className="rounded-2xl border border-raggio-border bg-raggio-card p-3 text-2xs text-slate-300 space-y-1"
            >
              <div className="font-semibold text-raggio-goldLight">
                🔒 Arquitectura Zero-Server (Privacidad Total)
              </div>
              <p className="m-0 leading-relaxed text-slate-400">
                Escudo Criollo procesa todo localmente en tu navegador. No envía tu historial de compras, CUITs ni enlaces a ningún servidor externo.
              </p>
            </section>
          </div>
        )}
      </main>

      {/* Raggiodev Signature Footer */}
      <footer className="border-t border-raggio-border bg-raggio-card px-3.5 py-2.5 text-center">
        <div className="text-2xs text-slate-300">
          <span className="font-mono font-semibold">Escudo Criollo v0.1.4</span>{' '}
          · Desarrollado por{' '}
          <a
            href={RAGGIODEV_PORTFOLIO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="font-extrabold tracking-wide text-raggio-gold hover:underline"
          >
            <span className="raggio-gold-text">Raggiodev</span>
          </a>
        </div>
        <div className="mt-0.5 font-mono text-2xs text-slate-400">
          100% Local &amp; Open Source
        </div>
      </footer>
    </div>
  );
};

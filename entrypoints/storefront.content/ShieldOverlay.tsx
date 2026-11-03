import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  ExternalLink,
  Megaphone,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import { sanitizeUrl } from '../../src/modules/v01-clean-links/sanitizer';
import {
  AuditFinding,
  ExtensionSettings,
  RiskLevel,
  ScoreBreakdownItem,
  StoreAuditReport,
  ToastNotificationPayload,
} from '../../src/types';
import { copyTextSafely } from '../../src/utils/clipboard';
import { buildSafeXAlertTweet } from '../../src/utils/share';

const BCRA_DEUDORES_URL =
  'https://www.bcra.gob.ar/BCRAyVos/Situacion_Crediticia.asp';
const RAGGIODEV_PORTFOLIO_URL = 'https://raggiodev.com';

export interface ShieldOverlayProps {
  report: StoreAuditReport;
  settings: ExtensionSettings;
  toast: ToastNotificationPayload | null;
  onDismissToast: () => void;
  onHideOnSite: (hostname: string) => void;
}

function getSemaphoreConfig(risk: RiskLevel): {
  dotColor: string;
  pillBorder: string;
  badgeStyle: React.CSSProperties;
  scoreBarColor: string;
} {
  switch (risk) {
    case 'SAFE':
      return {
        dotColor: '#34D399',
        pillBorder: 'rgba(16, 185, 129, 0.55)',
        badgeStyle: {
          color: '#34D399',
          backgroundColor: 'rgba(6, 78, 59, 0.65)',
          borderColor: '#10B981',
        },
        scoreBarColor: '#10B981',
      };
    case 'WARNING':
      return {
        dotColor: '#FBBF24',
        pillBorder: 'rgba(245, 158, 11, 0.6)',
        badgeStyle: {
          color: '#FBBF24',
          backgroundColor: 'rgba(69, 26, 3, 0.65)',
          borderColor: '#F59E0B',
        },
        scoreBarColor: '#F59E0B',
      };
    case 'DANGER':
      return {
        dotColor: '#F87171',
        pillBorder: '#EF4444',
        badgeStyle: {
          color: '#F87171',
          backgroundColor: 'rgba(69, 10, 10, 0.75)',
          borderColor: '#EF4444',
        },
        scoreBarColor: '#EF4444',
      };
    case 'NEUTRAL':
    default:
      return {
        dotColor: '#A78BFA',
        pillBorder: '#2B2354',
        badgeStyle: {
          color: '#C4B5FD',
          backgroundColor: 'rgba(31, 25, 61, 0.85)',
          borderColor: '#4F46E5',
        },
        scoreBarColor: '#7C3AED',
      };
  }
}

function getFindingIconLabel(severity: AuditFinding['severity']): string {
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

export const ShieldOverlay: React.FC<ShieldOverlayProps> = ({
  report,
  settings,
  toast,
  onDismissToast,
  onHideOnSite,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const minimizedHostRef = useRef<string | null>(null);

  const [copiedCuit, setCopiedCuit] = useState<string | null>(null);
  const [cleanCopyStatus, setCleanCopyStatus] = useState<string | null>(null);
  const [liveAnnouncement, setLiveAnnouncement] = useState('');

  const isDismissedOnDomain = settings.dismissedDomains.includes(
    report.hostname.toLowerCase(),
  );
  const shouldShowShield =
    settings.showFloatingBadge &&
    !isDismissedOnDomain &&
    (report.ecommerce.isEcommerce || settings.alwaysShowBadge);

  // Fast 2.5s Sticky Auto-Minimize for SAFE stores: never resets back to false on background re-scans of the same hostname
  useEffect(() => {
    if (
      minimizedHostRef.current &&
      minimizedHostRef.current !== report.hostname
    ) {
      minimizedHostRef.current = null;
      setIsMinimized(false);
    }

    if (report.riskLevel !== 'SAFE') {
      minimizedHostRef.current = null;
      setIsMinimized(false);
      return;
    }

    if (minimizedHostRef.current === report.hostname) {
      setIsMinimized(true);
      return;
    }

    if (!shouldShowShield || isExpanded) {
      return;
    }

    const timer = window.setTimeout(() => {
      minimizedHostRef.current = report.hostname;
      setIsMinimized(true);
    }, 2500);

    return () => window.clearTimeout(timer);
  }, [report.hostname, report.riskLevel, isExpanded, shouldShowShield]);

  // Close expanded card on Escape key
  useEffect(() => {
    if (!isExpanded) {
      return;
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsExpanded(false);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isExpanded]);

  const semaphore = useMemo(
    () => getSemaphoreConfig(report.riskLevel),
    [report.riskLevel],
  );

  const positionStyle: React.CSSProperties =
    settings.badgePosition === 'bottom-right'
      ? { position: 'fixed', right: '18px', bottom: '18px', zIndex: 2147483640 }
      : { position: 'fixed', left: '18px', bottom: '18px', zIndex: 2147483640 };

  const handleCopyCuit = async (formattedCuit: string) => {
    const ok = await copyTextSafely(formattedCuit);
    if (ok) {
      setCopiedCuit(formattedCuit);
      setLiveAnnouncement(`CUIT ${formattedCuit} copiado al portapapeles.`);
      window.setTimeout(() => setCopiedCuit(null), 2200);
    }
  };

  const handleCopyCleanUrl = async () => {
    const currentHref = window.location.href;
    const sanitized = sanitizeUrl(currentHref);
    const targetToCopy = sanitized.isValidHttpUrl
      ? sanitized.cleanUrl
      : report.url;
    const ok = await copyTextSafely(targetToCopy);
    if (ok) {
      const feedback =
        sanitized.removedCount > 0
          ? `¡Copiado! (-${sanitized.removedCount} ${
              sanitized.removedCount === 1 ? 'tracker' : 'trackers'
            })`
          : '¡Link limpio copiado!';
      setCleanCopyStatus(feedback);
      setLiveAnnouncement(feedback);
      window.setTimeout(() => setCleanCopyStatus(null), 2600);
    }
  };

  const primaryCuit = report.cuits[0] ?? null;
  const xAlertUrl = useMemo(
    () =>
      report.riskLevel === 'DANGER'
        ? buildSafeXAlertTweet(report).intentUrl
        : null,
    [report],
  );

  if (!shouldShowShield && !toast) {
    return null;
  }

  return (
    <div
      style={positionStyle}
      className="flex flex-col items-start gap-2.5 font-sans text-slate-100 select-none"
    >
      {/* Centralized Screen-Reader Polite Live Region */}
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {liveAnnouncement}
      </div>

      {/* Context Menu / Auto-Clean Feedback Toast */}
      {toast && (
        <div
          role="status"
          className="w-[320px] max-w-[calc(100vw-32px)] rounded-xl border p-3 shadow-raggio-card transition-all"
          style={{
            backgroundColor: '#16122B',
            borderColor:
              toast.variant === 'DANGER'
                ? '#EF4444'
                : toast.variant === 'WARNING'
                  ? '#F59E0B'
                  : '#10B981',
          }}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-1.5 text-xs font-semibold">
              <span aria-hidden="true">
                {toast.variant === 'DANGER'
                  ? '🚨'
                  : toast.variant === 'WARNING'
                    ? '⚠️'
                    : '🛡️'}
              </span>
              <span
                style={{
                  color:
                    toast.variant === 'DANGER'
                      ? '#F87171'
                      : toast.variant === 'WARNING'
                        ? '#FBBF24'
                        : '#34D399',
                }}
              >
                {toast.title}
              </span>
            </div>
            <button
              type="button"
              onClick={onDismissToast}
              aria-label="Cerrar notificación"
              className="rounded p-1 text-slate-400 hover:bg-raggio-hover hover:text-white min-w-[24px] min-h-[24px] flex items-center justify-center"
            >
              <X className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
          <p className="mt-1 font-mono text-2xs text-slate-300 break-all leading-relaxed">
            {toast.detail}
          </p>
        </div>
      )}

      {/* Expanded 340px Forensic Report Card */}
      {shouldShowShield && isExpanded && (
        <section
          aria-label="Reporte forense de seguridad Escudo Criollo"
          className="w-[340px] max-w-[calc(100vw-32px)] overflow-hidden rounded-2xl border shadow-raggio-card select-text"
          style={{
            backgroundColor: '#0D0B18',
            borderColor: 'rgba(251, 191, 36, 0.35)',
          }}
        >
          {/* Raggiodev Violet-Blue & Gold Header */}
          <header
            className="p-3.5 border-b"
            style={{
              background:
                'linear-gradient(135deg, #4F46E5 0%, #7C3AED 55%, #2563EB 100%)',
              borderColor: 'rgba(251, 191, 36, 0.3)',
            }}
          >
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <div
                  className="flex h-7 w-7 items-center justify-center rounded-lg border"
                  style={{
                    backgroundColor: 'rgba(13, 11, 24, 0.72)',
                    borderColor: 'rgba(251, 191, 36, 0.55)',
                  }}
                >
                  <ShieldCheck
                    className="w-4 h-4 text-raggio-gold"
                    aria-hidden="true"
                  />
                </div>
                <div>
                  <div className="flex items-center gap-1.5">
                    <h2 className="text-sm font-bold text-white leading-tight m-0">
                      Escudo Criollo
                    </h2>
                    <span
                      className="rounded px-1.5 py-0.5 font-mono text-2xs font-bold"
                      style={{
                        backgroundColor: 'rgba(13, 11, 24, 0.75)',
                        color: '#FBBF24',
                        border: '1px solid rgba(251, 191, 36, 0.35)',
                      }}
                    >
                      v0.1.3
                    </span>
                  </div>
                  <p className="text-2xs text-indigo-100/90 m-0 leading-tight">
                    Auditoría Forense · by{' '}
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

              <button
                type="button"
                onClick={() => setIsExpanded(false)}
                aria-label="Minimizar reporte Escudo Criollo"
                className="flex min-h-[28px] min-w-[28px] items-center justify-center rounded-lg bg-black/30 text-white hover:bg-black/50 transition-colors"
              >
                <ChevronDown className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>

            {/* Platform Badge + Trust Score */}
            <div
              className="mt-3 flex items-center justify-between gap-2 rounded-xl px-3 py-2 border"
              style={{
                backgroundColor: 'rgba(13, 11, 24, 0.78)',
                borderColor: 'rgba(251, 191, 36, 0.25)',
              }}
            >
              <div className="min-w-0">
                <div className="text-2xs uppercase tracking-wider text-slate-400">
                  Plataforma / Dominio
                </div>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className="inline-flex items-center rounded-md bg-raggio-hover px-1.5 py-0.5 text-2xs font-semibold text-raggio-gold border border-raggio-border">
                    {report.ecommerce.platformLabel}
                  </span>
                  <span className="truncate font-mono text-2xs text-slate-300">
                    {report.hostname}
                  </span>
                </div>
              </div>

              <div className="text-right shrink-0">
                <div className="text-2xs uppercase tracking-wider text-slate-400">
                  Confianza
                </div>
                <div
                  className="font-mono text-base font-extrabold leading-tight"
                  style={{ color: semaphore.dotColor }}
                >
                  {report.trustScore}
                  <span className="text-2xs font-normal text-slate-400">
                    /100
                  </span>
                </div>
              </div>
            </div>

            {/* Progress bar */}
            <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-black/40">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{
                  width: `${report.trustScore}%`,
                  backgroundColor: semaphore.scoreBarColor,
                }}
              />
            </div>
          </header>

          {/* Body Content */}
          <div className="p-3.5 space-y-2.5">
            {/* Collapsible Transparent Score Breakdown */}
            {report.scoreBreakdown.length > 0 && (
              <details
                className="group rounded-xl border px-2.5 py-2"
                style={{
                  backgroundColor: '#16122B',
                  borderColor: '#2B2354',
                }}
              >
                <summary className="flex items-center justify-between gap-2 text-2xs font-semibold text-raggio-goldLight select-none min-h-[24px]">
                  <span>📊 ¿De dónde sale este puntaje? (Desglose)</span>
                  <ChevronRight
                    className="h-3.5 w-3.5 shrink-0 text-raggio-gold transition-transform group-open:rotate-90"
                    aria-hidden="true"
                  />
                </summary>
                <ul
                  role="list"
                  className="mt-2 space-y-1 border-t border-raggio-border pt-2 m-0 p-0 list-none"
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
                  <li className="flex items-center justify-between gap-2 border-t border-raggio-border/60 pt-1 text-2xs font-bold">
                    <span className="text-slate-200">Puntaje de Confianza Final</span>
                    <span
                      className="font-mono"
                      style={{ color: semaphore.dotColor }}
                    >
                      {report.trustScore}/100
                    </span>
                  </li>
                </ul>
              </details>
            )}

            {/* CUIT & ARCA/AFIP Status Box */}
            {report.ecommerce.platform !== 'ECOMMERCE_INTERNACIONAL' && (
              <div
                className="rounded-xl border p-2.5 space-y-2"
                style={{
                  backgroundColor: '#16122B',
                  borderColor: '#2B2354',
                }}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-2xs font-semibold uppercase tracking-wider text-slate-400">
                    CUIT &amp; Data Fiscal ARCA
                  </span>
                  <a
                    href={BCRA_DEUDORES_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-2xs font-semibold text-raggio-gold hover:underline min-h-[24px]"
                  >
                    <span>Central BCRA</span>
                    <ExternalLink className="w-3 h-3" aria-hidden="true" />
                  </a>
                </div>

                {primaryCuit ? (
                  <div className="flex items-center justify-between gap-2 rounded-lg bg-raggio-canvas px-2.5 py-1.5 border border-raggio-border">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="font-mono text-xs font-bold"
                          style={{
                            color: primaryCuit.isValid ? '#34D399' : '#F87171',
                          }}
                        >
                          {primaryCuit.formatted}
                        </span>
                        <span
                          className="rounded px-1 py-0.5 font-mono text-2xs font-semibold border"
                          style={
                            primaryCuit.isValid
                              ? {
                                  color: '#34D399',
                                  backgroundColor: 'rgba(6, 78, 59, 0.65)',
                                  borderColor: '#10B981',
                                }
                              : {
                                  color: '#F87171',
                                  backgroundColor: 'rgba(69, 10, 10, 0.75)',
                                  borderColor: '#EF4444',
                                }
                          }
                        >
                          {primaryCuit.isValid ? 'MÓD.11 OK' : 'INVÁLIDO'}
                        </span>
                      </div>
                      <div className="truncate text-2xs text-slate-400 mt-0.5">
                        {primaryCuit.entityLabel}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => void handleCopyCuit(primaryCuit.formatted)}
                      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-raggio-border bg-raggio-hover px-2 py-1 text-2xs font-medium text-slate-200 hover:border-raggio-gold hover:text-raggio-gold transition-colors min-h-[26px]"
                    >
                      {copiedCuit === primaryCuit.formatted ? (
                        <>
                          <Check
                            className="w-3 h-3 text-semaphore-safeText"
                            aria-hidden="true"
                          />
                          <span>Copiado</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" aria-hidden="true" />
                          <span>Copiar CUIT</span>
                        </>
                      )}
                    </button>
                  </div>
                ) : (
                  <div className="rounded-lg bg-raggio-canvas px-2.5 py-1.5 border border-raggio-border font-mono text-2xs text-slate-400">
                    Sin CUIT detectado en el pie de página
                  </div>
                )}

                {/* Data Fiscal Status Row */}
                <div className="flex items-center justify-between gap-2 text-2xs pt-0.5">
                  <span className="text-slate-400">Formulario F.960 QR:</span>
                  {report.dataFiscal.status === 'VERIFIED_OFFICIAL_QR' &&
                  report.dataFiscal.officialQrUrl ? (
                    <a
                      href={report.dataFiscal.officialQrUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono font-semibold text-semaphore-safeText hover:underline min-h-[24px]"
                    >
                      <span>QR Oficial Verificado</span>
                      <ExternalLink className="w-3 h-3" aria-hidden="true" />
                    </a>
                  ) : report.dataFiscal.status === 'FORGED_STATIC_SEAL' ? (
                    <span className="font-mono font-bold text-semaphore-dangerText">
                      🚨 Sello Trucho / Sin Link
                    </span>
                  ) : (
                    <span className="font-mono text-slate-400">
                      No detectado en vista actual
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* List of Findings */}
            <div>
              <h3 className="text-2xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 m-0">
                Diagnóstico de Seguridad ({report.findings.length})
              </h3>
              <ul
                role="list"
                className="raggio-scrollbar max-h-[175px] space-y-2 overflow-y-auto pr-1 m-0 p-0 list-none"
              >
                {report.findings.map((finding) => {
                  const borderMap: Record<AuditFinding['severity'], string> = {
                    SAFE: 'rgba(16, 185, 129, 0.35)',
                    WARNING: 'rgba(245, 158, 11, 0.4)',
                    DANGER: 'rgba(239, 68, 68, 0.55)',
                  };
                  const bgMap: Record<AuditFinding['severity'], string> = {
                    SAFE: 'rgba(6, 78, 59, 0.22)',
                    WARNING: 'rgba(69, 26, 3, 0.28)',
                    DANGER: 'rgba(69, 10, 10, 0.38)',
                  };
                  return (
                    <li
                      key={finding.id}
                      className="rounded-xl border p-2.5 text-xs"
                      style={{
                        backgroundColor: bgMap[finding.severity],
                        borderColor: borderMap[finding.severity],
                      }}
                    >
                      <div className="flex items-start gap-1.5 font-semibold text-slate-100 leading-snug">
                        <span aria-hidden="true" className="shrink-0">
                          {getFindingIconLabel(finding.severity)}
                        </span>
                        <span>{finding.title}</span>
                      </div>
                      <p className="mt-1 text-2xs text-slate-300 leading-relaxed m-0">
                        {finding.detail}
                      </p>
                      {finding.evidence && (
                        <div className="mt-1.5 rounded bg-black/35 px-2 py-1 font-mono text-2xs text-raggio-goldLight break-all border border-white/5">
                          {finding.evidence}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>

            {/* Quick Action Bar */}
            <div className="pt-1 border-t border-raggio-border space-y-1.5">
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => void handleCopyCleanUrl()}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-2xs font-semibold transition-colors min-h-[32px]"
                  style={{
                    backgroundColor: '#16122B',
                    borderColor: 'rgba(251, 191, 36, 0.35)',
                    color: '#FBBF24',
                  }}
                >
                  <Sparkles className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                  <span className="truncate">
                    {cleanCopyStatus ?? '🧹 Copiar Link Limpio'}
                  </span>
                </button>

                {report.riskLevel === 'DANGER' && xAlertUrl && (
                  <a
                    href={xAlertUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex shrink-0 items-center justify-center gap-1 rounded-lg border px-2.5 py-1.5 text-2xs font-semibold transition-colors min-h-[32px] no-underline"
                    style={{
                      backgroundColor: 'rgba(69, 10, 10, 0.75)',
                      borderColor: '#EF4444',
                      color: '#F87171',
                    }}
                  >
                    <Megaphone className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Alertar en X</span>
                  </a>
                )}
              </div>

              <div className="flex items-center justify-between text-2xs text-slate-400 pt-0.5">
                <span>
                  100% Local ·{' '}
                  <a
                    href={RAGGIODEV_PORTFOLIO_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-semibold text-raggio-gold hover:underline"
                  >
                    Raggiodev
                  </a>
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setIsExpanded(false);
                    onHideOnSite(report.hostname);
                  }}
                  className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-raggio-hover hover:text-slate-200 transition-colors min-h-[24px]"
                >
                  <X className="w-3 h-3" aria-hidden="true" />
                  <span>Ocultar en este sitio</span>
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Collapsed "Steamcito-style" Floating Pill (Sticky 2.5s compact mode for SAFE sites) */}
      {shouldShowShield && (
        <button
          type="button"
          onClick={() => {
            setIsExpanded((prev) => !prev);
          }}
          aria-expanded={isExpanded}
          aria-label={`Escudo Criollo: ${report.pillHeadline}. Puntaje ${report.trustScore} de 100. Hacé clic para ver el diagnóstico forense.`}
          className={`group inline-flex items-center gap-2 rounded-full border transition-all duration-200 min-h-[38px] ${
            report.riskLevel === 'DANGER'
              ? 'animate-danger-pulse'
              : 'shadow-raggio-card'
          } ${
            isMinimized && !isExpanded
              ? 'px-2 py-2 opacity-85 hover:opacity-100'
              : 'px-3.5 py-2'
          }`}
          style={{
            backgroundColor: '#0D0B18',
            borderColor: semaphore.pillBorder,
          }}
        >
          {/* Golden/Violet Shield Emblem */}
          <span
            className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full"
            style={{
              background:
                'linear-gradient(135deg, #4F46E5 0%, #7C3AED 55%, #2563EB 100%)',
              boxShadow: '0 0 10px rgba(245, 158, 11, 0.2)',
              border: '1px solid rgba(251, 191, 36, 0.5)',
            }}
          >
            {report.riskLevel === 'DANGER' ? (
              <ShieldAlert
                className="w-3.5 h-3.5 text-raggio-goldLight"
                aria-hidden="true"
              />
            ) : report.riskLevel === 'WARNING' ? (
              <AlertTriangle
                className="w-3.5 h-3.5 text-raggio-goldLight"
                aria-hidden="true"
              />
            ) : (
              <ShieldCheck
                className="w-3.5 h-3.5 text-raggio-goldLight"
                aria-hidden="true"
              />
            )}
          </span>

          {/* Status Semaphore Dot */}
          <span
            aria-hidden="true"
            className="h-2 w-2 shrink-0 rounded-full"
            style={{
              backgroundColor: semaphore.dotColor,
              boxShadow: `0 0 8px ${semaphore.dotColor}`,
            }}
          />

          {/* Verdict Text (hidden once sticky 2.5s minimize activates on SAFE sites) */}
          {(!isMinimized || isExpanded) && (
            <span className="flex items-center gap-2 text-xs font-semibold tracking-tight text-slate-100">
              <span>
                {report.riskLevel === 'DANGER'
                  ? `🚨 ${report.pillHeadline}`
                  : report.riskLevel === 'WARNING'
                    ? `⚠️ ${report.pillHeadline}`
                    : `🛡️ ${report.pillHeadline}`}
              </span>
              <span
                className="rounded-full border px-1.5 py-0.5 font-mono text-2xs font-bold"
                style={semaphore.badgeStyle}
              >
                {report.trustScore}
              </span>
            </span>
          )}
        </button>
      )}
    </div>
  );
};

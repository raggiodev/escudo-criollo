import './style.css';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { browser } from 'wxt/browser';
import { ContentScriptContext, createShadowRootUi } from 'wxt/client';
import { defineContentScript } from 'wxt/sandbox';
import { sanitizeUrl } from '../../src/modules/v01-clean-links/sanitizer';
import { auditStoreSecurity } from '../../src/modules/v01-store-heuristics/detector';
import {
  DEFAULT_SETTINGS,
  ExtensionMessageResponse,
  ExtensionSettings,
  StoreAuditReport,
  ToastNotificationPayload,
  parseSafeHttpUrl,
} from '../../src/types';
import { copyTextSafely } from '../../src/utils/clipboard';
import {
  dismissDomainForSite,
  getSettings,
  isTrustedExtensionSender,
  subscribeToSettings,
  validateExtensionMessage,
} from '../../src/utils/storage';
import { ShieldOverlay } from './ShieldOverlay';

const SPA_HYDRATION_CHECKPOINTS_MS = [600, 1600, 3200] as const;

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_idle',
  cssInjectionMode: 'ui',

  async main(ctx: ContentScriptContext) {
    if (!document.body) {
      return;
    }

    let currentSettings: ExtensionSettings = DEFAULT_SETTINGS;
    try {
      currentSettings = await getSettings();
    } catch {
      currentSettings = DEFAULT_SETTINGS;
    }

    let currentReport: StoreAuditReport = auditStoreSecurity(
      document,
      window.location.href,
    );
    let activeToast: ToastNotificationPayload | null = null;
    let toastTimer: number | null = null;
    let hydrationTimers: number[] = [];
    let reactRoot: ReactDOM.Root | null = null;
    let activeShadowHost: HTMLElement | null = null;
    let remountCount = 0;
    const MAX_ANTI_TAMPER_REMOUNTS = 1;

    const clearHydrationTimers = () => {
      for (const timerId of hydrationTimers) {
        window.clearTimeout(timerId);
      }
      hydrationTimers = [];
    };

    const reportToBackground = async (report: StoreAuditReport) => {
      try {
        await browser.runtime.sendMessage({
          type: 'REPORT_STORE_AUDIT',
          payload: report,
        });
      } catch {
        // Service worker may still be waking up
      }
    };

    const renderUi = () => {
      if (!reactRoot) {
        return;
      }
      reactRoot.render(
        <React.StrictMode>
          <ShieldOverlay
            report={currentReport}
            settings={currentSettings}
            toast={activeToast}
            onDismissToast={() => {
              activeToast = null;
              renderUi();
            }}
            onHideOnSite={(hostname) => {
              void (async () => {
                currentSettings = await dismissDomainForSite(hostname);
                renderUi();
              })();
            }}
          />
        </React.StrictMode>,
      );
    };

    /**
     * SPA Hydration Grace Period:
     * Re-scans at 600ms, 1600ms, and 3200ms when lazy-loaded SPAs (VTEX, Angular, Next.js)
     * haven't yet mounted their footer Data Fiscal F.960 QR or CUIT during initial load.
     */
    const scheduleHydrationGraceScans = () => {
      clearHydrationTimers();

      if (
        currentReport.ecommerce.platform === 'ECOMMERCE_INTERNACIONAL' ||
        currentReport.riskLevel === 'DANGER'
      ) {
        return;
      }

      for (const delayMs of SPA_HYDRATION_CHECKPOINTS_MS) {
        const timerId = window.setTimeout(() => {
          window.requestAnimationFrame(() => {
            if (ctx.isInvalid) {
              return;
            }
            // Only re-audit if F.960 QR or CUIT hasn't been picked up yet
            const needsHydrationCheck =
              currentReport.dataFiscal.status === 'MISSING_DATA_FISCAL' ||
              (!currentReport.ecommerce.isWhitelistedOfficial &&
                currentReport.riskLevel === 'WARNING');

            if (!needsHydrationCheck) {
              return;
            }

            const refreshed = auditStoreSecurity(document, window.location.href);
            const hasChanged =
              refreshed.trustScore !== currentReport.trustScore ||
              refreshed.riskLevel !== currentReport.riskLevel ||
              refreshed.dataFiscal.status !== currentReport.dataFiscal.status ||
              refreshed.cuits.length !== currentReport.cuits.length ||
              refreshed.ecommerce.isEcommerce !==
                currentReport.ecommerce.isEcommerce;

            if (hasChanged) {
              currentReport = refreshed;
              renderUi();
              void reportToBackground(currentReport);
            }
          });
        }, delayMs);
        hydrationTimers.push(timerId);
      }
    };

    const showToast = (payload: ToastNotificationPayload) => {
      activeToast = payload;
      if (toastTimer !== null) {
        window.clearTimeout(toastTimer);
      }
      renderUi();
      toastTimer = window.setTimeout(() => {
        activeToast = null;
        renderUi();
      }, 4500);
    };

    const mountClosedShadowUi = async () => {
      const ui = await createShadowRootUi(ctx, {
        name: 'escudo-criollo-shield',
        position: 'overlay',
        zIndex: 2147483640,
        mode: 'closed',
        isolateEvents: true,
        onMount: (uiContainer, _shadow, shadowHost) => {
          activeShadowHost = shadowHost;
          const root = ReactDOM.createRoot(uiContainer);
          reactRoot = root;
          renderUi();
          return root;
        },
        onRemove: (mountedRoot) => {
          mountedRoot?.unmount();
          if (reactRoot === mountedRoot) {
            reactRoot = null;
          }
        },
      });
      ui.mount();
      return ui;
    };

    await mountClosedShadowUi();
    void reportToBackground(currentReport);
    scheduleHydrationGraceScans();

    // Anti-Tampering MutationObserver: re-mounts once safely if a hostile page script deletes the host element
    const antiTamperObserver = new MutationObserver(() => {
      if (ctx.isInvalid) {
        antiTamperObserver.disconnect();
        return;
      }
      if (
        activeShadowHost &&
        !document.body.contains(activeShadowHost) &&
        remountCount < MAX_ANTI_TAMPER_REMOUNTS
      ) {
        remountCount += 1;
        activeShadowHost = null;
        window.requestAnimationFrame(() => {
          if (!ctx.isInvalid && document.body) {
            void mountClosedShadowUi();
          }
        });
      }
    });

    antiTamperObserver.observe(document.body, {
      childList: true,
    });

    // Subscribe to live settings changes from the Popup
    const unsubscribeSettings = subscribeToSettings((updated) => {
      currentSettings = updated;
      renderUi();
    });

    // Auto-clean trackers on copy when enabled in settings
    const onDocumentCopy = (event: ClipboardEvent) => {
      if (!currentSettings.autoCleanCopiedLinks) {
        return;
      }
      const selection = window.getSelection()?.toString().trim() ?? '';
      if (
        selection.length === 0 ||
        selection.length > 2048 ||
        /\s/.test(selection)
      ) {
        return;
      }
      if (!parseSafeHttpUrl(selection)) {
        return;
      }
      const sanitized = sanitizeUrl(selection);
      if (
        sanitized.isValidHttpUrl &&
        sanitized.isModified &&
        event.clipboardData
      ) {
        event.clipboardData.setData('text/plain', sanitized.cleanUrl);
        event.preventDefault();
        showToast({
          variant: 'SAFE',
          title: `Trackers limpiados al copiar (-${sanitized.removedCount})`,
          detail: sanitized.cleanUrl,
        });
      }
    };
    document.addEventListener('copy', onDocumentCopy);

    // SPA Navigation Watcher (MercadoLibre, CompraGamer, VTEX, Tiendanube, Shopify dynamic routes)
    let lastAuditedHref = window.location.href;
    let spaAuditTimer: number | null = null;

    const scheduleSpaReaudit = () => {
      if (ctx.isInvalid) {
        return;
      }
      if (spaAuditTimer !== null) {
        window.clearTimeout(spaAuditTimer);
      }
      spaAuditTimer = window.setTimeout(() => {
        window.requestAnimationFrame(() => {
          if (ctx.isInvalid) {
            return;
          }
          currentReport = auditStoreSecurity(document, window.location.href);
          renderUi();
          void reportToBackground(currentReport);
          scheduleHydrationGraceScans();
        });
      }, 350);
    };

    ctx.addEventListener(window, 'wxt:locationchange', () => {
      if (window.location.href !== lastAuditedHref) {
        lastAuditedHref = window.location.href;
        scheduleSpaReaudit();
      }
    });

    // Listen to validated IPC requests from Popup and Background Service Worker
    const onRuntimeMessage = (
      rawMessage: unknown,
      sender: { id?: string },
      sendResponse: (response: unknown) => void,
    ): true => {
      if (!isTrustedExtensionSender(sender)) {
        sendResponse({
          ok: false,
          error: 'Origen de mensaje no confiable.',
        } satisfies ExtensionMessageResponse);
        return true;
      }

      const validated = validateExtensionMessage(rawMessage);
      if (!validated) {
        sendResponse({
          ok: false,
          error: 'Payload inválido.',
        } satisfies ExtensionMessageResponse);
        return true;
      }

      if (validated.type === 'GET_TAB_AUDIT') {
        currentReport = auditStoreSecurity(document, window.location.href);
        renderUi();
        void reportToBackground(currentReport);
        sendResponse({
          ok: true,
          report: currentReport,
        } satisfies ExtensionMessageResponse);
        return true;
      }

      if (validated.type === 'CONTEXT_MENU_TOAST') {
        void (async () => {
          if (validated.payload.copyText) {
            await copyTextSafely(validated.payload.copyText);
          }
          showToast(validated.payload);
          sendResponse({ ok: true } satisfies ExtensionMessageResponse);
        })();
        return true;
      }

      sendResponse({ ok: true } satisfies ExtensionMessageResponse);
      return true;
    };

    browser.runtime.onMessage.addListener(onRuntimeMessage);

    ctx.onInvalidated(() => {
      antiTamperObserver.disconnect();
      unsubscribeSettings();
      clearHydrationTimers();
      document.removeEventListener('copy', onDocumentCopy);
      browser.runtime.onMessage.removeListener(onRuntimeMessage);
      if (toastTimer !== null) {
        window.clearTimeout(toastTimer);
      }
      if (spaAuditTimer !== null) {
        window.clearTimeout(spaAuditTimer);
      }
    });
  },
});

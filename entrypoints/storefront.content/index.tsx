import './xml-svg-guard';
import { browser } from 'wxt/browser';
import { ContentScriptContext } from 'wxt/client';
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
import type { ShieldController } from './mount-ui';

const SPA_HYDRATION_CHECKPOINTS_MS = [600, 1600, 3200] as const;

export default defineContentScript({
  allFrames: false,
  matches: ['http://*/*', 'https://*/*'],
  excludeMatches: [
    '*://camo.githubusercontent.com/*',
    '*://*/*.svg',
    '*://*/*.xml',
    '*://*/*.pdf',
    '*://*/*.json',
  ],
  runAt: 'document_idle',
  cssInjectionMode: 'manual',

  async main(ctx: ContentScriptContext) {
    if (
      window.self !== window.top ||
      typeof document === 'undefined' ||
      document.contentType !== 'text/html' ||
      !document.body ||
      !document.createElement('div').style
    ) {
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
    let currentToast: ToastNotificationPayload | null = null;
    let toastTimer: number | null = null;
    let hydrationTimers: number[] = [];
    let shieldController: ShieldController | null = null;
    let controllerLoadPromise: Promise<ShieldController> | null = null;

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

    const computeShouldShowUi = (): boolean => {
      const isDismissedOnDomain = currentSettings.dismissedDomains.includes(
        currentReport.hostname.toLowerCase(),
      );
      const shouldShowBadge =
        currentSettings.showFloatingBadge &&
        !isDismissedOnDomain &&
        (currentReport.ecommerce.isEcommerce || currentSettings.alwaysShowBadge);

      return (
        (currentReport.ecommerce.isEcommerce ||
          currentSettings.alwaysShowBadge ||
          currentToast !== null) &&
        (currentSettings.showFloatingBadge || currentToast !== null) &&
        (shouldShowBadge || currentToast !== null)
      );
    };

    const ensureUiMounted = async (): Promise<ShieldController | null> => {
      if (ctx.isInvalid) {
        return null;
      }
      if (shieldController) {
        return shieldController;
      }
      if (!controllerLoadPromise) {
        controllerLoadPromise = import('./mount-ui').then(
          ({ createShieldController }) => {
            const ctrl = createShieldController({
              ctx,
              onDismissToast: () => {
                currentToast = null;
                void syncUi();
              },
              onHideOnSite: (hostname: string) => {
                void (async () => {
                  currentSettings = await dismissDomainForSite(hostname);
                  await syncUi();
                })();
              },
            });
            shieldController = ctrl;
            return ctrl;
          },
        );
      }
      return controllerLoadPromise;
    };

    const syncUi = async (): Promise<void> => {
      if (ctx.isInvalid) {
        return;
      }
      const shouldShowUi = computeShouldShowUi();

      // Lazy on-demand mounting: never create Shadow DOM or boot React on non-ecommerce sites unless needed
      if (!shouldShowUi && !shieldController) {
        return;
      }

      const ctrl = await ensureUiMounted();
      if (!ctrl) {
        return;
      }
      await ctrl.update({
        report: currentReport,
        settings: currentSettings,
        toast: currentToast,
      });
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
              void syncUi();
              void reportToBackground(currentReport);
            }
          });
        }, delayMs);
        hydrationTimers.push(timerId);
      }
    };

    const showToast = (payload: ToastNotificationPayload) => {
      currentToast = payload;
      if (toastTimer !== null) {
        window.clearTimeout(toastTimer);
      }
      void syncUi();
      toastTimer = window.setTimeout(() => {
        currentToast = null;
        void syncUi();
      }, 4500);
    };

    // Initial evaluation: only mounts Shadow DOM if shouldShowUi is true
    await syncUi();
    void reportToBackground(currentReport);
    scheduleHydrationGraceScans();

    // Subscribe to live settings changes from the Popup
    const unsubscribeSettings = subscribeToSettings((updated) => {
      currentSettings = updated;
      void syncUi();
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
          void syncUi();
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
        void syncUi();
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
      shieldController?.destroy();
      shieldController = null;
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

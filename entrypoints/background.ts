import { browser } from 'wxt/browser';
import { defineBackground } from 'wxt/sandbox';
import { sanitizeUrl } from '../src/modules/v01-clean-links/sanitizer';
import {
  extractCUITsFromText,
  validateCUIT,
} from '../src/modules/v01-cuit-arca/validator';
import { ExtensionMessageResponse, RiskLevel, StoreAuditReport } from '../src/types';
import {
  TAB_AUDITS_STORAGE_KEY,
  isTrustedExtensionSender,
  saveTabAuditCache,
  validateExtensionMessage,
} from '../src/utils/storage';

const MENU_CLEAN_LINK_ID = 'escudo-criollo-clean-link';
const MENU_VALIDATE_CUIT_ID = 'escudo-criollo-validate-cuit';

async function applyActionBadgeForReport(
  tabId: number,
  report: StoreAuditReport,
): Promise<void> {
  const badgeMap: Record<
    RiskLevel,
    { text: string; color: string }
  > = {
    SAFE: {
      text: report.ecommerce.isEcommerce ? 'OK' : '',
      color: '#10B981',
    },
    WARNING: {
      text: '!',
      color: '#F59E0B',
    },
    DANGER: {
      text: '🚨',
      color: '#EF4444',
    },
    NEUTRAL: {
      text: '',
      color: '#4F46E5',
    },
  };

  const config = badgeMap[report.riskLevel];
  try {
    await browser.action.setBadgeText({ tabId, text: config.text });
    if (config.text) {
      await browser.action.setBadgeBackgroundColor({
        tabId,
        color: config.color,
      });
    }
  } catch {
    // Tab may have closed before badge update completed
  }
}

async function registerContextMenus(): Promise<void> {
  try {
    await browser.contextMenus.removeAll();
  } catch {
    // Ignore cleanup errors
  }

  browser.contextMenus.create({
    id: MENU_CLEAN_LINK_ID,
    title: '🧹 Copiar enlace limpio (Escudo Criollo)',
    contexts: ['link', 'page'],
  });

  browser.contextMenus.create({
    id: MENU_VALIDATE_CUIT_ID,
    title: '🛡️ Validar CUIT seleccionado con Escudo Criollo',
    contexts: ['selection'],
  });
}

export default defineBackground(() => {
  browser.runtime.onInstalled.addListener(() => {
    void registerContextMenus();
  });

  browser.contextMenus.onClicked.addListener((info, tab) => {
    void (async () => {
      const tabId = tab?.id;

      if (info.menuItemId === MENU_CLEAN_LINK_ID) {
        const rawTargetUrl = info.linkUrl ?? info.pageUrl ?? '';
        const sanitized = sanitizeUrl(rawTargetUrl);

        if (!sanitized.isValidHttpUrl) {
          if (typeof tabId === 'number') {
            try {
              await browser.tabs.sendMessage(tabId, {
                type: 'CONTEXT_MENU_TOAST',
                payload: {
                  variant: 'WARNING',
                  title: 'Enlace bloqueado por seguridad',
                  detail:
                    'Solo se permiten enlaces HTTP o HTTPS válidos. Se bloqueó el esquema inseguro.',
                },
              });
            } catch {
              await browser.action.setBadgeText({ tabId, text: '!' });
              await browser.action.setBadgeBackgroundColor({
                tabId,
                color: '#F59E0B',
              });
            }
          }
          return;
        }

        const title =
          sanitized.removedCount > 0
            ? `Link limpio copiado (${sanitized.removedCount} ${
                sanitized.removedCount === 1
                  ? 'tracker eliminado'
                  : 'trackers eliminados'
              })`
            : 'Link verificado y copiado (sin trackers)';

        if (typeof tabId === 'number') {
          try {
            await browser.tabs.sendMessage(tabId, {
              type: 'CONTEXT_MENU_TOAST',
              payload: {
                variant: 'SAFE',
                title,
                detail: sanitized.cleanUrl,
                copyText: sanitized.cleanUrl,
              },
            });
          } catch {
            await browser.action.setBadgeText({ tabId, text: 'OK' });
            await browser.action.setBadgeBackgroundColor({
              tabId,
              color: '#10B981',
            });
          }
        }
        return;
      }

      if (info.menuItemId === MENU_VALIDATE_CUIT_ID) {
        const selected = info.selectionText ?? '';
        const extracted = extractCUITsFromText(selected);
        const result = extracted[0] ?? validateCUIT(selected);

        if (typeof tabId === 'number') {
          try {
            await browser.tabs.sendMessage(tabId, {
              type: 'CONTEXT_MENU_TOAST',
              payload: {
                variant: result.isValid ? 'SAFE' : 'DANGER',
                title: result.isValid
                  ? `CUIT ${result.formatted} VÁLIDO`
                  : `CUIT INVÁLIDO (${result.formatted || 'Formato erróneo'})`,
                detail: `${result.entityLabel} · ${result.reason}`,
              },
            });
          } catch {
            await browser.action.setBadgeText({
              tabId,
              text: result.isValid ? 'OK' : '🚨',
            });
            await browser.action.setBadgeBackgroundColor({
              tabId,
              color: result.isValid ? '#10B981' : '#EF4444',
            });
          }
        }
      }
    })();
  });

  browser.runtime.onMessage.addListener(
    (rawMessage, sender, sendResponse): true => {
      if (!isTrustedExtensionSender(sender)) {
        sendResponse({
          ok: false,
          error: 'Remitente no autorizado bloqueado por Zero-Trust.',
        } satisfies ExtensionMessageResponse);
        return true;
      }

      const validated = validateExtensionMessage(rawMessage);
      if (!validated) {
        sendResponse({
          ok: false,
          error: 'Mensaje rechazado: estructura inválida.',
        } satisfies ExtensionMessageResponse);
        return true;
      }

      if (validated.type === 'REPORT_STORE_AUDIT') {
        void (async () => {
          const tabId = sender.tab?.id;
          if (typeof tabId === 'number') {
            await saveTabAuditCache(tabId, validated.payload);
            await applyActionBadgeForReport(tabId, validated.payload);
          }
          sendResponse({ ok: true } satisfies ExtensionMessageResponse);
        })();
        return true;
      }

      sendResponse({ ok: true } satisfies ExtensionMessageResponse);
      return true;
    },
  );

  browser.tabs.onRemoved.addListener((closedTabId) => {
    void (async () => {
      try {
        const raw = await browser.storage.local.get(TAB_AUDITS_STORAGE_KEY);
        const map = raw[TAB_AUDITS_STORAGE_KEY];
        if (map && typeof map === 'object' && !Array.isArray(map)) {
          const clone = { ...(map as Record<string, unknown>) };
          if (String(closedTabId) in clone) {
            delete clone[String(closedTabId)];
            await browser.storage.local.set({ [TAB_AUDITS_STORAGE_KEY]: clone });
          }
        }
      } catch {
        // Ignore non-fatal storage error
      }
    })();
  });
});

import inlineCss from './style.css?inline';
import React from 'react';
import ReactDOM from 'react-dom/client';
import { ContentScriptContext, createShadowRootUi } from 'wxt/client';
import {
  ExtensionSettings,
  StoreAuditReport,
  ToastNotificationPayload,
} from '../../src/types';
import { ShieldOverlay } from './ShieldOverlay';

const SHADOW_STYLESHEET = inlineCss.replaceAll(':root', ':host');
const MAX_ANTI_TAMPER_REMOUNTS = 1;

export interface ShieldControllerInit {
  ctx: ContentScriptContext;
  onDismissToast: () => void;
  onHideOnSite: (hostname: string) => void;
}

export interface ShieldControllerState {
  report: StoreAuditReport;
  settings: ExtensionSettings;
  toast: ToastNotificationPayload | null;
}

export interface ShieldController {
  update: (nextState: ShieldControllerState) => Promise<void>;
  destroy: () => void;
}

export function createShieldController(
  init: ShieldControllerInit,
): ShieldController {
  const { ctx, onDismissToast, onHideOnSite } = init;

  let latestState: ShieldControllerState | null = null;
  let reactRoot: ReactDOM.Root | null = null;
  let activeShadowHost: HTMLElement | null = null;
  let mountPromise: Promise<void> | null = null;
  let remountCount = 0;
  let isDestroyed = false;
  let antiTamperObserver: MutationObserver | null = null;

  const renderReactTree = () => {
    if (!reactRoot || !latestState || isDestroyed) {
      return;
    }
    reactRoot.render(
      <React.StrictMode>
        <ShieldOverlay
          report={latestState.report}
          settings={latestState.settings}
          toast={latestState.toast}
          onDismissToast={onDismissToast}
          onHideOnSite={onHideOnSite}
        />
      </React.StrictMode>,
    );
  };

  const mountClosedShadowRoot = async (): Promise<void> => {
    if (isDestroyed || ctx.isInvalid || !document.body) {
      return;
    }

    const ui = await createShadowRootUi(ctx, {
      name: 'escudo-criollo-shield',
      position: 'overlay',
      zIndex: 2147483640,
      mode: 'closed',
      isolateEvents: true,
      css: SHADOW_STYLESHEET,
      onMount: (uiContainer, _shadow, shadowHost) => {
        activeShadowHost = shadowHost;
        const root = ReactDOM.createRoot(uiContainer);
        reactRoot = root;
        renderReactTree();
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

    if (!antiTamperObserver && document.body) {
      antiTamperObserver = new MutationObserver(() => {
        if (isDestroyed || ctx.isInvalid) {
          antiTamperObserver?.disconnect();
          return;
        }
        if (
          activeShadowHost &&
          !document.body.contains(activeShadowHost) &&
          remountCount < MAX_ANTI_TAMPER_REMOUNTS
        ) {
          remountCount += 1;
          activeShadowHost = null;
          mountPromise = null;
          window.requestAnimationFrame(() => {
            if (!isDestroyed && !ctx.isInvalid && document.body) {
              mountPromise = mountClosedShadowRoot();
            }
          });
        }
      });

      antiTamperObserver.observe(document.body, {
        childList: true,
      });
    }
  };

  const ensureMounted = async (): Promise<void> => {
    if (reactRoot) {
      return;
    }
    if (!mountPromise) {
      mountPromise = mountClosedShadowRoot();
    }
    await mountPromise;
  };

  return {
    async update(nextState: ShieldControllerState): Promise<void> {
      if (isDestroyed || ctx.isInvalid) {
        return;
      }
      latestState = nextState;
      await ensureMounted();
      renderReactTree();
    },
    destroy(): void {
      isDestroyed = true;
      antiTamperObserver?.disconnect();
      antiTamperObserver = null;
      if (reactRoot) {
        reactRoot.unmount();
        reactRoot = null;
      }
      activeShadowHost = null;
    },
  };
}

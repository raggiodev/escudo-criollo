import { MAX_SCANNED_TEXT_CHARS, parseSafeHttpUrl, safeTruncate } from '../types';

/**
 * DOM Clobbering-immune runtime element guards.
 * Checks both global DOM constructors and doc.defaultView constructors (for isolated/JSDOM realms).
 */
export function isHtmlElement(node: unknown, doc?: Document): node is HTMLElement {
  if (!node || typeof node !== 'object') {
    return false;
  }
  if (typeof HTMLElement !== 'undefined' && node instanceof HTMLElement) {
    return true;
  }
  const viewCtor = doc?.defaultView?.HTMLElement;
  return Boolean(viewCtor && node instanceof viewCtor);
}

export function isAnchorElement(node: unknown, doc?: Document): node is HTMLAnchorElement {
  if (!node || typeof node !== 'object') {
    return false;
  }
  if (typeof HTMLAnchorElement !== 'undefined' && node instanceof HTMLAnchorElement) {
    return true;
  }
  const viewCtor = doc?.defaultView?.HTMLAnchorElement;
  return Boolean(viewCtor && node instanceof viewCtor);
}

export function isImageElement(node: unknown, doc?: Document): node is HTMLImageElement {
  if (!node || typeof node !== 'object') {
    return false;
  }
  if (typeof HTMLImageElement !== 'undefined' && node instanceof HTMLImageElement) {
    return true;
  }
  const viewCtor = doc?.defaultView?.HTMLImageElement;
  return Boolean(viewCtor && node instanceof viewCtor);
}

/**
 * Safely retrieves the document base HTTP(S) URL without trusting clobbered properties.
 */
export function getSafeDocumentUrl(doc: Document, fallbackUrl?: string): URL | null {
  if (fallbackUrl) {
    const parsedFallback = parseSafeHttpUrl(fallbackUrl);
    if (parsedFallback) {
      return parsedFallback;
    }
  }
  try {
    if (typeof doc.URL === 'string') {
      const parsedDocUrl = parseSafeHttpUrl(doc.URL);
      if (parsedDocUrl) {
        return parsedDocUrl;
      }
    }
  } catch {
    // Ignore hostile getter errors
  }
  return null;
}

/**
 * Extracts bounded plaintext from semantic regions (footer, header, checkout/promo banners, buttons)
 * without ever reading unbounded document.body.innerText on multi-megabyte pages.
 * Strictly capped at MAX_SCANNED_TEXT_CHARS (150,000 chars / 150 KB).
 */
export function extractBoundedSemanticText(
  doc: Document,
  selectors: readonly string[],
  maxChars: number = MAX_SCANNED_TEXT_CHARS,
): string {
  const cap = Math.min(Math.max(1024, maxChars), MAX_SCANNED_TEXT_CHARS);
  const visited = new Set<HTMLElement>();
  const chunks: string[] = [];
  let currentLength = 0;

  for (const selector of selectors) {
    if (currentLength >= cap) {
      break;
    }
    let elements: NodeListOf<Element>;
    try {
      elements = doc.querySelectorAll(selector);
    } catch {
      continue;
    }

    const maxNodesPerSelector = 80;
    const count = Math.min(elements.length, maxNodesPerSelector);
    for (let i = 0; i < count; i++) {
      if (currentLength >= cap) {
        break;
      }
      const el = elements[i];
      if (!isHtmlElement(el, doc) || visited.has(el)) {
        continue;
      }

      // Skip if an already-collected ancestor contains this element to avoid duplicate text bloat
      let hasVisitedAncestor = false;
      let parent = el.parentElement;
      while (parent) {
        if (visited.has(parent)) {
          hasVisitedAncestor = true;
          break;
        }
        parent = parent.parentElement;
      }
      if (hasVisitedAncestor) {
        continue;
      }

      visited.add(el);
      const rawText = typeof el.textContent === 'string' ? el.textContent : '';
      if (!rawText) {
        continue;
      }
      const remaining = cap - currentLength;
      const slice = rawText.slice(0, remaining);
      chunks.push(slice);
      currentLength += slice.length;
    }
  }

  return chunks.join('\n').slice(0, cap);
}

/**
 * Safely extracts a truncated attribute from an HTMLElement.
 */
export function getSafeAttr(el: HTMLElement, attrName: string, maxLen?: number): string {
  const val = el.getAttribute(attrName);
  return val ? safeTruncate(val, maxLen) : '';
}


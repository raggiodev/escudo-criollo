/**
 * Copies plain text to the user's clipboard using the modern Async Clipboard API,
 * with a DOM-safe fallback in case a host page's Permissions-Policy header blocks clipboard-write.
 */
export async function copyTextSafely(text: string): Promise<boolean> {
  if (typeof text !== 'string' || text.length === 0) {
    return false;
  }

  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below if Permissions-Policy blocks navigator.clipboard in content script
  }

  try {
    if (typeof document === 'undefined' || !document.body) {
      return false;
    }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'true');
    textarea.style.position = 'fixed';
    textarea.style.top = '-9999px';
    textarea.style.left = '-9999px';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

